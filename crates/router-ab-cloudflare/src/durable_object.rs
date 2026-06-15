use std::collections::BTreeMap;

use ed25519_hss::role_signing::{
    RoleSeparatedEd25519CommitmentsV1, RoleSeparatedEd25519Round1StateV1,
};
use router_ab_core::{
    ActiveSigningWorkerStateV1, ExpensiveWorkKindV1, LifecycleScopeV1, NormalSigningScopeV1,
    PublicDigest32, PublicRouterRequestV1, Role, RootShareEpoch,
};
use router_ab_core::{
    RouterAbLifecycleStateV1, RouterAbProtocolError, RouterAbProtocolErrorCode,
    RouterAbProtocolResult,
};
#[cfg(feature = "workers-rs")]
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
#[cfg(feature = "workers-rs")]
use wasm_bindgen as _;

use crate::{
    cloudflare_active_signing_worker_state_from_activation_request_v1,
    cloudflare_signing_worker_recipient_proof_bundle_activation_digest_v1,
    CloudflareDurableObjectBindingV1, CloudflareDurableObjectScopeV1, CloudflareRouterAbuseCheckV1,
    CloudflareRouterNormalSigningTrustedMetadataV1, CloudflareRouterProjectPolicyV1,
    CloudflareRouterQuotaCheckV1, CloudflareRouterTrustedRequestMetadataV1,
    CloudflareServerOutputMaterialRecordV1,
    CloudflareSigningWorkerRecipientProofBundleActivationRequestV1, CloudflareWorkerRoleV1,
};
#[cfg(feature = "workers-rs")]
use crate::{
    ROUTER_ABUSE_DO_BINDING_ENV, ROUTER_ABUSE_DO_KEY_PREFIX_ENV, ROUTER_ABUSE_DO_OBJECT_ENV,
    ROUTER_LIFECYCLE_DO_BINDING_ENV, ROUTER_LIFECYCLE_DO_KEY_PREFIX_ENV,
    ROUTER_LIFECYCLE_DO_OBJECT_ENV, ROUTER_PROJECT_POLICY_DO_BINDING_ENV,
    ROUTER_PROJECT_POLICY_DO_KEY_PREFIX_ENV, ROUTER_PROJECT_POLICY_DO_OBJECT_ENV,
    ROUTER_QUOTA_DO_BINDING_ENV, ROUTER_QUOTA_DO_KEY_PREFIX_ENV, ROUTER_QUOTA_DO_OBJECT_ENV,
    ROUTER_REPLAY_DO_BINDING_ENV, ROUTER_REPLAY_DO_KEY_PREFIX_ENV, ROUTER_REPLAY_DO_OBJECT_ENV,
    SIGNER_A_ROOT_SHARE_DO_BINDING_ENV, SIGNER_A_ROOT_SHARE_DO_KEY_PREFIX_ENV,
    SIGNER_A_ROOT_SHARE_DO_OBJECT_ENV, SIGNER_B_ROOT_SHARE_DO_BINDING_ENV,
    SIGNER_B_ROOT_SHARE_DO_KEY_PREFIX_ENV, SIGNER_B_ROOT_SHARE_DO_OBJECT_ENV,
    SIGNING_WORKER_SERVER_OUTPUT_DO_BINDING_ENV, SIGNING_WORKER_SERVER_OUTPUT_DO_KEY_PREFIX_ENV,
    SIGNING_WORKER_SERVER_OUTPUT_DO_OBJECT_ENV,
};

/// Version label for the Router/A/B Cloudflare Durable Object API.
pub const CLOUDFLARE_DURABLE_OBJECT_API_VERSION_V1: &str = "router-ab-cloudflare-do/v1";

/// Router replay/idempotency Durable Object class.
#[cfg(feature = "workers-rs")]
#[worker::durable_object(fetch)]
pub struct RouterAbRouterReplayDurableObject {
    state: worker::State,
    env: worker::Env,
}

#[cfg(feature = "workers-rs")]
impl worker::DurableObject for RouterAbRouterReplayDurableObject {
    fn new(state: worker::State, env: worker::Env) -> Self {
        Self { state, env }
    }

    async fn fetch(&self, request: worker::Request) -> worker::Result<worker::Response> {
        handle_cloudflare_durable_object_class_fetch_v1(
            CloudflareDurableObjectScopeV1::RouterReplay,
            ROUTER_REPLAY_DO_BINDING_ENV,
            ROUTER_REPLAY_DO_OBJECT_ENV,
            ROUTER_REPLAY_DO_KEY_PREFIX_ENV,
            &self.env,
            &self.state,
            request,
        )
        .await
    }
}

/// Router public lifecycle Durable Object class.
#[cfg(feature = "workers-rs")]
#[worker::durable_object(fetch)]
pub struct RouterAbRouterLifecycleDurableObject {
    state: worker::State,
    env: worker::Env,
}

#[cfg(feature = "workers-rs")]
impl worker::DurableObject for RouterAbRouterLifecycleDurableObject {
    fn new(state: worker::State, env: worker::Env) -> Self {
        Self { state, env }
    }

    async fn fetch(&self, request: worker::Request) -> worker::Result<worker::Response> {
        handle_cloudflare_durable_object_class_fetch_v1(
            CloudflareDurableObjectScopeV1::RouterLifecycle,
            ROUTER_LIFECYCLE_DO_BINDING_ENV,
            ROUTER_LIFECYCLE_DO_OBJECT_ENV,
            ROUTER_LIFECYCLE_DO_KEY_PREFIX_ENV,
            &self.env,
            &self.state,
            request,
        )
        .await
    }
}

/// Router project-policy Durable Object class.
#[cfg(feature = "workers-rs")]
#[worker::durable_object(fetch)]
pub struct RouterAbRouterProjectPolicyDurableObject {
    state: worker::State,
    env: worker::Env,
}

#[cfg(feature = "workers-rs")]
impl worker::DurableObject for RouterAbRouterProjectPolicyDurableObject {
    fn new(state: worker::State, env: worker::Env) -> Self {
        Self { state, env }
    }

    async fn fetch(&self, request: worker::Request) -> worker::Result<worker::Response> {
        handle_cloudflare_durable_object_class_fetch_v1(
            CloudflareDurableObjectScopeV1::RouterProjectPolicy,
            ROUTER_PROJECT_POLICY_DO_BINDING_ENV,
            ROUTER_PROJECT_POLICY_DO_OBJECT_ENV,
            ROUTER_PROJECT_POLICY_DO_KEY_PREFIX_ENV,
            &self.env,
            &self.state,
            request,
        )
        .await
    }
}

/// Router quota Durable Object class.
#[cfg(feature = "workers-rs")]
#[worker::durable_object(fetch)]
pub struct RouterAbRouterQuotaDurableObject {
    state: worker::State,
    env: worker::Env,
}

#[cfg(feature = "workers-rs")]
impl worker::DurableObject for RouterAbRouterQuotaDurableObject {
    fn new(state: worker::State, env: worker::Env) -> Self {
        Self { state, env }
    }

    async fn fetch(&self, request: worker::Request) -> worker::Result<worker::Response> {
        handle_cloudflare_durable_object_class_fetch_v1(
            CloudflareDurableObjectScopeV1::RouterQuota,
            ROUTER_QUOTA_DO_BINDING_ENV,
            ROUTER_QUOTA_DO_OBJECT_ENV,
            ROUTER_QUOTA_DO_KEY_PREFIX_ENV,
            &self.env,
            &self.state,
            request,
        )
        .await
    }
}

/// Router abuse-control Durable Object class.
#[cfg(feature = "workers-rs")]
#[worker::durable_object(fetch)]
pub struct RouterAbRouterAbuseDurableObject {
    state: worker::State,
    env: worker::Env,
}

#[cfg(feature = "workers-rs")]
impl worker::DurableObject for RouterAbRouterAbuseDurableObject {
    fn new(state: worker::State, env: worker::Env) -> Self {
        Self { state, env }
    }

    async fn fetch(&self, request: worker::Request) -> worker::Result<worker::Response> {
        handle_cloudflare_durable_object_class_fetch_v1(
            CloudflareDurableObjectScopeV1::RouterAbuse,
            ROUTER_ABUSE_DO_BINDING_ENV,
            ROUTER_ABUSE_DO_OBJECT_ENV,
            ROUTER_ABUSE_DO_KEY_PREFIX_ENV,
            &self.env,
            &self.state,
            request,
        )
        .await
    }
}

/// Signer A root-share Durable Object class.
#[cfg(feature = "workers-rs")]
#[worker::durable_object(fetch)]
pub struct RouterAbSignerARootShareDurableObject {
    state: worker::State,
    env: worker::Env,
}

#[cfg(feature = "workers-rs")]
impl worker::DurableObject for RouterAbSignerARootShareDurableObject {
    fn new(state: worker::State, env: worker::Env) -> Self {
        Self { state, env }
    }

    async fn fetch(&self, request: worker::Request) -> worker::Result<worker::Response> {
        handle_cloudflare_durable_object_class_fetch_v1(
            CloudflareDurableObjectScopeV1::SignerRootShare {
                role: Role::SignerA,
            },
            SIGNER_A_ROOT_SHARE_DO_BINDING_ENV,
            SIGNER_A_ROOT_SHARE_DO_OBJECT_ENV,
            SIGNER_A_ROOT_SHARE_DO_KEY_PREFIX_ENV,
            &self.env,
            &self.state,
            request,
        )
        .await
    }
}

/// SigningWorker server-output Durable Object class.
#[cfg(feature = "workers-rs")]
#[worker::durable_object(fetch)]
pub struct RouterAbSigningWorkerServerOutputDurableObject {
    state: worker::State,
    env: worker::Env,
}

#[cfg(feature = "workers-rs")]
impl worker::DurableObject for RouterAbSigningWorkerServerOutputDurableObject {
    fn new(state: worker::State, env: worker::Env) -> Self {
        Self { state, env }
    }

    async fn fetch(&self, request: worker::Request) -> worker::Result<worker::Response> {
        handle_cloudflare_durable_object_class_fetch_v1(
            CloudflareDurableObjectScopeV1::signing_worker_server_output(),
            SIGNING_WORKER_SERVER_OUTPUT_DO_BINDING_ENV,
            SIGNING_WORKER_SERVER_OUTPUT_DO_OBJECT_ENV,
            SIGNING_WORKER_SERVER_OUTPUT_DO_KEY_PREFIX_ENV,
            &self.env,
            &self.state,
            request,
        )
        .await
    }
}

/// Signer B root-share Durable Object class.
#[cfg(feature = "workers-rs")]
#[worker::durable_object(fetch)]
pub struct RouterAbSignerBRootShareDurableObject {
    state: worker::State,
    env: worker::Env,
}

#[cfg(feature = "workers-rs")]
impl worker::DurableObject for RouterAbSignerBRootShareDurableObject {
    fn new(state: worker::State, env: worker::Env) -> Self {
        Self { state, env }
    }

    async fn fetch(&self, request: worker::Request) -> worker::Result<worker::Response> {
        handle_cloudflare_durable_object_class_fetch_v1(
            CloudflareDurableObjectScopeV1::SignerRootShare {
                role: Role::SignerB,
            },
            SIGNER_B_ROOT_SHARE_DO_BINDING_ENV,
            SIGNER_B_ROOT_SHARE_DO_OBJECT_ENV,
            SIGNER_B_ROOT_SHARE_DO_KEY_PREFIX_ENV,
            &self.env,
            &self.state,
            request,
        )
        .await
    }
}

/// Explicit Durable Object operation names used by Router/A/B adapters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CloudflareDurableObjectOperationKindV1 {
    /// Check role-local root-share presence.
    RootShareHas,
    /// Read role-local root-share startup metadata.
    RootShareStartupMetadata,
    /// Reserve a Router replay nonce or request id.
    RouterReplayReserve,
    /// Remove expired Router replay reservations.
    RouterReplayCleanupExpired,
    /// Persist public Router lifecycle state.
    RouterLifecyclePutPublicState,
    /// Persist Cloudflare derivation ceremony state.
    DerivationCeremonyPutState,
    /// Evaluate Router project policy.
    RouterProjectPolicyEvaluate,
    /// Evaluate Router quota and active lifecycle state.
    RouterQuotaEvaluate,
    /// Remove expired Router quota reservations.
    RouterQuotaCleanupExpired,
    /// Evaluate Router abuse-control state.
    RouterAbuseEvaluate,
    /// Evaluate Router project policy for normal signing.
    RouterNormalSigningProjectPolicyEvaluate,
    /// Evaluate Router quota for normal signing.
    RouterNormalSigningQuotaEvaluate,
    /// Evaluate Router abuse-control state for normal signing.
    RouterNormalSigningAbuseEvaluate,
    /// Activate server-output material for the designated server.
    SigningWorkerOutputActivate,
    /// Read active SigningWorker state for normal signing.
    SigningWorkerOutputActiveStateGet,
    /// Read active SigningWorker material for normal signing.
    SigningWorkerOutputMaterialGet,
    /// Store one SigningWorker round-1 nonce record for normal signing.
    SigningWorkerRound1Put,
    /// Take one SigningWorker round-1 nonce record for normal signing.
    SigningWorkerRound1Take,
    /// Remove expired SigningWorker round-1 nonce records.
    SigningWorkerRound1CleanupExpired,
}

impl CloudflareDurableObjectOperationKindV1 {
    /// Returns the stable operation label.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RootShareHas => "root_share.has",
            Self::RootShareStartupMetadata => "root_share.startup_metadata",
            Self::RouterReplayReserve => "router_replay.reserve",
            Self::RouterReplayCleanupExpired => "router_replay.cleanup_expired",
            Self::RouterLifecyclePutPublicState => "router_lifecycle.put_public_state",
            Self::DerivationCeremonyPutState => "cloudflare_derivation_ceremony.put_state",
            Self::RouterProjectPolicyEvaluate => "router_project_policy.evaluate",
            Self::RouterQuotaEvaluate => "router_quota.evaluate",
            Self::RouterQuotaCleanupExpired => "router_quota.cleanup_expired",
            Self::RouterAbuseEvaluate => "router_abuse.evaluate",
            Self::RouterNormalSigningProjectPolicyEvaluate => {
                "router_normal_signing_project_policy.evaluate"
            }
            Self::RouterNormalSigningQuotaEvaluate => "router_normal_signing_quota.evaluate",
            Self::RouterNormalSigningAbuseEvaluate => "router_normal_signing_abuse.evaluate",
            Self::SigningWorkerOutputActivate => "signing_worker_output.activate",
            Self::SigningWorkerOutputActiveStateGet => "signing_worker_output.active_state_get",
            Self::SigningWorkerOutputMaterialGet => "signing_worker_output.material_get",
            Self::SigningWorkerRound1Put => "signing_worker_round1.put",
            Self::SigningWorkerRound1Take => "signing_worker_round1.take",
            Self::SigningWorkerRound1CleanupExpired => "signing_worker_round1.cleanup_expired",
        }
    }

    /// Returns the internal HTTP path used by the Worker-to-Durable-Object call.
    pub fn path(self) -> &'static str {
        match self {
            Self::RootShareHas => "/router-ab/do/v1/root-share/has",
            Self::RootShareStartupMetadata => "/router-ab/do/v1/root-share/startup-metadata",
            Self::RouterReplayReserve => "/router-ab/do/v1/router-replay/reserve",
            Self::RouterReplayCleanupExpired => "/router-ab/do/v1/router-replay/cleanup-expired",
            Self::RouterLifecyclePutPublicState => "/router-ab/do/v1/router-lifecycle/put",
            Self::DerivationCeremonyPutState => "/router-ab/do/v1/derivation-ceremony/put",
            Self::RouterProjectPolicyEvaluate => "/router-ab/do/v1/router-project-policy/evaluate",
            Self::RouterQuotaEvaluate => "/router-ab/do/v1/router-quota/evaluate",
            Self::RouterQuotaCleanupExpired => "/router-ab/do/v1/router-quota/cleanup-expired",
            Self::RouterAbuseEvaluate => "/router-ab/do/v1/router-abuse/evaluate",
            Self::RouterNormalSigningProjectPolicyEvaluate => {
                "/router-ab/do/v1/router-project-policy/normal-signing/evaluate"
            }
            Self::RouterNormalSigningQuotaEvaluate => {
                "/router-ab/do/v1/router-quota/normal-signing/evaluate"
            }
            Self::RouterNormalSigningAbuseEvaluate => {
                "/router-ab/do/v1/router-abuse/normal-signing/evaluate"
            }
            Self::SigningWorkerOutputActivate => "/router-ab/do/v1/signing-worker-output/activate",
            Self::SigningWorkerOutputActiveStateGet => {
                "/router-ab/do/v1/signing-worker-output/active-state/get"
            }
            Self::SigningWorkerOutputMaterialGet => {
                "/router-ab/do/v1/signing-worker-output/material/get"
            }
            Self::SigningWorkerRound1Put => "/router-ab/do/v1/signing-worker-round1/put",
            Self::SigningWorkerRound1Take => "/router-ab/do/v1/signing-worker-round1/take",
            Self::SigningWorkerRound1CleanupExpired => {
                "/router-ab/do/v1/signing-worker-round1/cleanup-expired"
            }
        }
    }
}

/// Root-share lookup request shared by `root_share.has` and startup metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareRootShareLookupRequestV1 {
    /// Signer set id.
    pub signer_set_id: String,
    /// Signer role expected in the Durable Object.
    pub signer_role: Role,
    /// Root-share epoch.
    pub root_share_epoch: RootShareEpoch,
}

impl CloudflareRootShareLookupRequestV1 {
    /// Creates a validated root-share lookup request.
    pub fn new(
        signer_set_id: impl Into<String>,
        signer_role: Role,
        root_share_epoch: RootShareEpoch,
    ) -> RouterAbProtocolResult<Self> {
        let request = Self {
            signer_set_id: signer_set_id.into(),
            signer_role,
            root_share_epoch,
        };
        request.validate()?;
        Ok(request)
    }

    /// Validates root-share lookup identity.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("signer_set_id", &self.signer_set_id)?;
        require_signer_role(self.signer_role)?;
        require_non_empty("root_share_epoch", self.root_share_epoch.as_str())
    }

    fn expected_scope(&self) -> CloudflareDurableObjectScopeV1 {
        CloudflareDurableObjectScopeV1::SignerRootShare {
            role: self.signer_role,
        }
    }
}

/// Router replay reservation request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareReplayReserveRequestV1 {
    /// Router request id or nonce.
    pub request_id: String,
    /// Digest of replay-bound public request material.
    pub replay_material_digest: PublicDigest32,
    /// Reservation expiry timestamp in Unix milliseconds.
    pub expires_at_ms: u64,
}

impl CloudflareReplayReserveRequestV1 {
    /// Creates a validated replay reservation request.
    pub fn new(
        request_id: impl Into<String>,
        replay_material_digest: PublicDigest32,
        expires_at_ms: u64,
    ) -> RouterAbProtocolResult<Self> {
        let request = Self {
            request_id: request_id.into(),
            replay_material_digest,
            expires_at_ms,
        };
        request.validate()?;
        Ok(request)
    }

    /// Validates replay reservation fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("request_id", &self.request_id)?;
        if self.expires_at_ms == 0 {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidTimeRange,
                "replay reservation expires_at_ms must be greater than zero",
            ));
        }
        Ok(())
    }
}

/// Router admission-store request shared by policy, abuse, and quota Durable Objects.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareRouterAdmissionStoreRequestV1 {
    /// Trusted Router metadata derived before storage checks.
    pub metadata: CloudflareRouterTrustedRequestMetadataV1,
    /// Client request nonce used for request-id derivation.
    pub request_nonce: String,
    /// Lifecycle id from the normalized public request.
    pub lifecycle_id: String,
    /// Request expiry in Unix milliseconds.
    pub expires_at_ms: u64,
    /// Current Worker time in Unix milliseconds.
    pub now_unix_ms: u64,
    /// Public transcript digest for the ceremony.
    pub transcript_digest: PublicDigest32,
}

impl CloudflareRouterAdmissionStoreRequestV1 {
    /// Creates an admission-store request from normalized Router inputs.
    pub fn new(
        metadata: CloudflareRouterTrustedRequestMetadataV1,
        request: &PublicRouterRequestV1,
        now_unix_ms: u64,
    ) -> RouterAbProtocolResult<Self> {
        metadata.validate_for_request(request)?;
        let request = Self {
            metadata,
            request_nonce: request.request_nonce.clone(),
            lifecycle_id: request.lifecycle.lifecycle_id.clone(),
            expires_at_ms: request.expires_at_ms,
            now_unix_ms,
            transcript_digest: request.transcript_digest,
        };
        request.validate()?;
        Ok(request)
    }

    /// Validates admission-store identity and timing fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.metadata.validate()?;
        require_non_empty("request_nonce", &self.request_nonce)?;
        require_non_empty("lifecycle_id", &self.lifecycle_id)?;
        require_positive_ms("expires_at_ms", self.expires_at_ms)?;
        if self.now_unix_ms > self.expires_at_ms {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidTimeRange,
                "admission-store request is already expired",
            ));
        }
        Ok(())
    }
}

/// Router admission-store request for normal-signing policy, abuse, and quota.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareRouterNormalSigningAdmissionStoreRequestV1 {
    /// Trusted Router metadata derived before storage checks.
    pub metadata: CloudflareRouterNormalSigningTrustedMetadataV1,
    /// Router normal-signing request id.
    pub request_id: String,
    /// Request expiry in Unix milliseconds.
    pub expires_at_ms: u64,
    /// Current Worker time in Unix milliseconds.
    pub now_unix_ms: u64,
    /// Digest of the canonical user intent authorized by policy.
    pub intent_digest: PublicDigest32,
    /// Digest of canonical normal-signing request bytes.
    pub request_digest: PublicDigest32,
}

impl CloudflareRouterNormalSigningAdmissionStoreRequestV1 {
    /// Validates normal-signing admission-store identity and timing fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.metadata.validate()?;
        require_non_empty("normal signing request_id", &self.request_id)?;
        require_positive_ms("normal signing expires_at_ms", self.expires_at_ms)?;
        require_positive_ms("normal signing now_unix_ms", self.now_unix_ms)?;
        if self.now_unix_ms >= self.expires_at_ms {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ExpiredLocalRequest,
                "normal-signing admission-store request is already expired",
            ));
        }
        Ok(())
    }
}

/// Stored Router project policy for one org/project/environment scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareRouterProjectPolicyRecordV1 {
    /// Organization id.
    pub org_id: String,
    /// Project id.
    pub project_id: String,
    /// Deployment environment label.
    pub environment: String,
    /// Work kinds allowed by this project policy.
    pub allowed_work_kinds: Vec<ExpensiveWorkKindV1>,
    /// Whether normal signing is allowed by this project policy.
    pub allow_normal_signing: bool,
    /// Retry-after returned when the work kind is rejected.
    pub rejected_retry_after_ms: u64,
}

impl CloudflareRouterProjectPolicyRecordV1 {
    /// Creates a validated project-policy record.
    pub fn new(
        org_id: impl Into<String>,
        project_id: impl Into<String>,
        environment: impl Into<String>,
        allowed_work_kinds: Vec<ExpensiveWorkKindV1>,
        allow_normal_signing: bool,
        rejected_retry_after_ms: u64,
    ) -> RouterAbProtocolResult<Self> {
        let record = Self {
            org_id: org_id.into(),
            project_id: project_id.into(),
            environment: environment.into(),
            allowed_work_kinds,
            allow_normal_signing,
            rejected_retry_after_ms,
        };
        record.validate()?;
        Ok(record)
    }

    /// Validates project-policy fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("org_id", &self.org_id)?;
        require_non_empty("project_id", &self.project_id)?;
        require_non_empty("environment", &self.environment)?;
        require_work_kind_set("allowed_work_kinds", &self.allowed_work_kinds)?;
        require_positive_ms(
            "project policy rejected_retry_after_ms",
            self.rejected_retry_after_ms,
        )
    }

    fn evaluate(
        &self,
        request: &CloudflareRouterAdmissionStoreRequestV1,
    ) -> RouterAbProtocolResult<CloudflareRouterProjectPolicyV1> {
        self.validate()?;
        request.validate()?;
        if self.org_id != request.metadata.org_id
            || self.project_id != request.metadata.project_id
            || self.environment != request.metadata.environment
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "project-policy record scope does not match admission metadata",
            ));
        }
        if self
            .allowed_work_kinds
            .iter()
            .any(|work_kind| *work_kind == request.metadata.work_kind)
        {
            Ok(CloudflareRouterProjectPolicyV1::Allowed)
        } else {
            Ok(CloudflareRouterProjectPolicyV1::Rejected {
                retry_after_ms: self.rejected_retry_after_ms,
            })
        }
    }

    fn evaluate_normal_signing(
        &self,
        request: &CloudflareRouterNormalSigningAdmissionStoreRequestV1,
    ) -> RouterAbProtocolResult<CloudflareRouterProjectPolicyV1> {
        self.validate()?;
        request.validate()?;
        if self.org_id != request.metadata.org_id
            || self.project_id != request.metadata.project_id
            || self.environment != request.metadata.environment
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "project-policy record scope does not match normal-signing metadata",
            ));
        }
        if self.allow_normal_signing {
            Ok(CloudflareRouterProjectPolicyV1::Allowed)
        } else {
            Ok(CloudflareRouterProjectPolicyV1::Rejected {
                retry_after_ms: self.rejected_retry_after_ms,
            })
        }
    }
}

/// Stored Router abuse-control decision for a trusted source/principal scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareRouterAbuseRecordV1 {
    /// Abuse-control outcome.
    pub outcome: CloudflareRouterAbuseCheckV1,
}

impl CloudflareRouterAbuseRecordV1 {
    /// Creates a validated abuse-control record.
    pub fn new(outcome: CloudflareRouterAbuseCheckV1) -> RouterAbProtocolResult<Self> {
        outcome.validate()?;
        Ok(Self { outcome })
    }

    /// Validates the stored abuse-control outcome.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.outcome.validate()
    }
}

/// Stored active quota reservation for one account/work-kind scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareRouterQuotaReservationV1 {
    /// Router request id.
    pub request_id: String,
    /// Active lifecycle id.
    pub lifecycle_id: String,
    /// Reservation expiry in Unix milliseconds.
    pub expires_at_ms: u64,
}

impl CloudflareRouterQuotaReservationV1 {
    /// Creates a validated quota reservation.
    pub fn new(
        request_id: impl Into<String>,
        lifecycle_id: impl Into<String>,
        expires_at_ms: u64,
    ) -> RouterAbProtocolResult<Self> {
        let reservation = Self {
            request_id: request_id.into(),
            lifecycle_id: lifecycle_id.into(),
            expires_at_ms,
        };
        reservation.validate()?;
        Ok(reservation)
    }

    /// Validates quota reservation identity and expiry.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("request_id", &self.request_id)?;
        require_non_empty("lifecycle_id", &self.lifecycle_id)?;
        require_positive_ms("quota reservation expires_at_ms", self.expires_at_ms)
    }

    fn is_active_at(&self, now_unix_ms: u64) -> bool {
        self.expires_at_ms > now_unix_ms
    }
}

/// Request body for an explicit expired-state cleanup pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareExpiredStateCleanupRequestV1 {
    /// Current Worker time in Unix milliseconds.
    pub now_unix_ms: u64,
}

impl CloudflareExpiredStateCleanupRequestV1 {
    /// Creates a validated expired-state cleanup request.
    pub fn new(now_unix_ms: u64) -> RouterAbProtocolResult<Self> {
        let request = Self { now_unix_ms };
        request.validate()?;
        Ok(request)
    }

    /// Validates cleanup time.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_positive_ms("cleanup now_unix_ms", self.now_unix_ms)
    }
}

/// Summary returned after one expired-state cleanup pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareExpiredStateCleanupReportV1 {
    /// Current Worker time used for expiry comparisons.
    pub now_unix_ms: u64,
    /// Primary storage records removed.
    pub records_removed: u64,
    /// Secondary index records removed.
    pub index_records_removed: u64,
}

impl CloudflareExpiredStateCleanupReportV1 {
    /// Creates a validated cleanup report.
    pub fn new(
        now_unix_ms: u64,
        records_removed: u64,
        index_records_removed: u64,
    ) -> RouterAbProtocolResult<Self> {
        let report = Self {
            now_unix_ms,
            records_removed,
            index_records_removed,
        };
        report.validate()?;
        Ok(report)
    }

    /// Validates cleanup report fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_positive_ms("cleanup report now_unix_ms", self.now_unix_ms)
    }
}

/// Metadata returned by `root_share.startup_metadata`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareRootShareStartupMetadataV1 {
    /// Signer set id.
    pub signer_set_id: String,
    /// Signer role stored with the root share.
    pub signer_role: Role,
    /// Signer id stored with the root share.
    pub signer_id: String,
    /// Signer key epoch stored with the root share.
    pub signer_key_epoch: String,
    /// Root-share epoch.
    pub root_share_epoch: RootShareEpoch,
    /// Storage key for the sealed root-share blob.
    pub sealed_share_storage_key: String,
}

impl CloudflareRootShareStartupMetadataV1 {
    /// Creates validated root-share startup metadata.
    pub fn new(
        signer_set_id: impl Into<String>,
        signer_role: Role,
        signer_id: impl Into<String>,
        signer_key_epoch: impl Into<String>,
        root_share_epoch: RootShareEpoch,
        sealed_share_storage_key: impl Into<String>,
    ) -> RouterAbProtocolResult<Self> {
        let metadata = Self {
            signer_set_id: signer_set_id.into(),
            signer_role,
            signer_id: signer_id.into(),
            signer_key_epoch: signer_key_epoch.into(),
            root_share_epoch,
            sealed_share_storage_key: sealed_share_storage_key.into(),
        };
        metadata.validate()?;
        Ok(metadata)
    }

    /// Validates startup metadata identity and storage key.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("signer_set_id", &self.signer_set_id)?;
        require_signer_role(self.signer_role)?;
        require_non_empty("signer_id", &self.signer_id)?;
        require_non_empty("signer_key_epoch", &self.signer_key_epoch)?;
        require_non_empty("root_share_epoch", self.root_share_epoch.as_str())?;
        require_non_empty("sealed_share_storage_key", &self.sealed_share_storage_key)
    }

    fn validate_matches_lookup(
        &self,
        lookup: &CloudflareRootShareLookupRequestV1,
    ) -> RouterAbProtocolResult<()> {
        self.validate()?;
        if self.signer_set_id != lookup.signer_set_id
            || self.signer_role != lookup.signer_role
            || self.root_share_epoch != lookup.root_share_epoch
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "root-share startup metadata does not match lookup request",
            ));
        }
        Ok(())
    }
}

/// Replay reservation response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareReplayReserveResponseV1 {
    /// Router request id or nonce.
    pub request_id: String,
    /// Whether this request won the reservation.
    pub reserved: bool,
}

impl CloudflareReplayReserveResponseV1 {
    /// Creates a validated replay reservation response.
    pub fn new(request_id: impl Into<String>, reserved: bool) -> RouterAbProtocolResult<Self> {
        let response = Self {
            request_id: request_id.into(),
            reserved,
        };
        response.validate()?;
        Ok(response)
    }

    /// Validates replay reservation response fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("request_id", &self.request_id)
    }
}

/// Router lifecycle persistence receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareLifecyclePutReceiptV1 {
    /// Lifecycle id stored in the Router lifecycle Durable Object.
    pub lifecycle_id: String,
    /// Whether public state was stored.
    pub stored: bool,
}

impl CloudflareLifecyclePutReceiptV1 {
    /// Creates a validated lifecycle receipt.
    pub fn new(lifecycle_id: impl Into<String>, stored: bool) -> RouterAbProtocolResult<Self> {
        let receipt = Self {
            lifecycle_id: lifecycle_id.into(),
            stored,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    /// Validates lifecycle receipt fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("lifecycle_id", &self.lifecycle_id)
    }
}

/// Public Cloudflare derivation ceremony state label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CloudflareDerivationCeremonyStateLabelV1 {
    /// Ceremony was created from a normalized lifecycle scope.
    Created,
    /// Router admission accepted work and assigned a request id.
    Admitted,
    /// Router forwarded the A envelope.
    AEnvelopeForwarded,
    /// Router forwarded the B envelope.
    BEnvelopeForwarded,
    /// A/B peer coordination started.
    AbRunning,
    /// Encrypted client output packages are ready.
    ClientOutputReady,
    /// Encrypted SigningWorker output packages are ready.
    SigningWorkerOutputReady,
    /// SigningWorker activation completed and normal signing can use the active state.
    Activated,
    /// Ceremony failed with a redacted reason.
    Failed,
    /// Ceremony expired before activation.
    Expired,
    /// Caller or authority abandoned the ceremony.
    Abandoned,
}

impl CloudflareDerivationCeremonyStateLabelV1 {
    /// Returns whether this label is terminal.
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Activated | Self::Failed | Self::Expired | Self::Abandoned
        )
    }
}

/// Dedicated Cloudflare record for derivation ceremony lifecycle persistence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum CloudflareDerivationCeremonyV1 {
    /// Ceremony was created and no Router admission outcome has been stored.
    Created {
        /// Public lifecycle scope.
        scope: LifecycleScopeV1,
        /// Creation timestamp in Unix milliseconds.
        created_at_ms: u64,
    },
    /// Router admitted the ceremony for private signer work.
    Admitted {
        /// Public lifecycle scope.
        scope: LifecycleScopeV1,
        /// Router-assigned request id.
        request_id: String,
        /// Admission timestamp in Unix milliseconds.
        admitted_at_ms: u64,
    },
    /// Router forwarded the A envelope.
    AEnvelopeForwarded {
        /// Public lifecycle scope.
        scope: LifecycleScopeV1,
        /// Router-assigned request id.
        request_id: String,
        /// Deriver A identity that received the envelope.
        deriver_a_id: String,
        /// Public A envelope digest.
        a_envelope_digest: PublicDigest32,
        /// Forward timestamp in Unix milliseconds.
        forwarded_at_ms: u64,
    },
    /// Router forwarded the B envelope.
    BEnvelopeForwarded {
        /// Public lifecycle scope.
        scope: LifecycleScopeV1,
        /// Router-assigned request id.
        request_id: String,
        /// Deriver A identity that received the first envelope.
        deriver_a_id: String,
        /// Public A envelope digest.
        a_envelope_digest: PublicDigest32,
        /// Deriver B identity that received the second envelope.
        deriver_b_id: String,
        /// Public B envelope digest.
        b_envelope_digest: PublicDigest32,
        /// Forward timestamp in Unix milliseconds.
        forwarded_at_ms: u64,
    },
    /// A/B peer protocol is running.
    AbRunning {
        /// Public lifecycle scope.
        scope: LifecycleScopeV1,
        /// Router-assigned request id.
        request_id: String,
        /// Public transcript digest.
        transcript_digest: PublicDigest32,
        /// Start timestamp in Unix milliseconds.
        started_at_ms: u64,
    },
    /// Encrypted client output packages are ready.
    ClientOutputReady {
        /// Public lifecycle scope.
        scope: LifecycleScopeV1,
        /// Router-assigned request id.
        request_id: String,
        /// Public client package digests.
        client_package_digests: Vec<PublicDigest32>,
        /// Ready timestamp in Unix milliseconds.
        ready_at_ms: u64,
    },
    /// Encrypted SigningWorker output packages are ready.
    SigningWorkerOutputReady {
        /// Public lifecycle scope.
        scope: LifecycleScopeV1,
        /// Router-assigned request id.
        request_id: String,
        /// Public SigningWorker package digests.
        signing_worker_package_digests: Vec<PublicDigest32>,
        /// Ready timestamp in Unix milliseconds.
        ready_at_ms: u64,
    },
    /// SigningWorker activation completed.
    Activated {
        /// Public lifecycle scope.
        scope: LifecycleScopeV1,
        /// Router-assigned request id.
        request_id: String,
        /// Active SigningWorker descriptor created by activation.
        active_signing_worker_state: ActiveSigningWorkerStateV1,
    },
    /// Ceremony failed before activation.
    Failed {
        /// Public lifecycle scope.
        scope: LifecycleScopeV1,
        /// Last nonterminal state before failure.
        last_active_state: CloudflareDerivationCeremonyStateLabelV1,
        /// Stable failure code for operators.
        error_code: String,
        /// Redacted failure reason.
        redacted_reason: String,
        /// Failure timestamp in Unix milliseconds.
        failed_at_ms: u64,
    },
    /// Ceremony expired before activation.
    Expired {
        /// Public lifecycle scope.
        scope: LifecycleScopeV1,
        /// Last nonterminal state before expiry.
        last_active_state: CloudflareDerivationCeremonyStateLabelV1,
        /// Expiry timestamp in Unix milliseconds.
        expired_at_ms: u64,
    },
    /// Ceremony was abandoned before activation.
    Abandoned {
        /// Public lifecycle scope.
        scope: LifecycleScopeV1,
        /// Last nonterminal state before abandonment.
        last_active_state: CloudflareDerivationCeremonyStateLabelV1,
        /// Redacted abandon reason.
        redacted_reason: String,
        /// Abandonment timestamp in Unix milliseconds.
        abandoned_at_ms: u64,
    },
}

impl CloudflareDerivationCeremonyV1 {
    /// Creates a validated Created ceremony state.
    pub fn created(scope: LifecycleScopeV1, created_at_ms: u64) -> RouterAbProtocolResult<Self> {
        let ceremony = Self::Created {
            scope,
            created_at_ms,
        };
        ceremony.validate()?;
        Ok(ceremony)
    }

    /// Creates a validated Admitted ceremony state.
    pub fn admitted(
        scope: LifecycleScopeV1,
        request_id: impl Into<String>,
        admitted_at_ms: u64,
    ) -> RouterAbProtocolResult<Self> {
        let ceremony = Self::Admitted {
            scope,
            request_id: request_id.into(),
            admitted_at_ms,
        };
        ceremony.validate()?;
        Ok(ceremony)
    }

    /// Creates a validated A-envelope-forwarded ceremony state.
    pub fn a_envelope_forwarded(
        scope: LifecycleScopeV1,
        request_id: impl Into<String>,
        deriver_a_id: impl Into<String>,
        a_envelope_digest: PublicDigest32,
        forwarded_at_ms: u64,
    ) -> RouterAbProtocolResult<Self> {
        let ceremony = Self::AEnvelopeForwarded {
            scope,
            request_id: request_id.into(),
            deriver_a_id: deriver_a_id.into(),
            a_envelope_digest,
            forwarded_at_ms,
        };
        ceremony.validate()?;
        Ok(ceremony)
    }

    /// Creates a validated B-envelope-forwarded ceremony state.
    pub fn b_envelope_forwarded(
        scope: LifecycleScopeV1,
        request_id: impl Into<String>,
        deriver_a_id: impl Into<String>,
        a_envelope_digest: PublicDigest32,
        deriver_b_id: impl Into<String>,
        b_envelope_digest: PublicDigest32,
        forwarded_at_ms: u64,
    ) -> RouterAbProtocolResult<Self> {
        let ceremony = Self::BEnvelopeForwarded {
            scope,
            request_id: request_id.into(),
            deriver_a_id: deriver_a_id.into(),
            a_envelope_digest,
            deriver_b_id: deriver_b_id.into(),
            b_envelope_digest,
            forwarded_at_ms,
        };
        ceremony.validate()?;
        Ok(ceremony)
    }

    /// Creates a validated A/B-running ceremony state.
    pub fn ab_running(
        scope: LifecycleScopeV1,
        request_id: impl Into<String>,
        transcript_digest: PublicDigest32,
        started_at_ms: u64,
    ) -> RouterAbProtocolResult<Self> {
        let ceremony = Self::AbRunning {
            scope,
            request_id: request_id.into(),
            transcript_digest,
            started_at_ms,
        };
        ceremony.validate()?;
        Ok(ceremony)
    }

    /// Creates a validated client-output-ready ceremony state.
    pub fn client_output_ready(
        scope: LifecycleScopeV1,
        request_id: impl Into<String>,
        client_package_digests: Vec<PublicDigest32>,
        ready_at_ms: u64,
    ) -> RouterAbProtocolResult<Self> {
        let ceremony = Self::ClientOutputReady {
            scope,
            request_id: request_id.into(),
            client_package_digests,
            ready_at_ms,
        };
        ceremony.validate()?;
        Ok(ceremony)
    }

    /// Creates a validated SigningWorker-output-ready ceremony state.
    pub fn signing_worker_output_ready(
        scope: LifecycleScopeV1,
        request_id: impl Into<String>,
        signing_worker_package_digests: Vec<PublicDigest32>,
        ready_at_ms: u64,
    ) -> RouterAbProtocolResult<Self> {
        let ceremony = Self::SigningWorkerOutputReady {
            scope,
            request_id: request_id.into(),
            signing_worker_package_digests,
            ready_at_ms,
        };
        ceremony.validate()?;
        Ok(ceremony)
    }

    /// Creates a validated Activated ceremony state.
    pub fn activated(
        scope: LifecycleScopeV1,
        request_id: impl Into<String>,
        active_signing_worker_state: ActiveSigningWorkerStateV1,
    ) -> RouterAbProtocolResult<Self> {
        let ceremony = Self::Activated {
            scope,
            request_id: request_id.into(),
            active_signing_worker_state,
        };
        ceremony.validate()?;
        Ok(ceremony)
    }

    /// Creates a validated Failed ceremony state.
    pub fn failed(
        scope: LifecycleScopeV1,
        last_active_state: CloudflareDerivationCeremonyStateLabelV1,
        error_code: impl Into<String>,
        redacted_reason: impl Into<String>,
        failed_at_ms: u64,
    ) -> RouterAbProtocolResult<Self> {
        let ceremony = Self::Failed {
            scope,
            last_active_state,
            error_code: error_code.into(),
            redacted_reason: redacted_reason.into(),
            failed_at_ms,
        };
        ceremony.validate()?;
        Ok(ceremony)
    }

    /// Creates a validated Expired ceremony state.
    pub fn expired(
        scope: LifecycleScopeV1,
        last_active_state: CloudflareDerivationCeremonyStateLabelV1,
        expired_at_ms: u64,
    ) -> RouterAbProtocolResult<Self> {
        let ceremony = Self::Expired {
            scope,
            last_active_state,
            expired_at_ms,
        };
        ceremony.validate()?;
        Ok(ceremony)
    }

    /// Creates a validated Abandoned ceremony state.
    pub fn abandoned(
        scope: LifecycleScopeV1,
        last_active_state: CloudflareDerivationCeremonyStateLabelV1,
        redacted_reason: impl Into<String>,
        abandoned_at_ms: u64,
    ) -> RouterAbProtocolResult<Self> {
        let ceremony = Self::Abandoned {
            scope,
            last_active_state,
            redacted_reason: redacted_reason.into(),
            abandoned_at_ms,
        };
        ceremony.validate()?;
        Ok(ceremony)
    }

    /// Returns the lifecycle scope carried by this ceremony state.
    pub fn scope(&self) -> &LifecycleScopeV1 {
        match self {
            Self::Created { scope, .. }
            | Self::Admitted { scope, .. }
            | Self::AEnvelopeForwarded { scope, .. }
            | Self::BEnvelopeForwarded { scope, .. }
            | Self::AbRunning { scope, .. }
            | Self::ClientOutputReady { scope, .. }
            | Self::SigningWorkerOutputReady { scope, .. }
            | Self::Activated { scope, .. }
            | Self::Failed { scope, .. }
            | Self::Expired { scope, .. }
            | Self::Abandoned { scope, .. } => scope,
        }
    }

    /// Returns the state label.
    pub fn label(&self) -> CloudflareDerivationCeremonyStateLabelV1 {
        match self {
            Self::Created { .. } => CloudflareDerivationCeremonyStateLabelV1::Created,
            Self::Admitted { .. } => CloudflareDerivationCeremonyStateLabelV1::Admitted,
            Self::AEnvelopeForwarded { .. } => {
                CloudflareDerivationCeremonyStateLabelV1::AEnvelopeForwarded
            }
            Self::BEnvelopeForwarded { .. } => {
                CloudflareDerivationCeremonyStateLabelV1::BEnvelopeForwarded
            }
            Self::AbRunning { .. } => CloudflareDerivationCeremonyStateLabelV1::AbRunning,
            Self::ClientOutputReady { .. } => {
                CloudflareDerivationCeremonyStateLabelV1::ClientOutputReady
            }
            Self::SigningWorkerOutputReady { .. } => {
                CloudflareDerivationCeremonyStateLabelV1::SigningWorkerOutputReady
            }
            Self::Activated { .. } => CloudflareDerivationCeremonyStateLabelV1::Activated,
            Self::Failed { .. } => CloudflareDerivationCeremonyStateLabelV1::Failed,
            Self::Expired { .. } => CloudflareDerivationCeremonyStateLabelV1::Expired,
            Self::Abandoned { .. } => CloudflareDerivationCeremonyStateLabelV1::Abandoned,
        }
    }

    /// Returns the timestamp associated with this state.
    pub fn recorded_at_ms(&self) -> u64 {
        match self {
            Self::Created { created_at_ms, .. } => *created_at_ms,
            Self::Admitted { admitted_at_ms, .. } => *admitted_at_ms,
            Self::AEnvelopeForwarded {
                forwarded_at_ms, ..
            }
            | Self::BEnvelopeForwarded {
                forwarded_at_ms, ..
            } => *forwarded_at_ms,
            Self::AbRunning { started_at_ms, .. } => *started_at_ms,
            Self::ClientOutputReady { ready_at_ms, .. }
            | Self::SigningWorkerOutputReady { ready_at_ms, .. } => *ready_at_ms,
            Self::Activated {
                active_signing_worker_state,
                ..
            } => active_signing_worker_state.activated_at_ms,
            Self::Failed { failed_at_ms, .. } => *failed_at_ms,
            Self::Expired { expired_at_ms, .. } => *expired_at_ms,
            Self::Abandoned {
                abandoned_at_ms, ..
            } => *abandoned_at_ms,
        }
    }

    /// Validates ceremony state fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.scope().validate()?;
        require_positive_ms("derivation ceremony recorded_at_ms", self.recorded_at_ms())?;
        match self {
            Self::Created { .. } => Ok(()),
            Self::Admitted { request_id, .. } | Self::AbRunning { request_id, .. } => {
                require_non_empty("derivation ceremony request_id", request_id)
            }
            Self::AEnvelopeForwarded {
                request_id,
                deriver_a_id,
                ..
            } => {
                require_non_empty("derivation ceremony request_id", request_id)?;
                require_non_empty("derivation ceremony deriver_a_id", deriver_a_id)
            }
            Self::BEnvelopeForwarded {
                request_id,
                deriver_a_id,
                deriver_b_id,
                ..
            } => {
                require_non_empty("derivation ceremony request_id", request_id)?;
                require_non_empty("derivation ceremony deriver_a_id", deriver_a_id)?;
                require_non_empty("derivation ceremony deriver_b_id", deriver_b_id)
            }
            Self::ClientOutputReady {
                request_id,
                client_package_digests,
                ..
            } => {
                require_non_empty("derivation ceremony request_id", request_id)?;
                require_non_empty_vec(
                    "derivation ceremony client_package_digests",
                    client_package_digests,
                )
            }
            Self::SigningWorkerOutputReady {
                request_id,
                signing_worker_package_digests,
                ..
            } => {
                require_non_empty("derivation ceremony request_id", request_id)?;
                require_non_empty_vec(
                    "derivation ceremony signing_worker_package_digests",
                    signing_worker_package_digests,
                )
            }
            Self::Activated {
                scope,
                request_id,
                active_signing_worker_state,
            } => {
                require_non_empty("derivation ceremony request_id", request_id)?;
                active_signing_worker_state.validate()?;
                if active_signing_worker_state.account_id == scope.account_id
                    && active_signing_worker_state.session_id == scope.session_id
                    && active_signing_worker_state.signing_worker.server_id
                        == scope.selected_server_id
                {
                    Ok(())
                } else {
                    Err(RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::InvalidLifecycleState,
                        "activated derivation ceremony does not match active SigningWorker state",
                    ))
                }
            }
            Self::Failed {
                last_active_state,
                error_code,
                redacted_reason,
                ..
            } => {
                validate_nonterminal_ceremony_label(*last_active_state)?;
                require_non_empty("derivation ceremony error_code", error_code)?;
                require_non_empty("derivation ceremony redacted_reason", redacted_reason)
            }
            Self::Expired {
                last_active_state, ..
            } => validate_nonterminal_ceremony_label(*last_active_state),
            Self::Abandoned {
                last_active_state,
                redacted_reason,
                ..
            } => {
                validate_nonterminal_ceremony_label(*last_active_state)?;
                require_non_empty("derivation ceremony redacted_reason", redacted_reason)
            }
        }
    }

    /// Validates a stored ceremony transition.
    pub fn validate_transition_from(
        existing: Option<&Self>,
        replacement: &Self,
    ) -> RouterAbProtocolResult<()> {
        replacement.validate()?;
        let Some(existing) = existing else {
            if replacement.label() == CloudflareDerivationCeremonyStateLabelV1::Created {
                return Ok(());
            }
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLifecycleState,
                "derivation ceremony storage must start in created state",
            ));
        };
        existing.validate()?;
        if existing == replacement {
            return Ok(());
        }
        if existing.scope() != replacement.scope() {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLifecycleState,
                "derivation ceremony transition cannot change lifecycle scope",
            ));
        }
        if existing.label().is_terminal() {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLifecycleState,
                "terminal derivation ceremony state cannot be rewritten",
            ));
        }
        if replacement.recorded_at_ms() < existing.recorded_at_ms() {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidTimeRange,
                "derivation ceremony transition cannot move backwards in time",
            ));
        }
        match (existing.label(), replacement) {
            (
                CloudflareDerivationCeremonyStateLabelV1::Created,
                Self::Admitted { .. }
                | Self::Failed { .. }
                | Self::Expired { .. }
                | Self::Abandoned { .. },
            ) => validate_terminal_transition_source(existing.label(), replacement),
            (
                CloudflareDerivationCeremonyStateLabelV1::Admitted,
                Self::AEnvelopeForwarded { .. }
                | Self::Failed { .. }
                | Self::Expired { .. }
                | Self::Abandoned { .. },
            ) => validate_terminal_transition_source(existing.label(), replacement),
            (
                CloudflareDerivationCeremonyStateLabelV1::AEnvelopeForwarded,
                Self::BEnvelopeForwarded { .. }
                | Self::Failed { .. }
                | Self::Expired { .. }
                | Self::Abandoned { .. },
            ) => validate_terminal_transition_source(existing.label(), replacement),
            (
                CloudflareDerivationCeremonyStateLabelV1::BEnvelopeForwarded,
                Self::AbRunning { .. }
                | Self::Failed { .. }
                | Self::Expired { .. }
                | Self::Abandoned { .. },
            ) => validate_terminal_transition_source(existing.label(), replacement),
            (
                CloudflareDerivationCeremonyStateLabelV1::AbRunning,
                Self::ClientOutputReady { .. }
                | Self::Failed { .. }
                | Self::Expired { .. }
                | Self::Abandoned { .. },
            ) => validate_terminal_transition_source(existing.label(), replacement),
            (
                CloudflareDerivationCeremonyStateLabelV1::ClientOutputReady,
                Self::SigningWorkerOutputReady { .. }
                | Self::Failed { .. }
                | Self::Expired { .. }
                | Self::Abandoned { .. },
            ) => validate_terminal_transition_source(existing.label(), replacement),
            (
                CloudflareDerivationCeremonyStateLabelV1::SigningWorkerOutputReady,
                Self::Activated { .. }
                | Self::Failed { .. }
                | Self::Expired { .. }
                | Self::Abandoned { .. },
            ) => validate_terminal_transition_source(existing.label(), replacement),
            _ => Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLifecycleState,
                "invalid derivation ceremony lifecycle transition",
            )),
        }
    }
}

fn validate_nonterminal_ceremony_label(
    label: CloudflareDerivationCeremonyStateLabelV1,
) -> RouterAbProtocolResult<()> {
    if !label.is_terminal() {
        return Ok(());
    }
    Err(RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::InvalidLifecycleState,
        "terminal derivation ceremony state must reference a nonterminal prior state",
    ))
}

fn validate_terminal_transition_source(
    existing_label: CloudflareDerivationCeremonyStateLabelV1,
    replacement: &CloudflareDerivationCeremonyV1,
) -> RouterAbProtocolResult<()> {
    let replacement_last_active_state = match replacement {
        CloudflareDerivationCeremonyV1::Failed {
            last_active_state, ..
        }
        | CloudflareDerivationCeremonyV1::Expired {
            last_active_state, ..
        }
        | CloudflareDerivationCeremonyV1::Abandoned {
            last_active_state, ..
        } => Some(*last_active_state),
        _ => None,
    };
    if replacement_last_active_state.is_none()
        || replacement_last_active_state == Some(existing_label)
    {
        return Ok(());
    }
    Err(RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::InvalidLifecycleState,
        "terminal derivation ceremony state does not match previous active state",
    ))
}

/// Cloudflare derivation ceremony persistence receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareDerivationCeremonyPutReceiptV1 {
    /// Lifecycle id stored in the ceremony Durable Object record.
    pub lifecycle_id: String,
    /// Stored ceremony state label.
    pub state: CloudflareDerivationCeremonyStateLabelV1,
    /// Whether the requested state changed storage.
    pub stored: bool,
}

impl CloudflareDerivationCeremonyPutReceiptV1 {
    /// Creates a validated ceremony persistence receipt.
    pub fn new(
        lifecycle_id: impl Into<String>,
        state: CloudflareDerivationCeremonyStateLabelV1,
        stored: bool,
    ) -> RouterAbProtocolResult<Self> {
        let receipt = Self {
            lifecycle_id: lifecycle_id.into(),
            state,
            stored,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    /// Validates receipt fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("lifecycle_id", &self.lifecycle_id)
    }
}

/// SigningWorker-output activation receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSigningWorkerOutputActivationReceiptV1 {
    /// Lifecycle id activated by the SigningWorker.
    pub lifecycle_id: String,
    /// SigningWorker id that accepted activation.
    pub signing_worker_id: String,
    /// Public transcript digest.
    pub transcript_digest: PublicDigest32,
    /// Active SigningWorker state descriptor for normal signing.
    pub active_signing_worker_state: ActiveSigningWorkerStateV1,
    /// Whether activation was stored.
    pub activated: bool,
}

impl CloudflareSigningWorkerOutputActivationReceiptV1 {
    /// Creates a validated SigningWorker-output activation receipt.
    pub fn new(
        lifecycle_id: impl Into<String>,
        signing_worker_id: impl Into<String>,
        transcript_digest: PublicDigest32,
        active_signing_worker_state: ActiveSigningWorkerStateV1,
        activated: bool,
    ) -> RouterAbProtocolResult<Self> {
        let receipt = Self {
            lifecycle_id: lifecycle_id.into(),
            signing_worker_id: signing_worker_id.into(),
            transcript_digest,
            active_signing_worker_state,
            activated,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    /// Validates SigningWorker-output activation receipt fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("lifecycle_id", &self.lifecycle_id)?;
        require_non_empty("signing_worker_id", &self.signing_worker_id)?;
        self.active_signing_worker_state.validate()?;
        if self.active_signing_worker_state.signing_worker.server_id != self.signing_worker_id
            || self
                .active_signing_worker_state
                .activation_transcript_digest
                != self.transcript_digest
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "SigningWorker activation receipt active state does not match receipt identity",
            ));
        }
        Ok(())
    }
}

/// Stored SigningWorker activation record inside SigningWorker's output Durable Object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSigningWorkerOutputActivationRecordV1 {
    /// Encrypted SigningWorker proof-bundle activation request.
    pub activation: CloudflareSigningWorkerRecipientProofBundleActivationRequestV1,
    /// Active SigningWorker state descriptor indexed for normal signing.
    pub active_signing_worker_state: ActiveSigningWorkerStateV1,
    /// SigningWorker-local opened output material.
    pub material: CloudflareServerOutputMaterialRecordV1,
}

impl CloudflareSigningWorkerOutputActivationRecordV1 {
    /// Creates a validated SigningWorker activation record.
    pub fn new(
        activation: CloudflareSigningWorkerRecipientProofBundleActivationRequestV1,
        active_signing_worker_state: ActiveSigningWorkerStateV1,
        material: CloudflareServerOutputMaterialRecordV1,
    ) -> RouterAbProtocolResult<Self> {
        let record = Self {
            activation,
            active_signing_worker_state,
            material,
        };
        record.validate()?;
        Ok(record)
    }

    /// Validates the active SigningWorker descriptor against the stored activation.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.activation.validate()?;
        self.active_signing_worker_state.validate()?;
        self.material
            .validate_for_activation_request(&self.activation)?;
        let activation_context = &self.activation.activation_context;
        let lifecycle = activation_context.lifecycle();
        let selected_server = &activation_context.signer_set().selected_server;
        if self.active_signing_worker_state.account_id != lifecycle.account_id
            || self.active_signing_worker_state.session_id != lifecycle.session_id
            || self.active_signing_worker_state.signing_worker != *selected_server
            || self
                .active_signing_worker_state
                .activation_transcript_digest
                != activation_context.transcript_digest()
            || self.active_signing_worker_state.activation_digest
                != cloudflare_signing_worker_recipient_proof_bundle_activation_digest_v1(
                    &self.activation.activation,
                )?
            || self.material.transcript_digest
                != self
                    .active_signing_worker_state
                    .activation_transcript_digest
            || self.material.recipient_identity
                != self.active_signing_worker_state.signing_worker.server_id
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "SigningWorker activation record active state does not match activation request",
            ));
        }
        Ok(())
    }
}

/// Account/session/SigningWorker lookup for active SigningWorker state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareActiveSigningWorkerStateLookupV1 {
    /// Canonical account or wallet id.
    pub account_id: String,
    /// Canonical session id.
    pub session_id: String,
    /// Active SigningWorker id.
    pub signing_worker_id: String,
}

impl CloudflareActiveSigningWorkerStateLookupV1 {
    /// Creates a validated active SigningWorker lookup.
    pub fn new(
        account_id: impl Into<String>,
        session_id: impl Into<String>,
        signing_worker_id: impl Into<String>,
    ) -> RouterAbProtocolResult<Self> {
        let lookup = Self {
            account_id: account_id.into(),
            session_id: session_id.into(),
            signing_worker_id: signing_worker_id.into(),
        };
        lookup.validate()?;
        Ok(lookup)
    }

    /// Creates a lookup from a normal-signing scope.
    pub fn from_normal_signing_scope(scope: &NormalSigningScopeV1) -> RouterAbProtocolResult<Self> {
        scope.validate()?;
        Self::new(
            scope.account_id.clone(),
            scope.session_id.clone(),
            scope.signing_worker_id.clone(),
        )
    }

    /// Validates lookup identity fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("active signing worker lookup account_id", &self.account_id)?;
        require_non_empty("active signing worker lookup session_id", &self.session_id)?;
        require_non_empty(
            "active signing worker lookup signing_worker_id",
            &self.signing_worker_id,
        )
    }

    /// Validates returned active state matches this lookup.
    pub fn validate_active_state(
        &self,
        active_signing_worker_state: &ActiveSigningWorkerStateV1,
    ) -> RouterAbProtocolResult<()> {
        self.validate()?;
        active_signing_worker_state.validate()?;
        if active_signing_worker_state.account_id == self.account_id
            && active_signing_worker_state.session_id == self.session_id
            && active_signing_worker_state.signing_worker.server_id == self.signing_worker_id
        {
            return Ok(());
        }
        Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "active SigningWorker state does not match lookup",
        ))
    }
}

/// Lookup for active SigningWorker material by active-state descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSigningWorkerOutputMaterialLookupV1 {
    /// Active SigningWorker descriptor returned by the state index.
    pub active_signing_worker_state: ActiveSigningWorkerStateV1,
}

impl CloudflareSigningWorkerOutputMaterialLookupV1 {
    /// Creates a validated material lookup.
    pub fn new(
        active_signing_worker_state: ActiveSigningWorkerStateV1,
    ) -> RouterAbProtocolResult<Self> {
        let lookup = Self {
            active_signing_worker_state,
        };
        lookup.validate()?;
        Ok(lookup)
    }

    /// Validates the material lookup descriptor.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.active_signing_worker_state.validate()
    }

    /// Validates returned material matches the active state used for lookup.
    pub fn validate_material(
        &self,
        material: &CloudflareServerOutputMaterialRecordV1,
    ) -> RouterAbProtocolResult<()> {
        self.validate()?;
        material.validate()?;
        if material.transcript_digest
            == self
                .active_signing_worker_state
                .activation_transcript_digest
            && material.recipient_identity
                == self.active_signing_worker_state.signing_worker.server_id
        {
            return Ok(());
        }
        Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "SigningWorker material does not match active SigningWorker state",
        ))
    }
}

/// Stored SigningWorker round-1 nonce material for one normal-signing request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSigningWorkerRound1RecordV1 {
    /// Active SigningWorker descriptor that owns this nonce material.
    pub active_signing_worker_state: ActiveSigningWorkerStateV1,
    /// SigningWorker-local nonce handle returned to the client.
    pub server_round1_handle: String,
    /// Digest binding this nonce material to the exact normal-signing context.
    pub round1_binding_digest: PublicDigest32,
    /// Router-admitted digest that this nonce material may sign.
    pub admitted_signing_digest: PublicDigest32,
    /// Persisted round-1 nonce material and public commitments.
    pub round1_state: RoleSeparatedEd25519Round1StateV1,
    /// Creation timestamp in Unix milliseconds.
    pub created_at_ms: u64,
    /// Expiry timestamp in Unix milliseconds.
    pub expires_at_ms: u64,
}

impl CloudflareSigningWorkerRound1RecordV1 {
    /// Creates a validated round-1 record.
    pub fn new(
        active_signing_worker_state: ActiveSigningWorkerStateV1,
        server_round1_handle: impl Into<String>,
        round1_binding_digest: PublicDigest32,
        admitted_signing_digest: PublicDigest32,
        round1_state: RoleSeparatedEd25519Round1StateV1,
        created_at_ms: u64,
        expires_at_ms: u64,
    ) -> RouterAbProtocolResult<Self> {
        let record = Self {
            active_signing_worker_state,
            server_round1_handle: server_round1_handle.into(),
            round1_binding_digest,
            admitted_signing_digest,
            round1_state,
            created_at_ms,
            expires_at_ms,
        };
        record.validate()?;
        Ok(record)
    }

    /// Validates persisted round-1 state and lifecycle timing.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.active_signing_worker_state.validate()?;
        require_non_empty("server_round1_handle", &self.server_round1_handle)?;
        self.round1_state.validate().map_err(|err| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                format!("SigningWorker round-1 state is invalid: {err}"),
            )
        })?;
        require_positive_ms("SigningWorker round-1 created_at_ms", self.created_at_ms)?;
        require_positive_ms("SigningWorker round-1 expires_at_ms", self.expires_at_ms)?;
        if self.expires_at_ms > self.created_at_ms {
            return Ok(());
        }
        Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidTimeRange,
            "SigningWorker round-1 expiry must be after creation",
        ))
    }

    /// Validates this record is live and matches the lookup used to load it.
    pub fn validate_for_lookup(
        &self,
        lookup: &CloudflareSigningWorkerRound1LookupV1,
    ) -> RouterAbProtocolResult<()> {
        self.validate()?;
        lookup.validate()?;
        if lookup.now_unix_ms >= self.expires_at_ms {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ExpiredLocalRequest,
                "SigningWorker round-1 nonce material expired",
            ));
        }
        if self.server_round1_handle == lookup.server_round1_handle
            && self.round1_binding_digest == lookup.round1_binding_digest
            && self.active_signing_worker_state == lookup.active_signing_worker_state
        {
            return Ok(());
        }
        Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "SigningWorker round-1 record does not match lookup",
        ))
    }
}

/// Lookup for one stored SigningWorker round-1 nonce record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSigningWorkerRound1LookupV1 {
    /// Active SigningWorker descriptor that owns this nonce material.
    pub active_signing_worker_state: ActiveSigningWorkerStateV1,
    /// SigningWorker-local nonce handle returned to the client.
    pub server_round1_handle: String,
    /// Expected digest binding this nonce material to the normal-signing context.
    pub round1_binding_digest: PublicDigest32,
    /// Current time for expiry enforcement.
    pub now_unix_ms: u64,
}

impl CloudflareSigningWorkerRound1LookupV1 {
    /// Creates a validated round-1 lookup.
    pub fn new(
        active_signing_worker_state: ActiveSigningWorkerStateV1,
        server_round1_handle: impl Into<String>,
        round1_binding_digest: PublicDigest32,
        now_unix_ms: u64,
    ) -> RouterAbProtocolResult<Self> {
        let lookup = Self {
            active_signing_worker_state,
            server_round1_handle: server_round1_handle.into(),
            round1_binding_digest,
            now_unix_ms,
        };
        lookup.validate()?;
        Ok(lookup)
    }

    /// Validates lookup fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.active_signing_worker_state.validate()?;
        require_non_empty("server_round1_handle", &self.server_round1_handle)?;
        require_positive_ms("SigningWorker round-1 lookup now_unix_ms", self.now_unix_ms)
    }
}

/// Receipt for a stored SigningWorker round-1 nonce record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSigningWorkerRound1PutReceiptV1 {
    /// Active SigningWorker descriptor that owns this nonce material.
    pub active_signing_worker_state: ActiveSigningWorkerStateV1,
    /// SigningWorker-local nonce handle returned to the client.
    pub server_round1_handle: String,
    /// Digest binding this nonce material to the exact normal-signing context.
    pub round1_binding_digest: PublicDigest32,
    /// Server public round-1 commitments.
    pub server_commitments: RoleSeparatedEd25519CommitmentsV1,
    /// Whether storage changed.
    pub stored: bool,
}

impl CloudflareSigningWorkerRound1PutReceiptV1 {
    /// Creates a validated round-1 put receipt from the stored record.
    pub fn from_record(
        record: &CloudflareSigningWorkerRound1RecordV1,
        stored: bool,
    ) -> RouterAbProtocolResult<Self> {
        record.validate()?;
        let receipt = Self {
            active_signing_worker_state: record.active_signing_worker_state.clone(),
            server_round1_handle: record.server_round1_handle.clone(),
            round1_binding_digest: record.round1_binding_digest,
            server_commitments: record.round1_state.commitments,
            stored,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    /// Validates receipt fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.active_signing_worker_state.validate()?;
        require_non_empty("server_round1_handle", &self.server_round1_handle)?;
        self.server_commitments.validate().map_err(|err| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                format!("SigningWorker round-1 commitments are invalid: {err}"),
            )
        })
    }

    /// Validates receipt identity against the record that created it.
    pub fn validate_for_record(
        &self,
        record: &CloudflareSigningWorkerRound1RecordV1,
    ) -> RouterAbProtocolResult<()> {
        self.validate()?;
        record.validate()?;
        if self.active_signing_worker_state == record.active_signing_worker_state
            && self.server_round1_handle == record.server_round1_handle
            && self.round1_binding_digest == record.round1_binding_digest
            && self.server_commitments == record.round1_state.commitments
        {
            return Ok(());
        }
        Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "SigningWorker round-1 put receipt does not match record",
        ))
    }
}

/// Typed request body sent to Router/A/B Durable Objects.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum CloudflareDurableObjectRequestV1 {
    /// Check root-share presence.
    RootShareHas {
        /// Lookup request.
        lookup: CloudflareRootShareLookupRequestV1,
    },
    /// Read root-share startup metadata.
    RootShareStartupMetadata {
        /// Lookup request.
        lookup: CloudflareRootShareLookupRequestV1,
    },
    /// Reserve a replay key.
    RouterReplayReserve {
        /// Replay request.
        request: CloudflareReplayReserveRequestV1,
    },
    /// Remove expired replay reservations.
    RouterReplayCleanupExpired {
        /// Cleanup request.
        cleanup: CloudflareExpiredStateCleanupRequestV1,
    },
    /// Store public lifecycle state.
    RouterLifecyclePutPublicState {
        /// Public lifecycle state.
        state: RouterAbLifecycleStateV1,
    },
    /// Store Cloudflare derivation ceremony state.
    DerivationCeremonyPutState {
        /// Dedicated ceremony lifecycle state.
        ceremony: CloudflareDerivationCeremonyV1,
    },
    /// Evaluate project policy.
    RouterProjectPolicyEvaluate {
        /// Admission-store request.
        request: CloudflareRouterAdmissionStoreRequestV1,
    },
    /// Evaluate quota and active lifecycle state.
    RouterQuotaEvaluate {
        /// Admission-store request.
        request: CloudflareRouterAdmissionStoreRequestV1,
    },
    /// Remove expired quota reservations.
    RouterQuotaCleanupExpired {
        /// Cleanup request.
        cleanup: CloudflareExpiredStateCleanupRequestV1,
    },
    /// Evaluate abuse-control state.
    RouterAbuseEvaluate {
        /// Admission-store request.
        request: CloudflareRouterAdmissionStoreRequestV1,
    },
    /// Evaluate normal-signing project policy.
    RouterNormalSigningProjectPolicyEvaluate {
        /// Normal-signing admission-store request.
        request: CloudflareRouterNormalSigningAdmissionStoreRequestV1,
    },
    /// Evaluate normal-signing quota.
    RouterNormalSigningQuotaEvaluate {
        /// Normal-signing admission-store request.
        request: CloudflareRouterNormalSigningAdmissionStoreRequestV1,
    },
    /// Evaluate normal-signing abuse control.
    RouterNormalSigningAbuseEvaluate {
        /// Normal-signing admission-store request.
        request: CloudflareRouterNormalSigningAdmissionStoreRequestV1,
    },
    /// Activate server-output material.
    SigningWorkerOutputActivate {
        /// Strict SigningWorker proof-bundle activation request.
        activation: CloudflareSigningWorkerRecipientProofBundleActivationRequestV1,
        /// Server-local opened output material.
        material: CloudflareServerOutputMaterialRecordV1,
        /// Activation timestamp in Unix milliseconds.
        activated_at_ms: u64,
    },
    /// Read active SigningWorker state for normal signing.
    SigningWorkerOutputActiveStateGet {
        /// Account/session/server lookup.
        lookup: CloudflareActiveSigningWorkerStateLookupV1,
    },
    /// Read active SigningWorker material for normal signing.
    SigningWorkerOutputMaterialGet {
        /// Active-state descriptor and material handle.
        lookup: CloudflareSigningWorkerOutputMaterialLookupV1,
    },
    /// Store SigningWorker round-1 nonce material for normal signing.
    SigningWorkerRound1Put {
        /// Round-1 record.
        record: CloudflareSigningWorkerRound1RecordV1,
    },
    /// Take SigningWorker round-1 nonce material for normal signing.
    SigningWorkerRound1Take {
        /// Round-1 lookup.
        lookup: CloudflareSigningWorkerRound1LookupV1,
    },
    /// Remove expired SigningWorker round-1 records.
    SigningWorkerRound1CleanupExpired {
        /// Cleanup request.
        cleanup: CloudflareExpiredStateCleanupRequestV1,
    },
}

impl CloudflareDurableObjectRequestV1 {
    /// Creates a root-share presence request.
    pub fn root_share_has(
        lookup: CloudflareRootShareLookupRequestV1,
    ) -> RouterAbProtocolResult<Self> {
        let request = Self::RootShareHas { lookup };
        request.validate()?;
        Ok(request)
    }

    /// Creates a root-share startup metadata request.
    pub fn root_share_startup_metadata(
        lookup: CloudflareRootShareLookupRequestV1,
    ) -> RouterAbProtocolResult<Self> {
        let request = Self::RootShareStartupMetadata { lookup };
        request.validate()?;
        Ok(request)
    }

    /// Creates a replay reservation request.
    pub fn router_replay_reserve(
        request: CloudflareReplayReserveRequestV1,
    ) -> RouterAbProtocolResult<Self> {
        let request = Self::RouterReplayReserve { request };
        request.validate()?;
        Ok(request)
    }

    /// Creates an expired replay cleanup request.
    pub fn router_replay_cleanup_expired(
        cleanup: CloudflareExpiredStateCleanupRequestV1,
    ) -> RouterAbProtocolResult<Self> {
        let request = Self::RouterReplayCleanupExpired { cleanup };
        request.validate()?;
        Ok(request)
    }

    /// Creates a public lifecycle persistence request.
    pub fn router_lifecycle_put_public_state(
        state: RouterAbLifecycleStateV1,
    ) -> RouterAbProtocolResult<Self> {
        let request = Self::RouterLifecyclePutPublicState { state };
        request.validate()?;
        Ok(request)
    }

    /// Creates a derivation ceremony persistence request.
    pub fn derivation_ceremony_put_state(
        ceremony: CloudflareDerivationCeremonyV1,
    ) -> RouterAbProtocolResult<Self> {
        let request = Self::DerivationCeremonyPutState { ceremony };
        request.validate()?;
        Ok(request)
    }

    /// Creates a project-policy evaluation request.
    pub fn router_project_policy_evaluate(
        request: CloudflareRouterAdmissionStoreRequestV1,
    ) -> RouterAbProtocolResult<Self> {
        let request = Self::RouterProjectPolicyEvaluate { request };
        request.validate()?;
        Ok(request)
    }

    /// Creates a quota evaluation request.
    pub fn router_quota_evaluate(
        request: CloudflareRouterAdmissionStoreRequestV1,
    ) -> RouterAbProtocolResult<Self> {
        let request = Self::RouterQuotaEvaluate { request };
        request.validate()?;
        Ok(request)
    }

    /// Creates an expired quota cleanup request.
    pub fn router_quota_cleanup_expired(
        cleanup: CloudflareExpiredStateCleanupRequestV1,
    ) -> RouterAbProtocolResult<Self> {
        let request = Self::RouterQuotaCleanupExpired { cleanup };
        request.validate()?;
        Ok(request)
    }

    /// Creates an abuse-control evaluation request.
    pub fn router_abuse_evaluate(
        request: CloudflareRouterAdmissionStoreRequestV1,
    ) -> RouterAbProtocolResult<Self> {
        let request = Self::RouterAbuseEvaluate { request };
        request.validate()?;
        Ok(request)
    }

    /// Creates a normal-signing project-policy evaluation request.
    pub fn router_normal_signing_project_policy_evaluate(
        request: CloudflareRouterNormalSigningAdmissionStoreRequestV1,
    ) -> RouterAbProtocolResult<Self> {
        let request = Self::RouterNormalSigningProjectPolicyEvaluate { request };
        request.validate()?;
        Ok(request)
    }

    /// Creates a normal-signing quota evaluation request.
    pub fn router_normal_signing_quota_evaluate(
        request: CloudflareRouterNormalSigningAdmissionStoreRequestV1,
    ) -> RouterAbProtocolResult<Self> {
        let request = Self::RouterNormalSigningQuotaEvaluate { request };
        request.validate()?;
        Ok(request)
    }

    /// Creates a normal-signing abuse-control evaluation request.
    pub fn router_normal_signing_abuse_evaluate(
        request: CloudflareRouterNormalSigningAdmissionStoreRequestV1,
    ) -> RouterAbProtocolResult<Self> {
        let request = Self::RouterNormalSigningAbuseEvaluate { request };
        request.validate()?;
        Ok(request)
    }

    /// Creates a SigningWorker-output activation request.
    pub fn signing_worker_output_activate(
        activation: CloudflareSigningWorkerRecipientProofBundleActivationRequestV1,
        material: CloudflareServerOutputMaterialRecordV1,
        activated_at_ms: u64,
    ) -> RouterAbProtocolResult<Self> {
        let request = Self::SigningWorkerOutputActivate {
            activation,
            material,
            activated_at_ms,
        };
        request.validate()?;
        Ok(request)
    }

    /// Creates an active SigningWorker-state lookup request.
    pub fn signing_worker_output_active_state_get(
        lookup: CloudflareActiveSigningWorkerStateLookupV1,
    ) -> RouterAbProtocolResult<Self> {
        let request = Self::SigningWorkerOutputActiveStateGet { lookup };
        request.validate()?;
        Ok(request)
    }

    /// Creates a SigningWorker-output material lookup request.
    pub fn signing_worker_output_material_get(
        lookup: CloudflareSigningWorkerOutputMaterialLookupV1,
    ) -> RouterAbProtocolResult<Self> {
        let request = Self::SigningWorkerOutputMaterialGet { lookup };
        request.validate()?;
        Ok(request)
    }

    /// Creates a SigningWorker round-1 put request.
    pub fn signing_worker_round1_put(
        record: CloudflareSigningWorkerRound1RecordV1,
    ) -> RouterAbProtocolResult<Self> {
        let request = Self::SigningWorkerRound1Put { record };
        request.validate()?;
        Ok(request)
    }

    /// Creates a SigningWorker round-1 take request.
    pub fn signing_worker_round1_take(
        lookup: CloudflareSigningWorkerRound1LookupV1,
    ) -> RouterAbProtocolResult<Self> {
        let request = Self::SigningWorkerRound1Take { lookup };
        request.validate()?;
        Ok(request)
    }

    /// Creates an expired SigningWorker round-1 cleanup request.
    pub fn signing_worker_round1_cleanup_expired(
        cleanup: CloudflareExpiredStateCleanupRequestV1,
    ) -> RouterAbProtocolResult<Self> {
        let request = Self::SigningWorkerRound1CleanupExpired { cleanup };
        request.validate()?;
        Ok(request)
    }

    /// Returns the stable operation kind.
    pub fn operation_kind(&self) -> CloudflareDurableObjectOperationKindV1 {
        match self {
            Self::RootShareHas { .. } => CloudflareDurableObjectOperationKindV1::RootShareHas,
            Self::RootShareStartupMetadata { .. } => {
                CloudflareDurableObjectOperationKindV1::RootShareStartupMetadata
            }
            Self::RouterReplayReserve { .. } => {
                CloudflareDurableObjectOperationKindV1::RouterReplayReserve
            }
            Self::RouterReplayCleanupExpired { .. } => {
                CloudflareDurableObjectOperationKindV1::RouterReplayCleanupExpired
            }
            Self::RouterLifecyclePutPublicState { .. } => {
                CloudflareDurableObjectOperationKindV1::RouterLifecyclePutPublicState
            }
            Self::DerivationCeremonyPutState { .. } => {
                CloudflareDurableObjectOperationKindV1::DerivationCeremonyPutState
            }
            Self::RouterProjectPolicyEvaluate { .. } => {
                CloudflareDurableObjectOperationKindV1::RouterProjectPolicyEvaluate
            }
            Self::RouterQuotaEvaluate { .. } => {
                CloudflareDurableObjectOperationKindV1::RouterQuotaEvaluate
            }
            Self::RouterQuotaCleanupExpired { .. } => {
                CloudflareDurableObjectOperationKindV1::RouterQuotaCleanupExpired
            }
            Self::RouterAbuseEvaluate { .. } => {
                CloudflareDurableObjectOperationKindV1::RouterAbuseEvaluate
            }
            Self::RouterNormalSigningProjectPolicyEvaluate { .. } => {
                CloudflareDurableObjectOperationKindV1::RouterNormalSigningProjectPolicyEvaluate
            }
            Self::RouterNormalSigningQuotaEvaluate { .. } => {
                CloudflareDurableObjectOperationKindV1::RouterNormalSigningQuotaEvaluate
            }
            Self::RouterNormalSigningAbuseEvaluate { .. } => {
                CloudflareDurableObjectOperationKindV1::RouterNormalSigningAbuseEvaluate
            }
            Self::SigningWorkerOutputActivate { .. } => {
                CloudflareDurableObjectOperationKindV1::SigningWorkerOutputActivate
            }
            Self::SigningWorkerOutputActiveStateGet { .. } => {
                CloudflareDurableObjectOperationKindV1::SigningWorkerOutputActiveStateGet
            }
            Self::SigningWorkerOutputMaterialGet { .. } => {
                CloudflareDurableObjectOperationKindV1::SigningWorkerOutputMaterialGet
            }
            Self::SigningWorkerRound1Put { .. } => {
                CloudflareDurableObjectOperationKindV1::SigningWorkerRound1Put
            }
            Self::SigningWorkerRound1Take { .. } => {
                CloudflareDurableObjectOperationKindV1::SigningWorkerRound1Take
            }
            Self::SigningWorkerRound1CleanupExpired { .. } => {
                CloudflareDurableObjectOperationKindV1::SigningWorkerRound1CleanupExpired
            }
        }
    }

    /// Returns the Durable Object scope required by this operation.
    pub fn required_scope(&self) -> CloudflareDurableObjectScopeV1 {
        match self {
            Self::RootShareHas { lookup } | Self::RootShareStartupMetadata { lookup } => {
                lookup.expected_scope()
            }
            Self::RouterReplayReserve { .. } => CloudflareDurableObjectScopeV1::RouterReplay,
            Self::RouterReplayCleanupExpired { .. } => CloudflareDurableObjectScopeV1::RouterReplay,
            Self::RouterLifecyclePutPublicState { .. } => {
                CloudflareDurableObjectScopeV1::RouterLifecycle
            }
            Self::DerivationCeremonyPutState { .. } => {
                CloudflareDurableObjectScopeV1::RouterLifecycle
            }
            Self::RouterProjectPolicyEvaluate { .. } => {
                CloudflareDurableObjectScopeV1::RouterProjectPolicy
            }
            Self::RouterQuotaEvaluate { .. } => CloudflareDurableObjectScopeV1::RouterQuota,
            Self::RouterQuotaCleanupExpired { .. } => CloudflareDurableObjectScopeV1::RouterQuota,
            Self::RouterAbuseEvaluate { .. } => CloudflareDurableObjectScopeV1::RouterAbuse,
            Self::RouterNormalSigningProjectPolicyEvaluate { .. } => {
                CloudflareDurableObjectScopeV1::RouterProjectPolicy
            }
            Self::RouterNormalSigningQuotaEvaluate { .. } => {
                CloudflareDurableObjectScopeV1::RouterQuota
            }
            Self::RouterNormalSigningAbuseEvaluate { .. } => {
                CloudflareDurableObjectScopeV1::RouterAbuse
            }
            Self::SigningWorkerOutputActivate { .. }
            | Self::SigningWorkerOutputActiveStateGet { .. }
            | Self::SigningWorkerOutputMaterialGet { .. }
            | Self::SigningWorkerRound1Put { .. }
            | Self::SigningWorkerRound1Take { .. }
            | Self::SigningWorkerRound1CleanupExpired { .. } => {
                CloudflareDurableObjectScopeV1::signing_worker_server_output()
            }
        }
    }

    /// Validates operation fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        match self {
            Self::RootShareHas { lookup } | Self::RootShareStartupMetadata { lookup } => {
                lookup.validate()
            }
            Self::RouterReplayReserve { request } => request.validate(),
            Self::RouterReplayCleanupExpired { cleanup } => cleanup.validate(),
            Self::RouterLifecyclePutPublicState { state } => validate_lifecycle_state(state),
            Self::DerivationCeremonyPutState { ceremony } => ceremony.validate(),
            Self::RouterProjectPolicyEvaluate { request }
            | Self::RouterQuotaEvaluate { request }
            | Self::RouterAbuseEvaluate { request } => request.validate(),
            Self::RouterQuotaCleanupExpired { cleanup } => cleanup.validate(),
            Self::RouterNormalSigningProjectPolicyEvaluate { request }
            | Self::RouterNormalSigningQuotaEvaluate { request }
            | Self::RouterNormalSigningAbuseEvaluate { request } => request.validate(),
            Self::SigningWorkerOutputActivate {
                activation,
                material,
                activated_at_ms,
            } => {
                activation.validate()?;
                material.validate_for_activation_request(activation)?;
                require_positive_ms("SigningWorker activation activated_at_ms", *activated_at_ms)
            }
            Self::SigningWorkerOutputActiveStateGet { lookup } => lookup.validate(),
            Self::SigningWorkerOutputMaterialGet { lookup } => lookup.validate(),
            Self::SigningWorkerRound1Put { record } => record.validate(),
            Self::SigningWorkerRound1Take { lookup } => lookup.validate(),
            Self::SigningWorkerRound1CleanupExpired { cleanup } => cleanup.validate(),
        }
    }
}

/// Typed response body returned from Router/A/B Durable Objects.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum CloudflareDurableObjectResponseV1 {
    /// Root-share presence response.
    RootShareHas {
        /// Whether the root share is present.
        present: bool,
    },
    /// Root-share startup metadata response.
    RootShareStartupMetadata {
        /// Startup metadata.
        metadata: CloudflareRootShareStartupMetadataV1,
    },
    /// Replay reservation response.
    RouterReplayReserve {
        /// Reservation response.
        response: CloudflareReplayReserveResponseV1,
    },
    /// Expired replay cleanup response.
    RouterReplayCleanupExpired {
        /// Cleanup report.
        report: CloudflareExpiredStateCleanupReportV1,
    },
    /// Lifecycle persistence response.
    RouterLifecyclePutPublicState {
        /// Lifecycle receipt.
        receipt: CloudflareLifecyclePutReceiptV1,
    },
    /// Derivation ceremony persistence response.
    DerivationCeremonyPutState {
        /// Ceremony persistence receipt.
        receipt: CloudflareDerivationCeremonyPutReceiptV1,
    },
    /// Project-policy evaluation response.
    RouterProjectPolicyEvaluate {
        /// Project-policy outcome.
        policy: CloudflareRouterProjectPolicyV1,
    },
    /// Quota evaluation response.
    RouterQuotaEvaluate {
        /// Quota outcome.
        quota: CloudflareRouterQuotaCheckV1,
    },
    /// Expired quota cleanup response.
    RouterQuotaCleanupExpired {
        /// Cleanup report.
        report: CloudflareExpiredStateCleanupReportV1,
    },
    /// Abuse-control evaluation response.
    RouterAbuseEvaluate {
        /// Abuse-control outcome.
        abuse: CloudflareRouterAbuseCheckV1,
    },
    /// Normal-signing project-policy evaluation response.
    RouterNormalSigningProjectPolicyEvaluate {
        /// Project-policy outcome.
        policy: CloudflareRouterProjectPolicyV1,
    },
    /// Normal-signing quota evaluation response.
    RouterNormalSigningQuotaEvaluate {
        /// Quota outcome.
        quota: CloudflareRouterQuotaCheckV1,
    },
    /// Normal-signing abuse-control evaluation response.
    RouterNormalSigningAbuseEvaluate {
        /// Abuse-control outcome.
        abuse: CloudflareRouterAbuseCheckV1,
    },
    /// SigningWorker-output activation response.
    SigningWorkerOutputActivate {
        /// Activation receipt.
        receipt: CloudflareSigningWorkerOutputActivationReceiptV1,
    },
    /// Active server-state lookup response.
    SigningWorkerOutputActiveStateGet {
        /// Active SigningWorker state.
        active_signing_worker_state: ActiveSigningWorkerStateV1,
    },
    /// Active SigningWorker material lookup response.
    SigningWorkerOutputMaterialGet {
        /// Active SigningWorker material.
        material: CloudflareServerOutputMaterialRecordV1,
    },
    /// SigningWorker round-1 put response.
    SigningWorkerRound1Put {
        /// Put receipt.
        receipt: CloudflareSigningWorkerRound1PutReceiptV1,
    },
    /// SigningWorker round-1 take response.
    SigningWorkerRound1Take {
        /// Stored round-1 record.
        record: CloudflareSigningWorkerRound1RecordV1,
    },
    /// Expired SigningWorker round-1 cleanup response.
    SigningWorkerRound1CleanupExpired {
        /// Cleanup report.
        report: CloudflareExpiredStateCleanupReportV1,
    },
}

impl CloudflareDurableObjectResponseV1 {
    /// Creates a root-share presence response.
    pub fn root_share_has(present: bool) -> Self {
        Self::RootShareHas { present }
    }

    /// Creates a root-share startup metadata response.
    pub fn root_share_startup_metadata(
        metadata: CloudflareRootShareStartupMetadataV1,
    ) -> RouterAbProtocolResult<Self> {
        let response = Self::RootShareStartupMetadata { metadata };
        response.validate()?;
        Ok(response)
    }

    /// Creates a replay reservation response.
    pub fn router_replay_reserve(
        response: CloudflareReplayReserveResponseV1,
    ) -> RouterAbProtocolResult<Self> {
        let response = Self::RouterReplayReserve { response };
        response.validate()?;
        Ok(response)
    }

    /// Creates an expired replay cleanup response.
    pub fn router_replay_cleanup_expired(
        report: CloudflareExpiredStateCleanupReportV1,
    ) -> RouterAbProtocolResult<Self> {
        let response = Self::RouterReplayCleanupExpired { report };
        response.validate()?;
        Ok(response)
    }

    /// Creates a lifecycle persistence response.
    pub fn router_lifecycle_put_public_state(
        receipt: CloudflareLifecyclePutReceiptV1,
    ) -> RouterAbProtocolResult<Self> {
        let response = Self::RouterLifecyclePutPublicState { receipt };
        response.validate()?;
        Ok(response)
    }

    /// Creates a derivation ceremony persistence response.
    pub fn derivation_ceremony_put_state(
        receipt: CloudflareDerivationCeremonyPutReceiptV1,
    ) -> RouterAbProtocolResult<Self> {
        let response = Self::DerivationCeremonyPutState { receipt };
        response.validate()?;
        Ok(response)
    }

    /// Creates a project-policy evaluation response.
    pub fn router_project_policy_evaluate(
        policy: CloudflareRouterProjectPolicyV1,
    ) -> RouterAbProtocolResult<Self> {
        let response = Self::RouterProjectPolicyEvaluate { policy };
        response.validate()?;
        Ok(response)
    }

    /// Creates a quota evaluation response.
    pub fn router_quota_evaluate(
        quota: CloudflareRouterQuotaCheckV1,
    ) -> RouterAbProtocolResult<Self> {
        let response = Self::RouterQuotaEvaluate { quota };
        response.validate()?;
        Ok(response)
    }

    /// Creates an expired quota cleanup response.
    pub fn router_quota_cleanup_expired(
        report: CloudflareExpiredStateCleanupReportV1,
    ) -> RouterAbProtocolResult<Self> {
        let response = Self::RouterQuotaCleanupExpired { report };
        response.validate()?;
        Ok(response)
    }

    /// Creates an abuse-control evaluation response.
    pub fn router_abuse_evaluate(
        abuse: CloudflareRouterAbuseCheckV1,
    ) -> RouterAbProtocolResult<Self> {
        let response = Self::RouterAbuseEvaluate { abuse };
        response.validate()?;
        Ok(response)
    }

    /// Creates a normal-signing project-policy evaluation response.
    pub fn router_normal_signing_project_policy_evaluate(
        policy: CloudflareRouterProjectPolicyV1,
    ) -> RouterAbProtocolResult<Self> {
        let response = Self::RouterNormalSigningProjectPolicyEvaluate { policy };
        response.validate()?;
        Ok(response)
    }

    /// Creates a normal-signing quota evaluation response.
    pub fn router_normal_signing_quota_evaluate(
        quota: CloudflareRouterQuotaCheckV1,
    ) -> RouterAbProtocolResult<Self> {
        let response = Self::RouterNormalSigningQuotaEvaluate { quota };
        response.validate()?;
        Ok(response)
    }

    /// Creates a normal-signing abuse-control evaluation response.
    pub fn router_normal_signing_abuse_evaluate(
        abuse: CloudflareRouterAbuseCheckV1,
    ) -> RouterAbProtocolResult<Self> {
        let response = Self::RouterNormalSigningAbuseEvaluate { abuse };
        response.validate()?;
        Ok(response)
    }

    /// Creates a SigningWorker-output activation response.
    pub fn signing_worker_output_activate(
        receipt: CloudflareSigningWorkerOutputActivationReceiptV1,
    ) -> RouterAbProtocolResult<Self> {
        let response = Self::SigningWorkerOutputActivate { receipt };
        response.validate()?;
        Ok(response)
    }

    /// Creates an active SigningWorker-state lookup response.
    pub fn signing_worker_output_active_state_get(
        active_signing_worker_state: ActiveSigningWorkerStateV1,
    ) -> RouterAbProtocolResult<Self> {
        let response = Self::SigningWorkerOutputActiveStateGet {
            active_signing_worker_state,
        };
        response.validate()?;
        Ok(response)
    }

    /// Creates a SigningWorker-output material lookup response.
    pub fn signing_worker_output_material_get(
        material: CloudflareServerOutputMaterialRecordV1,
    ) -> RouterAbProtocolResult<Self> {
        let response = Self::SigningWorkerOutputMaterialGet { material };
        response.validate()?;
        Ok(response)
    }

    /// Creates a SigningWorker round-1 put response.
    pub fn signing_worker_round1_put(
        receipt: CloudflareSigningWorkerRound1PutReceiptV1,
    ) -> RouterAbProtocolResult<Self> {
        let response = Self::SigningWorkerRound1Put { receipt };
        response.validate()?;
        Ok(response)
    }

    /// Creates a SigningWorker round-1 take response.
    pub fn signing_worker_round1_take(
        record: CloudflareSigningWorkerRound1RecordV1,
    ) -> RouterAbProtocolResult<Self> {
        let response = Self::SigningWorkerRound1Take { record };
        response.validate()?;
        Ok(response)
    }

    /// Creates an expired SigningWorker round-1 cleanup response.
    pub fn signing_worker_round1_cleanup_expired(
        report: CloudflareExpiredStateCleanupReportV1,
    ) -> RouterAbProtocolResult<Self> {
        let response = Self::SigningWorkerRound1CleanupExpired { report };
        response.validate()?;
        Ok(response)
    }

    /// Returns the response operation kind.
    pub fn operation_kind(&self) -> CloudflareDurableObjectOperationKindV1 {
        match self {
            Self::RootShareHas { .. } => CloudflareDurableObjectOperationKindV1::RootShareHas,
            Self::RootShareStartupMetadata { .. } => {
                CloudflareDurableObjectOperationKindV1::RootShareStartupMetadata
            }
            Self::RouterReplayReserve { .. } => {
                CloudflareDurableObjectOperationKindV1::RouterReplayReserve
            }
            Self::RouterReplayCleanupExpired { .. } => {
                CloudflareDurableObjectOperationKindV1::RouterReplayCleanupExpired
            }
            Self::RouterLifecyclePutPublicState { .. } => {
                CloudflareDurableObjectOperationKindV1::RouterLifecyclePutPublicState
            }
            Self::DerivationCeremonyPutState { .. } => {
                CloudflareDurableObjectOperationKindV1::DerivationCeremonyPutState
            }
            Self::RouterProjectPolicyEvaluate { .. } => {
                CloudflareDurableObjectOperationKindV1::RouterProjectPolicyEvaluate
            }
            Self::RouterQuotaEvaluate { .. } => {
                CloudflareDurableObjectOperationKindV1::RouterQuotaEvaluate
            }
            Self::RouterQuotaCleanupExpired { .. } => {
                CloudflareDurableObjectOperationKindV1::RouterQuotaCleanupExpired
            }
            Self::RouterAbuseEvaluate { .. } => {
                CloudflareDurableObjectOperationKindV1::RouterAbuseEvaluate
            }
            Self::RouterNormalSigningProjectPolicyEvaluate { .. } => {
                CloudflareDurableObjectOperationKindV1::RouterNormalSigningProjectPolicyEvaluate
            }
            Self::RouterNormalSigningQuotaEvaluate { .. } => {
                CloudflareDurableObjectOperationKindV1::RouterNormalSigningQuotaEvaluate
            }
            Self::RouterNormalSigningAbuseEvaluate { .. } => {
                CloudflareDurableObjectOperationKindV1::RouterNormalSigningAbuseEvaluate
            }
            Self::SigningWorkerOutputActivate { .. } => {
                CloudflareDurableObjectOperationKindV1::SigningWorkerOutputActivate
            }
            Self::SigningWorkerOutputActiveStateGet { .. } => {
                CloudflareDurableObjectOperationKindV1::SigningWorkerOutputActiveStateGet
            }
            Self::SigningWorkerOutputMaterialGet { .. } => {
                CloudflareDurableObjectOperationKindV1::SigningWorkerOutputMaterialGet
            }
            Self::SigningWorkerRound1Put { .. } => {
                CloudflareDurableObjectOperationKindV1::SigningWorkerRound1Put
            }
            Self::SigningWorkerRound1Take { .. } => {
                CloudflareDurableObjectOperationKindV1::SigningWorkerRound1Take
            }
            Self::SigningWorkerRound1CleanupExpired { .. } => {
                CloudflareDurableObjectOperationKindV1::SigningWorkerRound1CleanupExpired
            }
        }
    }

    /// Validates response fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        match self {
            Self::RootShareHas { .. } => Ok(()),
            Self::RootShareStartupMetadata { metadata } => metadata.validate(),
            Self::RouterReplayReserve { response } => response.validate(),
            Self::RouterReplayCleanupExpired { report } => report.validate(),
            Self::RouterLifecyclePutPublicState { receipt } => receipt.validate(),
            Self::DerivationCeremonyPutState { receipt } => receipt.validate(),
            Self::RouterProjectPolicyEvaluate { policy } => policy.validate(),
            Self::RouterQuotaEvaluate { quota } => quota.validate(),
            Self::RouterQuotaCleanupExpired { report } => report.validate(),
            Self::RouterAbuseEvaluate { abuse } => abuse.validate(),
            Self::RouterNormalSigningProjectPolicyEvaluate { policy } => policy.validate(),
            Self::RouterNormalSigningQuotaEvaluate { quota } => quota.validate(),
            Self::RouterNormalSigningAbuseEvaluate { abuse } => abuse.validate(),
            Self::SigningWorkerOutputActivate { receipt } => receipt.validate(),
            Self::SigningWorkerOutputActiveStateGet {
                active_signing_worker_state,
            } => active_signing_worker_state.validate(),
            Self::SigningWorkerOutputMaterialGet { material } => material.validate(),
            Self::SigningWorkerRound1Put { receipt } => receipt.validate(),
            Self::SigningWorkerRound1Take { record } => record.validate(),
            Self::SigningWorkerRound1CleanupExpired { report } => report.validate(),
        }
    }

    /// Validates the response branch and identity match the request.
    pub fn validate_for_request(
        &self,
        request: &CloudflareDurableObjectRequestV1,
    ) -> RouterAbProtocolResult<()> {
        self.validate()?;
        if self.operation_kind() != request.operation_kind() {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "Durable Object response operation does not match request",
            ));
        }
        match (self, request) {
            (
                Self::RootShareStartupMetadata { metadata },
                CloudflareDurableObjectRequestV1::RootShareStartupMetadata { lookup },
            ) => metadata.validate_matches_lookup(lookup),
            (
                Self::RouterReplayReserve { response },
                CloudflareDurableObjectRequestV1::RouterReplayReserve { request },
            ) => {
                if response.request_id == request.request_id {
                    Ok(())
                } else {
                    Err(RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                        "replay reservation response request id does not match request",
                    ))
                }
            }
            (
                Self::RouterLifecyclePutPublicState { receipt },
                CloudflareDurableObjectRequestV1::RouterLifecyclePutPublicState { state },
            ) => {
                if receipt.lifecycle_id == state.scope().lifecycle_id {
                    Ok(())
                } else {
                    Err(RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                        "lifecycle receipt id does not match request state",
                    ))
                }
            }
            (
                Self::DerivationCeremonyPutState { receipt },
                CloudflareDurableObjectRequestV1::DerivationCeremonyPutState { ceremony },
            ) => {
                if receipt.lifecycle_id == ceremony.scope().lifecycle_id
                    && receipt.state == ceremony.label()
                {
                    Ok(())
                } else {
                    Err(RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                        "derivation ceremony receipt does not match request state",
                    ))
                }
            }
            (
                Self::RouterProjectPolicyEvaluate { .. },
                CloudflareDurableObjectRequestV1::RouterProjectPolicyEvaluate { request },
            )
            | (
                Self::RouterQuotaEvaluate { .. },
                CloudflareDurableObjectRequestV1::RouterQuotaEvaluate { request },
            )
            | (
                Self::RouterAbuseEvaluate { .. },
                CloudflareDurableObjectRequestV1::RouterAbuseEvaluate { request },
            ) => request.validate(),
            (
                Self::RouterNormalSigningProjectPolicyEvaluate { .. },
                CloudflareDurableObjectRequestV1::RouterNormalSigningProjectPolicyEvaluate {
                    request,
                },
            )
            | (
                Self::RouterNormalSigningQuotaEvaluate { .. },
                CloudflareDurableObjectRequestV1::RouterNormalSigningQuotaEvaluate { request },
            )
            | (
                Self::RouterNormalSigningAbuseEvaluate { .. },
                CloudflareDurableObjectRequestV1::RouterNormalSigningAbuseEvaluate { request },
            ) => request.validate(),
            (
                Self::SigningWorkerOutputActivate { receipt },
                CloudflareDurableObjectRequestV1::SigningWorkerOutputActivate {
                    activation, ..
                },
            ) => {
                let activation_context = &activation.activation_context;
                let selected_server = &activation_context.signer_set().selected_server;
                if receipt.lifecycle_id == activation_context.lifecycle().lifecycle_id
                    && receipt.signing_worker_id == selected_server.server_id
                    && receipt.transcript_digest == activation_context.transcript_digest()
                    && receipt.active_signing_worker_state.account_id
                        == activation_context.lifecycle().account_id
                    && receipt.active_signing_worker_state.session_id
                        == activation_context.lifecycle().session_id
                    && receipt.active_signing_worker_state.signing_worker == *selected_server
                {
                    Ok(())
                } else {
                    Err(RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                        "SigningWorker activation receipt does not match request",
                    ))
                }
            }
            (
                Self::SigningWorkerOutputActiveStateGet {
                    active_signing_worker_state,
                },
                CloudflareDurableObjectRequestV1::SigningWorkerOutputActiveStateGet { lookup },
            ) => lookup.validate_active_state(active_signing_worker_state),
            (
                Self::SigningWorkerOutputMaterialGet { material },
                CloudflareDurableObjectRequestV1::SigningWorkerOutputMaterialGet { lookup },
            ) => lookup.validate_material(material),
            (
                Self::SigningWorkerRound1Put { receipt },
                CloudflareDurableObjectRequestV1::SigningWorkerRound1Put { record },
            ) => receipt.validate_for_record(record),
            (
                Self::SigningWorkerRound1Take { record },
                CloudflareDurableObjectRequestV1::SigningWorkerRound1Take { lookup },
            ) => record.validate_for_lookup(lookup),
            _ => Ok(()),
        }
    }
}

/// Validated executable Durable Object call descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareDurableObjectCallV1 {
    /// Worker role initiating the call.
    pub worker_role: CloudflareWorkerRoleV1,
    /// Durable Object binding descriptor.
    pub binding: CloudflareDurableObjectBindingV1,
    /// Typed Durable Object request.
    pub request: CloudflareDurableObjectRequestV1,
}

impl CloudflareDurableObjectCallV1 {
    /// Creates a validated Durable Object call descriptor.
    pub fn new(
        worker_role: CloudflareWorkerRoleV1,
        binding: CloudflareDurableObjectBindingV1,
        request: CloudflareDurableObjectRequestV1,
    ) -> RouterAbProtocolResult<Self> {
        let call = Self {
            worker_role,
            binding,
            request,
        };
        call.validate()?;
        Ok(call)
    }

    /// Validates worker visibility and operation scope.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.binding.validate_visible_to(self.worker_role)?;
        self.request.validate()?;
        if self.binding.scope != self.request.required_scope() {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                format!(
                    "{} Durable Object call expected {:?} scope, received {:?}",
                    self.request.operation_kind().as_str(),
                    self.request.required_scope(),
                    self.binding.scope
                ),
            ));
        }
        Ok(())
    }

    /// Returns the operation kind.
    pub fn operation_kind(&self) -> CloudflareDurableObjectOperationKindV1 {
        self.request.operation_kind()
    }

    /// Returns the internal Durable Object request URL.
    pub fn durable_object_url(&self) -> String {
        format!(
            "https://router-ab-durable-object.internal{}",
            self.operation_kind().path()
        )
    }

    /// Returns the storage key that the Durable Object should use for this call.
    pub fn storage_key(&self) -> String {
        match &self.request {
            CloudflareDurableObjectRequestV1::RootShareHas { lookup }
            | CloudflareDurableObjectRequestV1::RootShareStartupMetadata { lookup } => format!(
                "{}root-share/{}/{}/{}",
                self.binding.key_prefix,
                lookup.signer_set_id,
                lookup.signer_role.as_str(),
                lookup.root_share_epoch.as_str()
            ),
            CloudflareDurableObjectRequestV1::RouterReplayReserve { request } => format!(
                "{}replay/{}/{}",
                self.binding.key_prefix,
                request.request_id,
                digest_hex(request.replay_material_digest)
            ),
            CloudflareDurableObjectRequestV1::RouterReplayCleanupExpired { .. } => {
                self.replay_storage_prefix()
            }
            CloudflareDurableObjectRequestV1::RouterLifecyclePutPublicState { state } => {
                format!(
                    "{}lifecycle/{}",
                    self.binding.key_prefix,
                    state.scope().lifecycle_id
                )
            }
            CloudflareDurableObjectRequestV1::DerivationCeremonyPutState { ceremony } => {
                format!(
                    "{}derivation-ceremony/{}",
                    self.binding.key_prefix,
                    ceremony.scope().lifecycle_id
                )
            }
            CloudflareDurableObjectRequestV1::RouterProjectPolicyEvaluate { request } => format!(
                "{}project-policy/{}/{}/{}",
                self.binding.key_prefix,
                request.metadata.org_id,
                request.metadata.project_id,
                request.metadata.environment
            ),
            CloudflareDurableObjectRequestV1::RouterQuotaEvaluate { request } => format!(
                "{}quota/{}/{}/{}/{}/{}",
                self.binding.key_prefix,
                request.metadata.org_id,
                request.metadata.project_id,
                request.metadata.environment,
                request.metadata.account_id,
                request.metadata.work_kind.as_str()
            ),
            CloudflareDurableObjectRequestV1::RouterQuotaCleanupExpired { .. } => {
                self.quota_storage_prefix()
            }
            CloudflareDurableObjectRequestV1::RouterAbuseEvaluate { request } => format!(
                "{}abuse/{}/{}",
                self.binding.key_prefix,
                digest_hex(request.metadata.trusted_source_digest),
                request.metadata.account_id
            ),
            CloudflareDurableObjectRequestV1::RouterNormalSigningProjectPolicyEvaluate {
                request,
            } => format!(
                "{}project-policy/{}/{}/{}",
                self.binding.key_prefix,
                request.metadata.org_id,
                request.metadata.project_id,
                request.metadata.environment
            ),
            CloudflareDurableObjectRequestV1::RouterNormalSigningQuotaEvaluate { request } => {
                format!(
                    "{}quota/{}/{}/{}/{}/normal-signing",
                    self.binding.key_prefix,
                    request.metadata.org_id,
                    request.metadata.project_id,
                    request.metadata.environment,
                    request.metadata.account_id
                )
            }
            CloudflareDurableObjectRequestV1::RouterNormalSigningAbuseEvaluate { request } => {
                format!(
                    "{}abuse/{}/{}",
                    self.binding.key_prefix,
                    digest_hex(request.metadata.trusted_source_digest),
                    request.metadata.account_id
                )
            }
            CloudflareDurableObjectRequestV1::SigningWorkerOutputActivate {
                activation, ..
            } => format!(
                "{}signing-worker-output/{}/{}",
                self.binding.key_prefix,
                activation.activation_context.lifecycle().lifecycle_id,
                digest_hex(activation.activation_context.transcript_digest())
            ),
            CloudflareDurableObjectRequestV1::SigningWorkerOutputActiveStateGet { lookup } => {
                format!(
                    "{}active-signing-worker/{}/{}/{}",
                    self.binding.key_prefix,
                    lookup.account_id,
                    lookup.session_id,
                    lookup.signing_worker_id
                )
            }
            CloudflareDurableObjectRequestV1::SigningWorkerOutputMaterialGet { lookup } => lookup
                .active_signing_worker_state
                .signing_worker_material_handle
                .clone(),
            CloudflareDurableObjectRequestV1::SigningWorkerRound1Put { record } => format!(
                "{}signing-worker-round1/{}/{}/{}/{}",
                self.binding.key_prefix,
                record.active_signing_worker_state.account_id,
                record.active_signing_worker_state.session_id,
                record.active_signing_worker_state.signing_worker.server_id,
                record.server_round1_handle
            ),
            CloudflareDurableObjectRequestV1::SigningWorkerRound1Take { lookup } => format!(
                "{}signing-worker-round1/{}/{}/{}/{}",
                self.binding.key_prefix,
                lookup.active_signing_worker_state.account_id,
                lookup.active_signing_worker_state.session_id,
                lookup.active_signing_worker_state.signing_worker.server_id,
                lookup.server_round1_handle
            ),
            CloudflareDurableObjectRequestV1::SigningWorkerRound1CleanupExpired { .. } => {
                self.signing_worker_round1_storage_prefix()
            }
        }
    }

    /// Returns the prefix used by replay primary storage records.
    pub fn replay_storage_prefix(&self) -> String {
        format!("{}replay/", self.binding.key_prefix)
    }

    /// Returns the prefix used by replay request-id index records.
    pub fn replay_request_index_storage_prefix(&self) -> String {
        format!("{}replay-request/", self.binding.key_prefix)
    }

    /// Returns the prefix used by quota storage records.
    pub fn quota_storage_prefix(&self) -> String {
        format!("{}quota/", self.binding.key_prefix)
    }

    /// Returns the prefix used by SigningWorker round-1 storage records.
    pub fn signing_worker_round1_storage_prefix(&self) -> String {
        format!("{}signing-worker-round1/", self.binding.key_prefix)
    }

    /// Returns the request-id replay index key used by replay reservations.
    pub fn replay_request_index_storage_key(&self) -> RouterAbProtocolResult<String> {
        self.validate()?;
        let CloudflareDurableObjectRequestV1::RouterReplayReserve { request } = &self.request
        else {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "replay request index key is defined only for router replay reservations",
            ));
        };
        Ok(format!(
            "{}replay-request/{}",
            self.binding.key_prefix, request.request_id
        ))
    }

    /// Returns the account/session/SigningWorker active-state index key.
    pub fn active_signing_worker_state_index_storage_key(&self) -> RouterAbProtocolResult<String> {
        self.validate()?;
        match &self.request {
            CloudflareDurableObjectRequestV1::SigningWorkerOutputActivate { activation, .. } => {
                let lifecycle = activation.activation_context.lifecycle();
                let selected_server = &activation.activation_context.signer_set().selected_server;
                Ok(format!(
                    "{}active-signing-worker/{}/{}/{}",
                    self.binding.key_prefix,
                    lifecycle.account_id,
                    lifecycle.session_id,
                    selected_server.server_id
                ))
            }
            CloudflareDurableObjectRequestV1::SigningWorkerOutputActiveStateGet { lookup } => {
                Ok(format!(
                    "{}active-signing-worker/{}/{}/{}",
                    self.binding.key_prefix,
                    lookup.account_id,
                    lookup.session_id,
                    lookup.signing_worker_id
                ))
            }
            CloudflareDurableObjectRequestV1::SigningWorkerOutputMaterialGet { lookup } => {
                Ok(lookup
                    .active_signing_worker_state
                    .signing_worker_material_handle
                    .clone())
            }
            _ => Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "active SigningWorker state index is defined only for SigningWorker-output operations",
            )),
        }
    }
}

/// Storage methods required by the typed Durable Object operation handler.
pub trait CloudflareDurableObjectStorageV1 {
    /// Reads root-share startup metadata by storage key.
    fn root_share_startup_metadata(
        &self,
        storage_key: &str,
    ) -> RouterAbProtocolResult<Option<CloudflareRootShareStartupMetadataV1>>;

    /// Reads a replay reservation by request-id index key.
    fn replay_reservation_by_request_id(
        &self,
        request_index_key: &str,
    ) -> RouterAbProtocolResult<Option<CloudflareReplayReserveRequestV1>>;

    /// Stores a replay reservation under both request-id and transcript-bound keys.
    fn put_replay_reservation(
        &mut self,
        request_index_key: &str,
        storage_key: &str,
        request: CloudflareReplayReserveRequestV1,
    ) -> RouterAbProtocolResult<()>;

    /// Removes expired replay reservations and request-id indexes.
    fn cleanup_expired_replay_reservations(
        &mut self,
        now_unix_ms: u64,
    ) -> RouterAbProtocolResult<CloudflareExpiredStateCleanupReportV1>;

    /// Stores public Router lifecycle state.
    fn put_router_lifecycle_state(
        &mut self,
        storage_key: &str,
        state: RouterAbLifecycleStateV1,
    ) -> RouterAbProtocolResult<()>;

    /// Reads public Router lifecycle state by storage key.
    fn router_lifecycle_state(
        &self,
        storage_key: &str,
    ) -> RouterAbProtocolResult<Option<RouterAbLifecycleStateV1>>;

    /// Stores Cloudflare derivation ceremony state.
    fn put_derivation_ceremony(
        &mut self,
        storage_key: &str,
        ceremony: CloudflareDerivationCeremonyV1,
    ) -> RouterAbProtocolResult<()>;

    /// Reads Cloudflare derivation ceremony state by storage key.
    fn derivation_ceremony(
        &self,
        storage_key: &str,
    ) -> RouterAbProtocolResult<Option<CloudflareDerivationCeremonyV1>>;

    /// Reads project-policy state by storage key.
    fn router_project_policy(
        &self,
        storage_key: &str,
    ) -> RouterAbProtocolResult<Option<CloudflareRouterProjectPolicyRecordV1>>;

    /// Reads abuse-control state by storage key.
    fn router_abuse(
        &self,
        storage_key: &str,
    ) -> RouterAbProtocolResult<Option<CloudflareRouterAbuseRecordV1>>;

    /// Reads active quota state by storage key.
    fn router_quota(
        &self,
        storage_key: &str,
    ) -> RouterAbProtocolResult<Option<CloudflareRouterQuotaReservationV1>>;

    /// Stores active quota state.
    fn put_router_quota(
        &mut self,
        storage_key: &str,
        reservation: CloudflareRouterQuotaReservationV1,
    ) -> RouterAbProtocolResult<()>;

    /// Removes expired quota reservations.
    fn cleanup_expired_router_quota_reservations(
        &mut self,
        now_unix_ms: u64,
    ) -> RouterAbProtocolResult<CloudflareExpiredStateCleanupReportV1>;

    /// Reads SigningWorker-output activation by storage key.
    fn signing_worker_output_activation(
        &self,
        storage_key: &str,
    ) -> RouterAbProtocolResult<Option<CloudflareSigningWorkerOutputActivationRecordV1>>;

    /// Stores SigningWorker-output activation.
    fn put_signing_worker_output_activation(
        &mut self,
        storage_key: &str,
        active_state_index_key: &str,
        record: CloudflareSigningWorkerOutputActivationRecordV1,
    ) -> RouterAbProtocolResult<()>;

    /// Reads active SigningWorker state by account/session/SigningWorker index key.
    fn active_signing_worker_state(
        &self,
        active_state_index_key: &str,
    ) -> RouterAbProtocolResult<Option<ActiveSigningWorkerStateV1>>;

    /// Reads SigningWorker round-1 nonce material by storage key.
    fn signing_worker_round1(
        &self,
        storage_key: &str,
    ) -> RouterAbProtocolResult<Option<CloudflareSigningWorkerRound1RecordV1>>;

    /// Stores SigningWorker round-1 nonce material.
    fn put_signing_worker_round1(
        &mut self,
        storage_key: &str,
        record: CloudflareSigningWorkerRound1RecordV1,
    ) -> RouterAbProtocolResult<()>;

    /// Removes and returns SigningWorker round-1 nonce material.
    fn take_signing_worker_round1(
        &mut self,
        storage_key: &str,
    ) -> RouterAbProtocolResult<Option<CloudflareSigningWorkerRound1RecordV1>>;

    /// Removes expired SigningWorker round-1 nonce records.
    fn cleanup_expired_signing_worker_round1_records(
        &mut self,
        now_unix_ms: u64,
    ) -> RouterAbProtocolResult<CloudflareExpiredStateCleanupReportV1>;
}

/// Deterministic in-memory Durable Object storage used by tests and local checks.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CloudflareDurableObjectMemoryStorageV1 {
    root_share_metadata: BTreeMap<String, CloudflareRootShareStartupMetadataV1>,
    replay_by_request_id: BTreeMap<String, CloudflareReplayReserveRequestV1>,
    replay_by_storage_key: BTreeMap<String, CloudflareReplayReserveRequestV1>,
    lifecycle_states: BTreeMap<String, RouterAbLifecycleStateV1>,
    derivation_ceremonies: BTreeMap<String, CloudflareDerivationCeremonyV1>,
    project_policies: BTreeMap<String, CloudflareRouterProjectPolicyRecordV1>,
    abuse_records: BTreeMap<String, CloudflareRouterAbuseRecordV1>,
    quota_reservations: BTreeMap<String, CloudflareRouterQuotaReservationV1>,
    signing_worker_activations: BTreeMap<String, CloudflareSigningWorkerOutputActivationRecordV1>,
    active_signing_worker_states: BTreeMap<String, ActiveSigningWorkerStateV1>,
    signing_worker_round1_records: BTreeMap<String, CloudflareSigningWorkerRound1RecordV1>,
}

impl CloudflareDurableObjectMemoryStorageV1 {
    /// Creates empty in-memory Durable Object storage.
    pub fn new() -> Self {
        Self::default()
    }

    /// Seeds root-share startup metadata at a precomputed storage key.
    pub fn seed_root_share_startup_metadata(
        &mut self,
        storage_key: impl Into<String>,
        metadata: CloudflareRootShareStartupMetadataV1,
    ) -> RouterAbProtocolResult<()> {
        let storage_key = storage_key.into();
        require_non_empty("storage_key", &storage_key)?;
        metadata.validate()?;
        self.root_share_metadata.insert(storage_key, metadata);
        Ok(())
    }

    /// Seeds project-policy state at a precomputed storage key.
    pub fn seed_router_project_policy(
        &mut self,
        storage_key: impl Into<String>,
        policy: CloudflareRouterProjectPolicyRecordV1,
    ) -> RouterAbProtocolResult<()> {
        let storage_key = storage_key.into();
        require_non_empty("storage_key", &storage_key)?;
        policy.validate()?;
        self.project_policies.insert(storage_key, policy);
        Ok(())
    }

    /// Seeds abuse-control state at a precomputed storage key.
    pub fn seed_router_abuse(
        &mut self,
        storage_key: impl Into<String>,
        abuse: CloudflareRouterAbuseRecordV1,
    ) -> RouterAbProtocolResult<()> {
        let storage_key = storage_key.into();
        require_non_empty("storage_key", &storage_key)?;
        abuse.validate()?;
        self.abuse_records.insert(storage_key, abuse);
        Ok(())
    }

    /// Reads a stored lifecycle state for tests and local smoke checks.
    pub fn lifecycle_state(&self, storage_key: &str) -> Option<&RouterAbLifecycleStateV1> {
        self.lifecycle_states.get(storage_key)
    }

    /// Reads a stored derivation ceremony for tests and local smoke checks.
    pub fn derivation_ceremony(
        &self,
        storage_key: &str,
    ) -> Option<&CloudflareDerivationCeremonyV1> {
        self.derivation_ceremonies.get(storage_key)
    }

    /// Reads a stored SigningWorker activation for tests and local smoke checks.
    pub fn signing_worker_activation(
        &self,
        storage_key: &str,
    ) -> Option<&CloudflareSigningWorkerOutputActivationRecordV1> {
        self.signing_worker_activations.get(storage_key)
    }

    /// Reads indexed active SigningWorker state for tests and local smoke checks.
    pub fn active_signing_worker_state(
        &self,
        storage_key: &str,
    ) -> Option<&ActiveSigningWorkerStateV1> {
        self.active_signing_worker_states.get(storage_key)
    }

    /// Reads a transcript-bound replay reservation for tests and local smoke checks.
    pub fn replay_reservation(
        &self,
        storage_key: &str,
    ) -> Option<&CloudflareReplayReserveRequestV1> {
        self.replay_by_storage_key.get(storage_key)
    }

    /// Reads an active quota reservation for tests and local smoke checks.
    pub fn quota_reservation(
        &self,
        storage_key: &str,
    ) -> Option<&CloudflareRouterQuotaReservationV1> {
        self.quota_reservations.get(storage_key)
    }
}

impl CloudflareDurableObjectStorageV1 for CloudflareDurableObjectMemoryStorageV1 {
    fn root_share_startup_metadata(
        &self,
        storage_key: &str,
    ) -> RouterAbProtocolResult<Option<CloudflareRootShareStartupMetadataV1>> {
        require_non_empty("storage_key", storage_key)?;
        Ok(self.root_share_metadata.get(storage_key).cloned())
    }

    fn replay_reservation_by_request_id(
        &self,
        request_index_key: &str,
    ) -> RouterAbProtocolResult<Option<CloudflareReplayReserveRequestV1>> {
        require_non_empty("request_index_key", request_index_key)?;
        Ok(self.replay_by_request_id.get(request_index_key).cloned())
    }

    fn put_replay_reservation(
        &mut self,
        request_index_key: &str,
        storage_key: &str,
        request: CloudflareReplayReserveRequestV1,
    ) -> RouterAbProtocolResult<()> {
        require_non_empty("request_index_key", request_index_key)?;
        require_non_empty("storage_key", storage_key)?;
        request.validate()?;
        self.replay_by_request_id
            .insert(request_index_key.to_owned(), request.clone());
        self.replay_by_storage_key
            .insert(storage_key.to_owned(), request);
        Ok(())
    }

    fn cleanup_expired_replay_reservations(
        &mut self,
        now_unix_ms: u64,
    ) -> RouterAbProtocolResult<CloudflareExpiredStateCleanupReportV1> {
        require_positive_ms("cleanup now_unix_ms", now_unix_ms)?;
        let storage_before = self.replay_by_storage_key.len();
        self.replay_by_storage_key
            .retain(|_, request| request.expires_at_ms > now_unix_ms);
        let index_before = self.replay_by_request_id.len();
        self.replay_by_request_id
            .retain(|_, request| request.expires_at_ms > now_unix_ms);
        CloudflareExpiredStateCleanupReportV1::new(
            now_unix_ms,
            (storage_before - self.replay_by_storage_key.len()) as u64,
            (index_before - self.replay_by_request_id.len()) as u64,
        )
    }

    fn put_router_lifecycle_state(
        &mut self,
        storage_key: &str,
        state: RouterAbLifecycleStateV1,
    ) -> RouterAbProtocolResult<()> {
        require_non_empty("storage_key", storage_key)?;
        validate_lifecycle_state(&state)?;
        self.lifecycle_states.insert(storage_key.to_owned(), state);
        Ok(())
    }

    fn router_lifecycle_state(
        &self,
        storage_key: &str,
    ) -> RouterAbProtocolResult<Option<RouterAbLifecycleStateV1>> {
        require_non_empty("storage_key", storage_key)?;
        Ok(self.lifecycle_states.get(storage_key).cloned())
    }

    fn put_derivation_ceremony(
        &mut self,
        storage_key: &str,
        ceremony: CloudflareDerivationCeremonyV1,
    ) -> RouterAbProtocolResult<()> {
        require_non_empty("storage_key", storage_key)?;
        ceremony.validate()?;
        self.derivation_ceremonies
            .insert(storage_key.to_owned(), ceremony);
        Ok(())
    }

    fn derivation_ceremony(
        &self,
        storage_key: &str,
    ) -> RouterAbProtocolResult<Option<CloudflareDerivationCeremonyV1>> {
        require_non_empty("storage_key", storage_key)?;
        Ok(self.derivation_ceremonies.get(storage_key).cloned())
    }

    fn router_project_policy(
        &self,
        storage_key: &str,
    ) -> RouterAbProtocolResult<Option<CloudflareRouterProjectPolicyRecordV1>> {
        require_non_empty("storage_key", storage_key)?;
        Ok(self.project_policies.get(storage_key).cloned())
    }

    fn router_abuse(
        &self,
        storage_key: &str,
    ) -> RouterAbProtocolResult<Option<CloudflareRouterAbuseRecordV1>> {
        require_non_empty("storage_key", storage_key)?;
        Ok(self.abuse_records.get(storage_key).cloned())
    }

    fn router_quota(
        &self,
        storage_key: &str,
    ) -> RouterAbProtocolResult<Option<CloudflareRouterQuotaReservationV1>> {
        require_non_empty("storage_key", storage_key)?;
        Ok(self.quota_reservations.get(storage_key).cloned())
    }

    fn put_router_quota(
        &mut self,
        storage_key: &str,
        reservation: CloudflareRouterQuotaReservationV1,
    ) -> RouterAbProtocolResult<()> {
        require_non_empty("storage_key", storage_key)?;
        reservation.validate()?;
        self.quota_reservations
            .insert(storage_key.to_owned(), reservation);
        Ok(())
    }

    fn cleanup_expired_router_quota_reservations(
        &mut self,
        now_unix_ms: u64,
    ) -> RouterAbProtocolResult<CloudflareExpiredStateCleanupReportV1> {
        require_positive_ms("cleanup now_unix_ms", now_unix_ms)?;
        let before = self.quota_reservations.len();
        self.quota_reservations
            .retain(|_, reservation| reservation.is_active_at(now_unix_ms));
        CloudflareExpiredStateCleanupReportV1::new(
            now_unix_ms,
            (before - self.quota_reservations.len()) as u64,
            0,
        )
    }

    fn signing_worker_output_activation(
        &self,
        storage_key: &str,
    ) -> RouterAbProtocolResult<Option<CloudflareSigningWorkerOutputActivationRecordV1>> {
        require_non_empty("storage_key", storage_key)?;
        Ok(self.signing_worker_activations.get(storage_key).cloned())
    }

    fn put_signing_worker_output_activation(
        &mut self,
        storage_key: &str,
        active_state_index_key: &str,
        record: CloudflareSigningWorkerOutputActivationRecordV1,
    ) -> RouterAbProtocolResult<()> {
        require_non_empty("storage_key", storage_key)?;
        require_non_empty("active_state_index_key", active_state_index_key)?;
        record.validate()?;
        self.active_signing_worker_states.insert(
            active_state_index_key.to_owned(),
            record.active_signing_worker_state.clone(),
        );
        self.signing_worker_activations
            .insert(storage_key.to_owned(), record);
        Ok(())
    }

    fn active_signing_worker_state(
        &self,
        active_state_index_key: &str,
    ) -> RouterAbProtocolResult<Option<ActiveSigningWorkerStateV1>> {
        require_non_empty("active_state_index_key", active_state_index_key)?;
        Ok(self
            .active_signing_worker_states
            .get(active_state_index_key)
            .cloned())
    }

    fn signing_worker_round1(
        &self,
        storage_key: &str,
    ) -> RouterAbProtocolResult<Option<CloudflareSigningWorkerRound1RecordV1>> {
        require_non_empty("storage_key", storage_key)?;
        Ok(self.signing_worker_round1_records.get(storage_key).cloned())
    }

    fn put_signing_worker_round1(
        &mut self,
        storage_key: &str,
        record: CloudflareSigningWorkerRound1RecordV1,
    ) -> RouterAbProtocolResult<()> {
        require_non_empty("storage_key", storage_key)?;
        record.validate()?;
        self.signing_worker_round1_records
            .insert(storage_key.to_owned(), record);
        Ok(())
    }

    fn take_signing_worker_round1(
        &mut self,
        storage_key: &str,
    ) -> RouterAbProtocolResult<Option<CloudflareSigningWorkerRound1RecordV1>> {
        require_non_empty("storage_key", storage_key)?;
        Ok(self.signing_worker_round1_records.remove(storage_key))
    }

    fn cleanup_expired_signing_worker_round1_records(
        &mut self,
        now_unix_ms: u64,
    ) -> RouterAbProtocolResult<CloudflareExpiredStateCleanupReportV1> {
        require_positive_ms("cleanup now_unix_ms", now_unix_ms)?;
        let before = self.signing_worker_round1_records.len();
        self.signing_worker_round1_records
            .retain(|_, record| record.expires_at_ms > now_unix_ms);
        CloudflareExpiredStateCleanupReportV1::new(
            now_unix_ms,
            (before - self.signing_worker_round1_records.len()) as u64,
            0,
        )
    }
}

fn validate_signing_worker_output_active_state_replacement_v1(
    existing: Option<&ActiveSigningWorkerStateV1>,
    replacement: &ActiveSigningWorkerStateV1,
) -> RouterAbProtocolResult<()> {
    replacement.validate()?;
    let Some(existing) = existing else {
        return Ok(());
    };
    existing.validate()?;
    if existing.account_id != replacement.account_id
        || existing.session_id != replacement.session_id
        || existing.signing_worker.server_id != replacement.signing_worker.server_id
    {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "SigningWorker-output activation cannot replace a different active SigningWorker scope",
        ));
    }
    if replacement.activated_at_ms <= existing.activated_at_ms {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "SigningWorker-output activation must be newer than current active state",
        ));
    }
    Ok(())
}

/// Handles a validated Durable Object operation against typed storage.
pub fn handle_cloudflare_durable_object_call_v1(
    call: &CloudflareDurableObjectCallV1,
    storage: &mut impl CloudflareDurableObjectStorageV1,
) -> RouterAbProtocolResult<CloudflareDurableObjectResponseV1> {
    call.validate()?;
    let storage_key = call.storage_key();
    let response = match &call.request {
        CloudflareDurableObjectRequestV1::RootShareHas { lookup } => {
            let present = match storage.root_share_startup_metadata(&storage_key)? {
                Some(metadata) => {
                    metadata.validate_matches_lookup(lookup)?;
                    true
                }
                None => false,
            };
            CloudflareDurableObjectResponseV1::root_share_has(present)
        }
        CloudflareDurableObjectRequestV1::RootShareStartupMetadata { lookup } => {
            let metadata = storage
                .root_share_startup_metadata(&storage_key)?
                .ok_or_else(|| {
                    RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::MissingLocalBinding,
                        "root-share startup metadata is missing",
                    )
                })?;
            metadata.validate_matches_lookup(lookup)?;
            CloudflareDurableObjectResponseV1::root_share_startup_metadata(metadata)?
        }
        CloudflareDurableObjectRequestV1::RouterReplayReserve { request } => {
            let request_index_key = call.replay_request_index_storage_key()?;
            let reserved = match storage.replay_reservation_by_request_id(&request_index_key)? {
                Some(existing) => {
                    if existing == *request {
                        false
                    } else {
                        return Err(RouterAbProtocolError::new(
                            RouterAbProtocolErrorCode::ReplayedLocalRequest,
                            "router replay request id is already reserved for different material",
                        ));
                    }
                }
                None => {
                    storage.put_replay_reservation(
                        &request_index_key,
                        &storage_key,
                        request.clone(),
                    )?;
                    true
                }
            };
            CloudflareDurableObjectResponseV1::router_replay_reserve(
                CloudflareReplayReserveResponseV1::new(request.request_id.clone(), reserved)?,
            )?
        }
        CloudflareDurableObjectRequestV1::RouterReplayCleanupExpired { cleanup } => {
            cleanup.validate()?;
            CloudflareDurableObjectResponseV1::router_replay_cleanup_expired(
                storage.cleanup_expired_replay_reservations(cleanup.now_unix_ms)?,
            )?
        }
        CloudflareDurableObjectRequestV1::RouterLifecyclePutPublicState { state } => {
            let previous = storage.router_lifecycle_state(&storage_key)?;
            RouterAbLifecycleStateV1::validate_transition_from(previous.as_ref(), state)?;
            storage.put_router_lifecycle_state(&storage_key, state.clone())?;
            CloudflareDurableObjectResponseV1::router_lifecycle_put_public_state(
                CloudflareLifecyclePutReceiptV1::new(state.scope().lifecycle_id.clone(), true)?,
            )?
        }
        CloudflareDurableObjectRequestV1::DerivationCeremonyPutState { ceremony } => {
            let previous = storage.derivation_ceremony(&storage_key)?;
            CloudflareDerivationCeremonyV1::validate_transition_from(previous.as_ref(), ceremony)?;
            let stored = previous.as_ref() != Some(ceremony);
            if stored {
                storage.put_derivation_ceremony(&storage_key, ceremony.clone())?;
            }
            CloudflareDurableObjectResponseV1::derivation_ceremony_put_state(
                CloudflareDerivationCeremonyPutReceiptV1::new(
                    ceremony.scope().lifecycle_id.clone(),
                    ceremony.label(),
                    stored,
                )?,
            )?
        }
        CloudflareDurableObjectRequestV1::RouterProjectPolicyEvaluate { request } => {
            let policy = storage
                .router_project_policy(&storage_key)?
                .ok_or_else(|| {
                    RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::MissingLocalBinding,
                        "router project-policy record is missing",
                    )
                })?
                .evaluate(request)?;
            CloudflareDurableObjectResponseV1::router_project_policy_evaluate(policy)?
        }
        CloudflareDurableObjectRequestV1::RouterQuotaEvaluate { request } => {
            let quota = match storage.router_quota(&storage_key)? {
                Some(existing) if existing.is_active_at(request.now_unix_ms) => {
                    existing.validate()?;
                    CloudflareRouterQuotaCheckV1::ReuseExisting {
                        request_id: request.request_nonce.clone(),
                        existing_lifecycle_id: existing.lifecycle_id,
                    }
                }
                _ => {
                    let reservation = CloudflareRouterQuotaReservationV1::new(
                        request.request_nonce.clone(),
                        request.lifecycle_id.clone(),
                        request.expires_at_ms,
                    )?;
                    storage.put_router_quota(&storage_key, reservation)?;
                    CloudflareRouterQuotaCheckV1::Accepted {
                        request_id: request.request_nonce.clone(),
                    }
                }
            };
            CloudflareDurableObjectResponseV1::router_quota_evaluate(quota)?
        }
        CloudflareDurableObjectRequestV1::RouterQuotaCleanupExpired { cleanup } => {
            cleanup.validate()?;
            CloudflareDurableObjectResponseV1::router_quota_cleanup_expired(
                storage.cleanup_expired_router_quota_reservations(cleanup.now_unix_ms)?,
            )?
        }
        CloudflareDurableObjectRequestV1::RouterAbuseEvaluate { request } => {
            request.validate()?;
            let abuse = match storage.router_abuse(&storage_key)? {
                Some(record) => {
                    record.validate()?;
                    record.outcome
                }
                None => CloudflareRouterAbuseCheckV1::Allowed,
            };
            CloudflareDurableObjectResponseV1::router_abuse_evaluate(abuse)?
        }
        CloudflareDurableObjectRequestV1::RouterNormalSigningProjectPolicyEvaluate { request } => {
            let policy = storage
                .router_project_policy(&storage_key)?
                .ok_or_else(|| {
                    RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::MissingLocalBinding,
                        "router project-policy record is missing",
                    )
                })?
                .evaluate_normal_signing(request)?;
            CloudflareDurableObjectResponseV1::router_normal_signing_project_policy_evaluate(
                policy,
            )?
        }
        CloudflareDurableObjectRequestV1::RouterNormalSigningQuotaEvaluate { request } => {
            let quota = match storage.router_quota(&storage_key)? {
                Some(existing)
                    if existing.is_active_at(request.now_unix_ms)
                        && existing.request_id == request.request_id =>
                {
                    existing.validate()?;
                    CloudflareRouterQuotaCheckV1::Accepted {
                        request_id: request.request_id.clone(),
                    }
                }
                Some(existing) if existing.is_active_at(request.now_unix_ms) => {
                    existing.validate()?;
                    CloudflareRouterQuotaCheckV1::ShortWindowSaturated
                }
                _ => {
                    let reservation = CloudflareRouterQuotaReservationV1::new(
                        request.request_id.clone(),
                        request.request_id.clone(),
                        request.expires_at_ms,
                    )?;
                    storage.put_router_quota(&storage_key, reservation)?;
                    CloudflareRouterQuotaCheckV1::Accepted {
                        request_id: request.request_id.clone(),
                    }
                }
            };
            CloudflareDurableObjectResponseV1::router_normal_signing_quota_evaluate(quota)?
        }
        CloudflareDurableObjectRequestV1::RouterNormalSigningAbuseEvaluate { request } => {
            request.validate()?;
            let abuse = match storage.router_abuse(&storage_key)? {
                Some(record) => {
                    record.validate()?;
                    record.outcome
                }
                None => CloudflareRouterAbuseCheckV1::Allowed,
            };
            CloudflareDurableObjectResponseV1::router_normal_signing_abuse_evaluate(abuse)?
        }
        CloudflareDurableObjectRequestV1::SigningWorkerOutputActivate {
            activation,
            material,
            activated_at_ms,
        } => {
            let active_state_index_key = call.active_signing_worker_state_index_storage_key()?;
            let (active_signing_worker_state, activated) = match storage
                .signing_worker_output_activation(&storage_key)?
            {
                Some(existing) => {
                    existing.validate()?;
                    if existing.activation == *activation && existing.material == *material {
                        (existing.active_signing_worker_state, false)
                    } else {
                        return Err(RouterAbProtocolError::new(
                                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                                "server-output activation conflicts with existing activation or material",
                            ));
                    }
                }
                None => {
                    let active_signing_worker_state =
                        cloudflare_active_signing_worker_state_from_activation_request_v1(
                            activation,
                            storage_key.clone(),
                            *activated_at_ms,
                        )?;
                    let existing_active_state =
                        storage.active_signing_worker_state(&active_state_index_key)?;
                    validate_signing_worker_output_active_state_replacement_v1(
                        existing_active_state.as_ref(),
                        &active_signing_worker_state,
                    )?;
                    let record = CloudflareSigningWorkerOutputActivationRecordV1::new(
                        activation.clone(),
                        active_signing_worker_state.clone(),
                        material.clone(),
                    )?;
                    storage.put_signing_worker_output_activation(
                        &storage_key,
                        &active_state_index_key,
                        record,
                    )?;
                    (active_signing_worker_state, true)
                }
            };
            let activation_context = &activation.activation_context;
            let selected_server = &activation_context.signer_set().selected_server;
            CloudflareDurableObjectResponseV1::signing_worker_output_activate(
                CloudflareSigningWorkerOutputActivationReceiptV1::new(
                    activation_context.lifecycle().lifecycle_id.clone(),
                    selected_server.server_id.clone(),
                    activation_context.transcript_digest(),
                    active_signing_worker_state,
                    activated,
                )?,
            )?
        }
        CloudflareDurableObjectRequestV1::SigningWorkerOutputActiveStateGet { lookup } => {
            lookup.validate()?;
            let active_signing_worker_state = storage
                .active_signing_worker_state(&storage_key)?
                .ok_or_else(|| {
                    RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::MissingLocalBinding,
                        "active SigningWorker state is missing",
                    )
                })?;
            lookup.validate_active_state(&active_signing_worker_state)?;
            CloudflareDurableObjectResponseV1::signing_worker_output_active_state_get(
                active_signing_worker_state,
            )?
        }
        CloudflareDurableObjectRequestV1::SigningWorkerOutputMaterialGet { lookup } => {
            lookup.validate()?;
            let record = storage
                .signing_worker_output_activation(&storage_key)?
                .ok_or_else(|| {
                    RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::MissingLocalBinding,
                        "SigningWorker-output material is missing",
                    )
                })?;
            record.validate()?;
            if record.active_signing_worker_state != lookup.active_signing_worker_state {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                    "SigningWorker-output material active state does not match lookup",
                ));
            }
            lookup.validate_material(&record.material)?;
            CloudflareDurableObjectResponseV1::signing_worker_output_material_get(record.material)?
        }
        CloudflareDurableObjectRequestV1::SigningWorkerRound1Put { record } => {
            record.validate()?;
            let stored = match storage.signing_worker_round1(&storage_key)? {
                Some(existing) => {
                    existing.validate()?;
                    if existing == *record {
                        false
                    } else {
                        return Err(RouterAbProtocolError::new(
                            RouterAbProtocolErrorCode::ReplayedLocalRequest,
                            "SigningWorker round-1 handle is already stored for different material",
                        ));
                    }
                }
                None => {
                    storage.put_signing_worker_round1(&storage_key, record.clone())?;
                    true
                }
            };
            CloudflareDurableObjectResponseV1::signing_worker_round1_put(
                CloudflareSigningWorkerRound1PutReceiptV1::from_record(record, stored)?,
            )?
        }
        CloudflareDurableObjectRequestV1::SigningWorkerRound1Take { lookup } => {
            lookup.validate()?;
            let record = storage
                .signing_worker_round1(&storage_key)?
                .ok_or_else(|| {
                    RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::MissingLocalBinding,
                        "SigningWorker round-1 nonce material is missing",
                    )
                })?;
            record.validate_for_lookup(lookup)?;
            storage.take_signing_worker_round1(&storage_key)?;
            CloudflareDurableObjectResponseV1::signing_worker_round1_take(record)?
        }
        CloudflareDurableObjectRequestV1::SigningWorkerRound1CleanupExpired { cleanup } => {
            cleanup.validate()?;
            CloudflareDurableObjectResponseV1::signing_worker_round1_cleanup_expired(
                storage.cleanup_expired_signing_worker_round1_records(cleanup.now_unix_ms)?,
            )?
        }
    };
    response.validate_for_request(&call.request)?;
    Ok(response)
}

/// Handles a real `workers-rs` Durable Object fetch event for Router/A/B storage.
#[cfg(feature = "workers-rs")]
pub async fn handle_cloudflare_durable_object_fetch_v1(
    binding: &CloudflareDurableObjectBindingV1,
    mut request: worker::Request,
    storage: &worker::Storage,
) -> worker::Result<worker::Response> {
    if request.method() != worker::Method::Post {
        return worker::Response::error("Router A/B Durable Object requires POST", 405);
    }
    let parsed = match request.json::<CloudflareDurableObjectRequestV1>().await {
        Ok(parsed) => parsed,
        Err(err) => {
            return worker::Response::error(
                format!("Router A/B Durable Object request JSON parse failed: {err}"),
                400,
            );
        }
    };
    if request.path() != parsed.operation_kind().path() {
        return worker::Response::error(
            format!(
                "{} must be served at {}",
                parsed.operation_kind().as_str(),
                parsed.operation_kind().path()
            ),
            404,
        );
    }
    match handle_cloudflare_durable_object_worker_request_v1(binding, parsed, storage).await {
        Ok(response) => worker::Response::from_json(&response),
        Err(err) => worker::Response::error(
            format!("{:?}: {}", err.code(), err.message()),
            durable_object_error_status(err.code()),
        ),
    }
}

#[cfg(feature = "workers-rs")]
async fn handle_cloudflare_durable_object_class_fetch_v1(
    scope: CloudflareDurableObjectScopeV1,
    binding_env_key: &str,
    object_env_key: &str,
    key_prefix_env_key: &str,
    env: &worker::Env,
    state: &worker::State,
    request: worker::Request,
) -> worker::Result<worker::Response> {
    let binding = match cloudflare_durable_object_class_binding_v1(
        scope,
        binding_env_key,
        object_env_key,
        key_prefix_env_key,
        env,
    ) {
        Ok(binding) => binding,
        Err(err) => {
            return worker::Response::error(
                format!("{:?}: {}", err.code(), err.message()),
                durable_object_error_status(err.code()),
            );
        }
    };
    let storage = state.storage();
    handle_cloudflare_durable_object_fetch_v1(&binding, request, &storage).await
}

#[cfg(feature = "workers-rs")]
fn cloudflare_durable_object_class_binding_v1(
    scope: CloudflareDurableObjectScopeV1,
    binding_env_key: &str,
    object_env_key: &str,
    key_prefix_env_key: &str,
    env: &worker::Env,
) -> RouterAbProtocolResult<CloudflareDurableObjectBindingV1> {
    CloudflareDurableObjectBindingV1::new(
        scope,
        read_cloudflare_durable_object_class_env_text_v1(env, binding_env_key)?,
        read_cloudflare_durable_object_class_env_text_v1(env, object_env_key)?,
        read_cloudflare_durable_object_class_env_text_v1(env, key_prefix_env_key)?,
    )
}

#[cfg(feature = "workers-rs")]
fn read_cloudflare_durable_object_class_env_text_v1(
    env: &worker::Env,
    key: &str,
) -> RouterAbProtocolResult<String> {
    let value = env.var(key).map_err(|err| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MissingLocalBinding,
            format!("Durable Object class is missing Env key {key}: {err}"),
        )
    })?;
    let value = value.to_string().trim().to_owned();
    require_non_empty(key, &value)?;
    Ok(value)
}

/// Handles a parsed Durable Object request against real Cloudflare storage.
#[cfg(feature = "workers-rs")]
pub async fn handle_cloudflare_durable_object_worker_request_v1(
    binding: &CloudflareDurableObjectBindingV1,
    request: CloudflareDurableObjectRequestV1,
    storage: &worker::Storage,
) -> RouterAbProtocolResult<CloudflareDurableObjectResponseV1> {
    let worker_role = worker_role_for_durable_object_scope(binding.scope)?;
    let call = CloudflareDurableObjectCallV1::new(worker_role, binding.clone(), request)?;
    let storage_key = call.storage_key();
    let response = match &call.request {
        CloudflareDurableObjectRequestV1::RootShareHas { lookup } => {
            let present = match worker_storage_get::<CloudflareRootShareStartupMetadataV1>(
                storage,
                &storage_key,
                call.operation_kind(),
            )
            .await?
            {
                Some(metadata) => {
                    metadata.validate_matches_lookup(lookup)?;
                    true
                }
                None => false,
            };
            CloudflareDurableObjectResponseV1::root_share_has(present)
        }
        CloudflareDurableObjectRequestV1::RootShareStartupMetadata { lookup } => {
            let metadata = worker_storage_get::<CloudflareRootShareStartupMetadataV1>(
                storage,
                &storage_key,
                call.operation_kind(),
            )
            .await?
            .ok_or_else(|| {
                RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::MissingLocalBinding,
                    "root-share startup metadata is missing",
                )
            })?;
            metadata.validate_matches_lookup(lookup)?;
            CloudflareDurableObjectResponseV1::root_share_startup_metadata(metadata)?
        }
        CloudflareDurableObjectRequestV1::RouterReplayReserve { request } => {
            let request_index_key = call.replay_request_index_storage_key()?;
            let reserved = match worker_storage_get::<CloudflareReplayReserveRequestV1>(
                storage,
                &request_index_key,
                call.operation_kind(),
            )
            .await?
            {
                Some(existing) => {
                    if existing == *request {
                        false
                    } else {
                        return Err(RouterAbProtocolError::new(
                            RouterAbProtocolErrorCode::ReplayedLocalRequest,
                            "router replay request id is already reserved for different material",
                        ));
                    }
                }
                None => {
                    worker_storage_put(
                        storage,
                        &request_index_key,
                        request.clone(),
                        call.operation_kind(),
                    )
                    .await?;
                    worker_storage_put(
                        storage,
                        &storage_key,
                        request.clone(),
                        call.operation_kind(),
                    )
                    .await?;
                    true
                }
            };
            CloudflareDurableObjectResponseV1::router_replay_reserve(
                CloudflareReplayReserveResponseV1::new(request.request_id.clone(), reserved)?,
            )?
        }
        CloudflareDurableObjectRequestV1::RouterReplayCleanupExpired { cleanup } => {
            cleanup.validate()?;
            let records_removed = worker_storage_cleanup_expired_values(
                storage,
                &call.replay_storage_prefix(),
                cleanup.now_unix_ms,
                call.operation_kind(),
                cloudflare_replay_reservation_expires_at_ms_v1,
            )
            .await?;
            let index_records_removed = worker_storage_cleanup_expired_values(
                storage,
                &call.replay_request_index_storage_prefix(),
                cleanup.now_unix_ms,
                call.operation_kind(),
                cloudflare_replay_reservation_expires_at_ms_v1,
            )
            .await?;
            CloudflareDurableObjectResponseV1::router_replay_cleanup_expired(
                CloudflareExpiredStateCleanupReportV1::new(
                    cleanup.now_unix_ms,
                    records_removed,
                    index_records_removed,
                )?,
            )?
        }
        CloudflareDurableObjectRequestV1::RouterLifecyclePutPublicState { state } => {
            let previous = worker_storage_get::<RouterAbLifecycleStateV1>(
                storage,
                &storage_key,
                call.operation_kind(),
            )
            .await?;
            RouterAbLifecycleStateV1::validate_transition_from(previous.as_ref(), state)?;
            worker_storage_put(storage, &storage_key, state.clone(), call.operation_kind()).await?;
            CloudflareDurableObjectResponseV1::router_lifecycle_put_public_state(
                CloudflareLifecyclePutReceiptV1::new(state.scope().lifecycle_id.clone(), true)?,
            )?
        }
        CloudflareDurableObjectRequestV1::DerivationCeremonyPutState { ceremony } => {
            let previous = worker_storage_get::<CloudflareDerivationCeremonyV1>(
                storage,
                &storage_key,
                call.operation_kind(),
            )
            .await?;
            CloudflareDerivationCeremonyV1::validate_transition_from(previous.as_ref(), ceremony)?;
            let stored = previous.as_ref() != Some(ceremony);
            if stored {
                worker_storage_put(
                    storage,
                    &storage_key,
                    ceremony.clone(),
                    call.operation_kind(),
                )
                .await?;
            }
            CloudflareDurableObjectResponseV1::derivation_ceremony_put_state(
                CloudflareDerivationCeremonyPutReceiptV1::new(
                    ceremony.scope().lifecycle_id.clone(),
                    ceremony.label(),
                    stored,
                )?,
            )?
        }
        CloudflareDurableObjectRequestV1::RouterProjectPolicyEvaluate { request } => {
            let policy = worker_storage_get::<CloudflareRouterProjectPolicyRecordV1>(
                storage,
                &storage_key,
                call.operation_kind(),
            )
            .await?
            .ok_or_else(|| {
                RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::MissingLocalBinding,
                    "router project-policy record is missing",
                )
            })?
            .evaluate(request)?;
            CloudflareDurableObjectResponseV1::router_project_policy_evaluate(policy)?
        }
        CloudflareDurableObjectRequestV1::RouterQuotaEvaluate { request } => {
            let quota = match worker_storage_get::<CloudflareRouterQuotaReservationV1>(
                storage,
                &storage_key,
                call.operation_kind(),
            )
            .await?
            {
                Some(existing) if existing.is_active_at(request.now_unix_ms) => {
                    existing.validate()?;
                    CloudflareRouterQuotaCheckV1::ReuseExisting {
                        request_id: request.request_nonce.clone(),
                        existing_lifecycle_id: existing.lifecycle_id,
                    }
                }
                _ => {
                    let reservation = CloudflareRouterQuotaReservationV1::new(
                        request.request_nonce.clone(),
                        request.lifecycle_id.clone(),
                        request.expires_at_ms,
                    )?;
                    worker_storage_put(storage, &storage_key, reservation, call.operation_kind())
                        .await?;
                    CloudflareRouterQuotaCheckV1::Accepted {
                        request_id: request.request_nonce.clone(),
                    }
                }
            };
            CloudflareDurableObjectResponseV1::router_quota_evaluate(quota)?
        }
        CloudflareDurableObjectRequestV1::RouterQuotaCleanupExpired { cleanup } => {
            cleanup.validate()?;
            let records_removed = worker_storage_cleanup_expired_values(
                storage,
                &call.quota_storage_prefix(),
                cleanup.now_unix_ms,
                call.operation_kind(),
                cloudflare_quota_reservation_expires_at_ms_v1,
            )
            .await?;
            CloudflareDurableObjectResponseV1::router_quota_cleanup_expired(
                CloudflareExpiredStateCleanupReportV1::new(
                    cleanup.now_unix_ms,
                    records_removed,
                    0,
                )?,
            )?
        }
        CloudflareDurableObjectRequestV1::RouterAbuseEvaluate { request } => {
            request.validate()?;
            let abuse = match worker_storage_get::<CloudflareRouterAbuseRecordV1>(
                storage,
                &storage_key,
                call.operation_kind(),
            )
            .await?
            {
                Some(record) => {
                    record.validate()?;
                    record.outcome
                }
                None => CloudflareRouterAbuseCheckV1::Allowed,
            };
            CloudflareDurableObjectResponseV1::router_abuse_evaluate(abuse)?
        }
        CloudflareDurableObjectRequestV1::RouterNormalSigningProjectPolicyEvaluate { request } => {
            let policy = worker_storage_get::<CloudflareRouterProjectPolicyRecordV1>(
                storage,
                &storage_key,
                call.operation_kind(),
            )
            .await?
            .ok_or_else(|| {
                RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::MissingLocalBinding,
                    "router project-policy record is missing",
                )
            })?
            .evaluate_normal_signing(request)?;
            CloudflareDurableObjectResponseV1::router_normal_signing_project_policy_evaluate(
                policy,
            )?
        }
        CloudflareDurableObjectRequestV1::RouterNormalSigningQuotaEvaluate { request } => {
            let quota = match worker_storage_get::<CloudflareRouterQuotaReservationV1>(
                storage,
                &storage_key,
                call.operation_kind(),
            )
            .await?
            {
                Some(existing)
                    if existing.is_active_at(request.now_unix_ms)
                        && existing.request_id == request.request_id =>
                {
                    existing.validate()?;
                    CloudflareRouterQuotaCheckV1::Accepted {
                        request_id: request.request_id.clone(),
                    }
                }
                Some(existing) if existing.is_active_at(request.now_unix_ms) => {
                    existing.validate()?;
                    CloudflareRouterQuotaCheckV1::ShortWindowSaturated
                }
                _ => {
                    let reservation = CloudflareRouterQuotaReservationV1::new(
                        request.request_id.clone(),
                        request.request_id.clone(),
                        request.expires_at_ms,
                    )?;
                    worker_storage_put(storage, &storage_key, reservation, call.operation_kind())
                        .await?;
                    CloudflareRouterQuotaCheckV1::Accepted {
                        request_id: request.request_id.clone(),
                    }
                }
            };
            CloudflareDurableObjectResponseV1::router_normal_signing_quota_evaluate(quota)?
        }
        CloudflareDurableObjectRequestV1::RouterNormalSigningAbuseEvaluate { request } => {
            request.validate()?;
            let abuse = match worker_storage_get::<CloudflareRouterAbuseRecordV1>(
                storage,
                &storage_key,
                call.operation_kind(),
            )
            .await?
            {
                Some(record) => {
                    record.validate()?;
                    record.outcome
                }
                None => CloudflareRouterAbuseCheckV1::Allowed,
            };
            CloudflareDurableObjectResponseV1::router_normal_signing_abuse_evaluate(abuse)?
        }
        CloudflareDurableObjectRequestV1::SigningWorkerOutputActivate {
            activation,
            material,
            activated_at_ms,
        } => {
            let active_state_index_key = call.active_signing_worker_state_index_storage_key()?;
            let (active_signing_worker_state, activated) = match worker_storage_get::<
                CloudflareSigningWorkerOutputActivationRecordV1,
            >(
                storage,
                &storage_key,
                call.operation_kind(),
            )
            .await?
            {
                Some(existing) => {
                    existing.validate()?;
                    if existing.activation == *activation && existing.material == *material {
                        (existing.active_signing_worker_state, false)
                    } else {
                        return Err(RouterAbProtocolError::new(
                                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                                "server-output activation conflicts with existing activation or material",
                            ));
                    }
                }
                None => {
                    let active_signing_worker_state =
                        cloudflare_active_signing_worker_state_from_activation_request_v1(
                            activation,
                            storage_key.clone(),
                            *activated_at_ms,
                        )?;
                    let existing_active_state = worker_storage_get::<ActiveSigningWorkerStateV1>(
                        storage,
                        &active_state_index_key,
                        call.operation_kind(),
                    )
                    .await?;
                    validate_signing_worker_output_active_state_replacement_v1(
                        existing_active_state.as_ref(),
                        &active_signing_worker_state,
                    )?;
                    let record = CloudflareSigningWorkerOutputActivationRecordV1::new(
                        activation.clone(),
                        active_signing_worker_state.clone(),
                        material.clone(),
                    )?;
                    worker_storage_put(storage, &storage_key, record, call.operation_kind())
                        .await?;
                    worker_storage_put(
                        storage,
                        &active_state_index_key,
                        active_signing_worker_state.clone(),
                        call.operation_kind(),
                    )
                    .await?;
                    (active_signing_worker_state, true)
                }
            };
            let activation_context = &activation.activation_context;
            let selected_server = &activation_context.signer_set().selected_server;
            CloudflareDurableObjectResponseV1::signing_worker_output_activate(
                CloudflareSigningWorkerOutputActivationReceiptV1::new(
                    activation_context.lifecycle().lifecycle_id.clone(),
                    selected_server.server_id.clone(),
                    activation_context.transcript_digest(),
                    active_signing_worker_state,
                    activated,
                )?,
            )?
        }
        CloudflareDurableObjectRequestV1::SigningWorkerOutputActiveStateGet { lookup } => {
            lookup.validate()?;
            let active_signing_worker_state = worker_storage_get::<ActiveSigningWorkerStateV1>(
                storage,
                &storage_key,
                call.operation_kind(),
            )
            .await?
            .ok_or_else(|| {
                RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::MissingLocalBinding,
                    "active SigningWorker state is missing",
                )
            })?;
            lookup.validate_active_state(&active_signing_worker_state)?;
            CloudflareDurableObjectResponseV1::signing_worker_output_active_state_get(
                active_signing_worker_state,
            )?
        }
        CloudflareDurableObjectRequestV1::SigningWorkerOutputMaterialGet { lookup } => {
            lookup.validate()?;
            let record = worker_storage_get::<CloudflareSigningWorkerOutputActivationRecordV1>(
                storage,
                &storage_key,
                call.operation_kind(),
            )
            .await?
            .ok_or_else(|| {
                RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::MissingLocalBinding,
                    "SigningWorker-output material is missing",
                )
            })?;
            record.validate()?;
            if record.active_signing_worker_state != lookup.active_signing_worker_state {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                    "SigningWorker-output material active state does not match lookup",
                ));
            }
            lookup.validate_material(&record.material)?;
            CloudflareDurableObjectResponseV1::signing_worker_output_material_get(record.material)?
        }
        CloudflareDurableObjectRequestV1::SigningWorkerRound1Put { record } => {
            record.validate()?;
            let stored = match worker_storage_get::<CloudflareSigningWorkerRound1RecordV1>(
                storage,
                &storage_key,
                call.operation_kind(),
            )
            .await?
            {
                Some(existing) => {
                    existing.validate()?;
                    if existing == *record {
                        false
                    } else {
                        return Err(RouterAbProtocolError::new(
                            RouterAbProtocolErrorCode::ReplayedLocalRequest,
                            "SigningWorker round-1 handle is already stored for different material",
                        ));
                    }
                }
                None => {
                    worker_storage_put(
                        storage,
                        &storage_key,
                        record.clone(),
                        call.operation_kind(),
                    )
                    .await?;
                    true
                }
            };
            CloudflareDurableObjectResponseV1::signing_worker_round1_put(
                CloudflareSigningWorkerRound1PutReceiptV1::from_record(record, stored)?,
            )?
        }
        CloudflareDurableObjectRequestV1::SigningWorkerRound1Take { lookup } => {
            lookup.validate()?;
            let record = worker_storage_get::<CloudflareSigningWorkerRound1RecordV1>(
                storage,
                &storage_key,
                call.operation_kind(),
            )
            .await?
            .ok_or_else(|| {
                RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::MissingLocalBinding,
                    "SigningWorker round-1 nonce material is missing",
                )
            })?;
            record.validate_for_lookup(lookup)?;
            worker_storage_delete(storage, &storage_key, call.operation_kind()).await?;
            CloudflareDurableObjectResponseV1::signing_worker_round1_take(record)?
        }
        CloudflareDurableObjectRequestV1::SigningWorkerRound1CleanupExpired { cleanup } => {
            cleanup.validate()?;
            let records_removed = worker_storage_cleanup_expired_values(
                storage,
                &call.signing_worker_round1_storage_prefix(),
                cleanup.now_unix_ms,
                call.operation_kind(),
                cloudflare_signing_worker_round1_expires_at_ms_v1,
            )
            .await?;
            CloudflareDurableObjectResponseV1::signing_worker_round1_cleanup_expired(
                CloudflareExpiredStateCleanupReportV1::new(
                    cleanup.now_unix_ms,
                    records_removed,
                    0,
                )?,
            )?
        }
    };
    response.validate_for_request(&call.request)?;
    Ok(response)
}

/// Executes a typed Durable Object call through a real `workers-rs` Env.
#[cfg(feature = "workers-rs")]
pub async fn execute_cloudflare_durable_object_call_v1(
    env: &worker::Env,
    call: &CloudflareDurableObjectCallV1,
) -> RouterAbProtocolResult<CloudflareDurableObjectResponseV1> {
    call.validate()?;
    let namespace = env
        .durable_object(&call.binding.binding_name)
        .map_err(|err| {
            worker_do_error(
                RouterAbProtocolErrorCode::MissingLocalBinding,
                call,
                format!("Durable Object namespace lookup failed: {err}"),
            )
        })?;
    let stub = namespace
        .get_by_name(&call.binding.object_name)
        .map_err(|err| {
            worker_do_error(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                call,
                format!("Durable Object stub lookup failed: {err}"),
            )
        })?;
    let request_body = serde_json::to_string(&call.request).map_err(|err| {
        worker_do_error(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            call,
            format!("Durable Object request serialization failed: {err}"),
        )
    })?;
    let mut init = worker::RequestInit::new();
    init.with_method(worker::Method::Post)
        .with_body(Some(worker::wasm_bindgen::JsValue::from_str(&request_body)));
    let request =
        worker::Request::new_with_init(&call.durable_object_url(), &init).map_err(|err| {
            worker_do_error(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                call,
                format!("Durable Object request construction failed: {err}"),
            )
        })?;
    let mut response = stub.fetch_with_request(request).await.map_err(|err| {
        worker_do_error(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            call,
            format!("Durable Object request failed: {err}"),
        )
    })?;
    let status = response.status_code();
    if !(200..=299).contains(&status) {
        return Err(worker_do_error(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            call,
            format!("Durable Object returned HTTP status {status}"),
        ));
    }
    let parsed = response
        .json::<CloudflareDurableObjectResponseV1>()
        .await
        .map_err(|err| {
            worker_do_error(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                call,
                format!("Durable Object response parsing failed: {err}"),
            )
        })?;
    parsed.validate_for_request(&call.request)?;
    Ok(parsed)
}

fn validate_lifecycle_state(state: &RouterAbLifecycleStateV1) -> RouterAbProtocolResult<()> {
    state.validate()
}

#[cfg(feature = "workers-rs")]
fn worker_role_for_durable_object_scope(
    scope: CloudflareDurableObjectScopeV1,
) -> RouterAbProtocolResult<CloudflareWorkerRoleV1> {
    scope.validate()?;
    match scope {
        CloudflareDurableObjectScopeV1::RouterReplay
        | CloudflareDurableObjectScopeV1::RouterLifecycle
        | CloudflareDurableObjectScopeV1::RouterProjectPolicy
        | CloudflareDurableObjectScopeV1::RouterQuota
        | CloudflareDurableObjectScopeV1::RouterAbuse => Ok(CloudflareWorkerRoleV1::Router),
        CloudflareDurableObjectScopeV1::SignerRootShare {
            role: Role::SignerA,
        } => Ok(CloudflareWorkerRoleV1::SignerA),
        CloudflareDurableObjectScopeV1::SignerRootShare {
            role: Role::SignerB,
        } => Ok(CloudflareWorkerRoleV1::SignerB),
        CloudflareDurableObjectScopeV1::ServerOutput {
            owner_role: CloudflareWorkerRoleV1::SigningWorker,
        } => Ok(CloudflareWorkerRoleV1::SigningWorker),
        CloudflareDurableObjectScopeV1::SignerRootShare { role } => {
            Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidRole,
                format!(
                    "no Router A/B Worker role can own Durable Object scope for {}",
                    role.as_str()
                ),
            ))
        }
        CloudflareDurableObjectScopeV1::ServerOutput { owner_role } => {
            Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidRole,
                format!(
                    "no Router A/B Worker role can own server-output Durable Object scope for {}",
                    owner_role.as_str()
                ),
            ))
        }
    }
}

#[cfg(feature = "workers-rs")]
async fn worker_storage_get<T>(
    storage: &worker::Storage,
    storage_key: &str,
    operation_kind: CloudflareDurableObjectOperationKindV1,
) -> RouterAbProtocolResult<Option<T>>
where
    T: DeserializeOwned,
{
    require_non_empty("storage_key", storage_key)?;
    storage.get::<T>(storage_key).await.map_err(|err| {
        worker_storage_error(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            operation_kind,
            storage_key,
            format!("Durable Object storage read failed: {err}"),
        )
    })
}

#[cfg(feature = "workers-rs")]
async fn worker_storage_put<T>(
    storage: &worker::Storage,
    storage_key: &str,
    value: T,
    operation_kind: CloudflareDurableObjectOperationKindV1,
) -> RouterAbProtocolResult<()>
where
    T: Serialize,
{
    require_non_empty("storage_key", storage_key)?;
    storage.put(storage_key, value).await.map_err(|err| {
        worker_storage_error(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            operation_kind,
            storage_key,
            format!("Durable Object storage write failed: {err}"),
        )
    })
}

#[cfg(feature = "workers-rs")]
async fn worker_storage_cleanup_expired_values<T>(
    storage: &worker::Storage,
    storage_prefix: &str,
    now_unix_ms: u64,
    operation_kind: CloudflareDurableObjectOperationKindV1,
    expires_at_ms: fn(&T) -> u64,
) -> RouterAbProtocolResult<u64>
where
    T: DeserializeOwned,
{
    require_non_empty("storage_prefix", storage_prefix)?;
    require_positive_ms("cleanup now_unix_ms", now_unix_ms)?;
    let values = storage
        .list_with_options(worker::ListOptions::new().prefix(storage_prefix))
        .await
        .map_err(|err| {
            worker_storage_error(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                operation_kind,
                storage_prefix,
                format!("Durable Object storage list failed: {err}"),
            )
        })?;
    let keys = worker::js_sys::Array::from(&values.keys());
    let mut removed = 0u64;
    for key in keys.iter() {
        let storage_key = key.as_string().ok_or_else(|| {
            worker_storage_error(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                operation_kind,
                storage_prefix,
                "Durable Object storage list returned a non-string key".to_owned(),
            )
        })?;
        let Some(record) = worker_storage_get::<T>(storage, &storage_key, operation_kind).await?
        else {
            continue;
        };
        if expires_at_ms(&record) <= now_unix_ms {
            worker_storage_delete(storage, &storage_key, operation_kind).await?;
            removed += 1;
        }
    }
    Ok(removed)
}

#[cfg(feature = "workers-rs")]
fn cloudflare_replay_reservation_expires_at_ms_v1(
    request: &CloudflareReplayReserveRequestV1,
) -> u64 {
    request.expires_at_ms
}

#[cfg(feature = "workers-rs")]
fn cloudflare_quota_reservation_expires_at_ms_v1(
    reservation: &CloudflareRouterQuotaReservationV1,
) -> u64 {
    reservation.expires_at_ms
}

#[cfg(feature = "workers-rs")]
fn cloudflare_signing_worker_round1_expires_at_ms_v1(
    record: &CloudflareSigningWorkerRound1RecordV1,
) -> u64 {
    record.expires_at_ms
}

#[cfg(feature = "workers-rs")]
async fn worker_storage_delete(
    storage: &worker::Storage,
    storage_key: &str,
    operation_kind: CloudflareDurableObjectOperationKindV1,
) -> RouterAbProtocolResult<()> {
    require_non_empty("storage_key", storage_key)?;
    storage.delete(storage_key).await.map_err(|err| {
        worker_storage_error(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            operation_kind,
            storage_key,
            format!("Durable Object storage delete failed: {err}"),
        )
    })?;
    Ok(())
}

#[cfg(feature = "workers-rs")]
fn worker_storage_error(
    code: RouterAbProtocolErrorCode,
    operation_kind: CloudflareDurableObjectOperationKindV1,
    storage_key: &str,
    message: String,
) -> RouterAbProtocolError {
    RouterAbProtocolError::new(
        code,
        format!(
            "{} storage key `{}` failed: {message}",
            operation_kind.as_str(),
            storage_key
        ),
    )
}

#[cfg(feature = "workers-rs")]
fn durable_object_error_status(code: RouterAbProtocolErrorCode) -> u16 {
    match code {
        RouterAbProtocolErrorCode::ForbiddenLocalBinding
        | RouterAbProtocolErrorCode::InvalidRole => 403,
        RouterAbProtocolErrorCode::MissingLocalBinding => 404,
        RouterAbProtocolErrorCode::ReplayedLocalRequest => 409,
        RouterAbProtocolErrorCode::MalformedWirePayload => 400,
        _ => 422,
    }
}

#[cfg(feature = "workers-rs")]
fn worker_do_error(
    code: RouterAbProtocolErrorCode,
    call: &CloudflareDurableObjectCallV1,
    message: String,
) -> RouterAbProtocolError {
    RouterAbProtocolError::new(
        code,
        format!(
            "{} via {} binding `{}` failed: {message}",
            call.operation_kind().as_str(),
            call.worker_role.as_str(),
            call.binding.binding_name
        ),
    )
}

fn digest_hex(digest: PublicDigest32) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for byte in digest.as_bytes() {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn require_non_empty(field: &str, value: &str) -> RouterAbProtocolResult<()> {
    if value.is_empty() {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::EmptyField,
            format!("{field} must not be empty"),
        ));
    }
    Ok(())
}

fn require_non_empty_vec<T>(field: &str, value: &[T]) -> RouterAbProtocolResult<()> {
    if value.is_empty() {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::EmptyField,
            format!("{field} must not be empty"),
        ));
    }
    Ok(())
}

fn require_positive_ms(field: &str, value: u64) -> RouterAbProtocolResult<()> {
    if value == 0 {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidTimeRange,
            format!("{field} must be greater than zero"),
        ));
    }
    Ok(())
}

fn require_work_kind_set(
    field: &str,
    work_kinds: &[ExpensiveWorkKindV1],
) -> RouterAbProtocolResult<()> {
    if work_kinds.is_empty() {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::EmptyField,
            format!("{field} must not be empty"),
        ));
    }
    for (index, work_kind) in work_kinds.iter().enumerate() {
        for prior in &work_kinds[..index] {
            if prior == work_kind {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                    format!("{field} must not contain duplicate work kinds"),
                ));
            }
        }
    }
    Ok(())
}

fn require_signer_role(role: Role) -> RouterAbProtocolResult<()> {
    match role {
        Role::SignerA | Role::SignerB => Ok(()),
        _ => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidRole,
            format!(
                "Cloudflare root-share Durable Object request requires signer role, received {}",
                role.as_str()
            ),
        )),
    }
}
