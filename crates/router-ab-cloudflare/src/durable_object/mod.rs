use std::collections::BTreeMap;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use router_ab_core::{
    ActiveSigningWorkerStateV1, EcdsaThresholdPrfRequestV1, ExpensiveWorkKindV1, LifecycleScopeV1,
    NormalSigningEd25519TwoPartyFrostCommitmentsV1, NormalSigningScopeV1, PublicDigest32, Role,
    RootShareEpoch, RouterAbEcdsaHssNormalSigningScopeV1,
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
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    cloudflare_active_signing_worker_state_from_activation_request_v1,
    cloudflare_signing_worker_recipient_proof_bundle_activation_digest_v1, require_non_empty,
    require_non_empty_vec, require_positive_ms, CloudflareDurableObjectBindingV1,
    CloudflareDurableObjectScopeV1, CloudflareRouterAbuseCheckV1,
    CloudflareRouterNormalSigningTrustedMetadataV1, CloudflareRouterProjectPolicyV1,
    CloudflareRouterQuotaCheckV1, CloudflareRouterTrustedRequestMetadataV1,
    CloudflareServerOutputMaterialRecordV1,
    CloudflareSigningWorkerDirectRecipientProofBundleActivationDeliveryV1,
    CloudflareSigningWorkerDirectRecipientProofBundleActivationPendingRecordV1,
    CloudflareSigningWorkerDirectRecipientProofBundleActivationPutOutcomeV1,
    CloudflareSigningWorkerRecipientProofBundleActivationRequestV1, CloudflareWorkerRoleV1,
};
#[cfg(feature = "workers-rs")]
use crate::{
    DERIVER_A_ROOT_SHARE_DO_BINDING_ENV, DERIVER_A_ROOT_SHARE_DO_KEY_PREFIX_ENV,
    DERIVER_A_ROOT_SHARE_DO_OBJECT_ENV, DERIVER_B_ROOT_SHARE_DO_BINDING_ENV,
    DERIVER_B_ROOT_SHARE_DO_KEY_PREFIX_ENV, DERIVER_B_ROOT_SHARE_DO_OBJECT_ENV,
    ROUTER_ABUSE_DO_BINDING_ENV, ROUTER_ABUSE_DO_KEY_PREFIX_ENV, ROUTER_ABUSE_DO_OBJECT_ENV,
    ROUTER_LIFECYCLE_DO_BINDING_ENV, ROUTER_LIFECYCLE_DO_KEY_PREFIX_ENV,
    ROUTER_LIFECYCLE_DO_OBJECT_ENV, ROUTER_PROJECT_POLICY_DO_BINDING_ENV,
    ROUTER_PROJECT_POLICY_DO_KEY_PREFIX_ENV, ROUTER_PROJECT_POLICY_DO_OBJECT_ENV,
    ROUTER_QUOTA_DO_BINDING_ENV, ROUTER_QUOTA_DO_KEY_PREFIX_ENV, ROUTER_QUOTA_DO_OBJECT_ENV,
    ROUTER_REPLAY_DO_BINDING_ENV, ROUTER_REPLAY_DO_KEY_PREFIX_ENV, ROUTER_REPLAY_DO_OBJECT_ENV,
    ROUTER_WALLET_BUDGET_DO_BINDING_ENV, ROUTER_WALLET_BUDGET_DO_KEY_PREFIX_ENV,
    ROUTER_WALLET_BUDGET_DO_OBJECT_ENV, SIGNING_WORKER_SERVER_OUTPUT_DO_BINDING_ENV,
    SIGNING_WORKER_SERVER_OUTPUT_DO_KEY_PREFIX_ENV, SIGNING_WORKER_SERVER_OUTPUT_DO_OBJECT_ENV,
};

mod handlers;
mod memory_storage;
#[cfg(feature = "workers-rs")]
mod worker_storage;
pub use handlers::handle_cloudflare_durable_object_call_v1;
pub use memory_storage::CloudflareDurableObjectMemoryStorageV1;
#[cfg(feature = "workers-rs")]
use worker_storage::handle_cloudflare_durable_object_class_fetch_v1;
#[cfg(feature = "workers-rs")]
pub use worker_storage::{
    execute_cloudflare_durable_object_call_v1, handle_cloudflare_durable_object_fetch_v1,
    handle_cloudflare_durable_object_worker_request_v1,
};

/// Version label for the Router/A/B Cloudflare Durable Object API.
pub const CLOUDFLARE_DURABLE_OBJECT_API_VERSION: &str = "router-ab-cloudflare-do";

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

/// Router Wallet Session budget Durable Object class.
#[cfg(feature = "workers-rs")]
#[worker::durable_object(fetch)]
pub struct RouterAbRouterWalletBudgetDurableObject {
    state: worker::State,
    env: worker::Env,
}

#[cfg(feature = "workers-rs")]
impl worker::DurableObject for RouterAbRouterWalletBudgetDurableObject {
    fn new(state: worker::State, env: worker::Env) -> Self {
        Self { state, env }
    }

    async fn fetch(&self, request: worker::Request) -> worker::Result<worker::Response> {
        handle_cloudflare_durable_object_class_fetch_v1(
            CloudflareDurableObjectScopeV1::RouterWalletBudget,
            ROUTER_WALLET_BUDGET_DO_BINDING_ENV,
            ROUTER_WALLET_BUDGET_DO_OBJECT_ENV,
            ROUTER_WALLET_BUDGET_DO_KEY_PREFIX_ENV,
            &self.env,
            &self.state,
            request,
        )
        .await
    }
}

/// Deriver A root-share Durable Object class.
#[cfg(feature = "workers-rs")]
#[worker::durable_object(fetch)]
pub struct RouterAbDeriverARootShareDurableObject {
    state: worker::State,
    env: worker::Env,
}

#[cfg(feature = "workers-rs")]
impl worker::DurableObject for RouterAbDeriverARootShareDurableObject {
    fn new(state: worker::State, env: worker::Env) -> Self {
        Self { state, env }
    }

    async fn fetch(&self, request: worker::Request) -> worker::Result<worker::Response> {
        handle_cloudflare_durable_object_class_fetch_v1(
            CloudflareDurableObjectScopeV1::SignerRootShare {
                role: Role::SignerA,
            },
            DERIVER_A_ROOT_SHARE_DO_BINDING_ENV,
            DERIVER_A_ROOT_SHARE_DO_OBJECT_ENV,
            DERIVER_A_ROOT_SHARE_DO_KEY_PREFIX_ENV,
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

/// Deriver B root-share Durable Object class.
#[cfg(feature = "workers-rs")]
#[worker::durable_object(fetch)]
pub struct RouterAbDeriverBRootShareDurableObject {
    state: worker::State,
    env: worker::Env,
}

#[cfg(feature = "workers-rs")]
impl worker::DurableObject for RouterAbDeriverBRootShareDurableObject {
    fn new(state: worker::State, env: worker::Env) -> Self {
        Self { state, env }
    }

    async fn fetch(&self, request: worker::Request) -> worker::Result<worker::Response> {
        handle_cloudflare_durable_object_class_fetch_v1(
            CloudflareDurableObjectScopeV1::SignerRootShare {
                role: Role::SignerB,
            },
            DERIVER_B_ROOT_SHARE_DO_BINDING_ENV,
            DERIVER_B_ROOT_SHARE_DO_OBJECT_ENV,
            DERIVER_B_ROOT_SHARE_DO_KEY_PREFIX_ENV,
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
    /// Repoint role-local root-share startup metadata after a server-side rewrap.
    RootShareRewrapStartupMetadata,
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
    /// Create or reuse a Wallet Session signing budget grant.
    RouterWalletBudgetPutGrant,
    /// Reserve Wallet Session signing budget before prepare.
    RouterWalletBudgetReserve,
    /// Validate an existing Wallet Session signing budget reservation before finalize.
    RouterWalletBudgetValidate,
    /// Commit Wallet Session signing budget after successful signing.
    RouterWalletBudgetCommit,
    /// Release an uncommitted Wallet Session signing budget reservation.
    RouterWalletBudgetRelease,
    /// Read Wallet Session signing budget status.
    RouterWalletBudgetStatus,
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
    /// Store one SigningWorker ECDSA presignature record for ECDSA-HSS signing.
    SigningWorkerEcdsaPresignaturePut,
    /// Take one SigningWorker ECDSA presignature record for ECDSA-HSS signing.
    SigningWorkerEcdsaPresignatureTake,
    /// Remove expired SigningWorker ECDSA presignature records.
    SigningWorkerEcdsaPresignatureCleanupExpired,
    /// Store one unbound SigningWorker ECDSA presignature pool record.
    SigningWorkerEcdsaPresignaturePoolPut,
    /// Reserve one unbound SigningWorker ECDSA presignature pool record.
    SigningWorkerEcdsaPresignaturePoolTake,
    /// Remove expired unbound SigningWorker ECDSA presignature pool records.
    SigningWorkerEcdsaPresignaturePoolCleanupExpired,
    /// Store one direct Deriver activation delivery and return pending or ready state.
    SigningWorkerDirectActivationPut,
}

impl CloudflareDurableObjectOperationKindV1 {
    /// Returns the stable operation label.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RootShareHas => "root_share.has",
            Self::RootShareStartupMetadata => "root_share.startup_metadata",
            Self::RootShareRewrapStartupMetadata => "root_share.rewrap_startup_metadata",
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
            Self::RouterWalletBudgetPutGrant => "router_wallet_budget.put_grant",
            Self::RouterWalletBudgetReserve => "router_wallet_budget.reserve",
            Self::RouterWalletBudgetValidate => "router_wallet_budget.validate",
            Self::RouterWalletBudgetCommit => "router_wallet_budget.commit",
            Self::RouterWalletBudgetRelease => "router_wallet_budget.release",
            Self::RouterWalletBudgetStatus => "router_wallet_budget.status",
            Self::SigningWorkerOutputActivate => "signing_worker_output.activate",
            Self::SigningWorkerOutputActiveStateGet => "signing_worker_output.active_state_get",
            Self::SigningWorkerOutputMaterialGet => "signing_worker_output.material_get",
            Self::SigningWorkerRound1Put => "signing_worker_round1.put",
            Self::SigningWorkerRound1Take => "signing_worker_round1.take",
            Self::SigningWorkerRound1CleanupExpired => "signing_worker_round1.cleanup_expired",
            Self::SigningWorkerEcdsaPresignaturePut => "signing_worker_ecdsa_presignature.put",
            Self::SigningWorkerEcdsaPresignatureTake => "signing_worker_ecdsa_presignature.take",
            Self::SigningWorkerEcdsaPresignatureCleanupExpired => {
                "signing_worker_ecdsa_presignature.cleanup_expired"
            }
            Self::SigningWorkerEcdsaPresignaturePoolPut => {
                "signing_worker_ecdsa_presignature_pool.put"
            }
            Self::SigningWorkerEcdsaPresignaturePoolTake => {
                "signing_worker_ecdsa_presignature_pool.take"
            }
            Self::SigningWorkerEcdsaPresignaturePoolCleanupExpired => {
                "signing_worker_ecdsa_presignature_pool.cleanup_expired"
            }
            Self::SigningWorkerDirectActivationPut => "signing_worker_direct_activation.put",
        }
    }

    /// Returns the internal HTTP path used by the Worker-to-Durable-Object call.
    pub fn path(self) -> &'static str {
        match self {
            Self::RootShareHas => "/router-ab/do/root-share/has",
            Self::RootShareStartupMetadata => "/router-ab/do/root-share/startup-metadata",
            Self::RootShareRewrapStartupMetadata => {
                "/router-ab/do/root-share/rewrap-startup-metadata"
            }
            Self::RouterReplayReserve => "/router-ab/do/router-replay/reserve",
            Self::RouterReplayCleanupExpired => "/router-ab/do/router-replay/cleanup-expired",
            Self::RouterLifecyclePutPublicState => "/router-ab/do/router-lifecycle/put",
            Self::DerivationCeremonyPutState => "/router-ab/do/derivation-ceremony/put",
            Self::RouterProjectPolicyEvaluate => "/router-ab/do/router-project-policy/evaluate",
            Self::RouterQuotaEvaluate => "/router-ab/do/router-quota/evaluate",
            Self::RouterQuotaCleanupExpired => "/router-ab/do/router-quota/cleanup-expired",
            Self::RouterAbuseEvaluate => "/router-ab/do/router-abuse/evaluate",
            Self::RouterNormalSigningProjectPolicyEvaluate => {
                "/router-ab/do/router-project-policy/normal-signing/evaluate"
            }
            Self::RouterNormalSigningQuotaEvaluate => {
                "/router-ab/do/router-quota/normal-signing/evaluate"
            }
            Self::RouterNormalSigningAbuseEvaluate => {
                "/router-ab/do/router-abuse/normal-signing/evaluate"
            }
            Self::RouterWalletBudgetPutGrant => "/router-ab/do/router-wallet-budget/put-grant",
            Self::RouterWalletBudgetReserve => "/router-ab/do/router-wallet-budget/reserve",
            Self::RouterWalletBudgetValidate => "/router-ab/do/router-wallet-budget/validate",
            Self::RouterWalletBudgetCommit => "/router-ab/do/router-wallet-budget/commit",
            Self::RouterWalletBudgetRelease => "/router-ab/do/router-wallet-budget/release",
            Self::RouterWalletBudgetStatus => "/router-ab/do/router-wallet-budget/status",
            Self::SigningWorkerOutputActivate => "/router-ab/do/signing-worker-output/activate",
            Self::SigningWorkerOutputActiveStateGet => {
                "/router-ab/do/signing-worker-output/active-state/get"
            }
            Self::SigningWorkerOutputMaterialGet => {
                "/router-ab/do/signing-worker-output/material/get"
            }
            Self::SigningWorkerRound1Put => "/router-ab/do/signing-worker-round1/put",
            Self::SigningWorkerRound1Take => "/router-ab/do/signing-worker-round1/take",
            Self::SigningWorkerRound1CleanupExpired => {
                "/router-ab/do/signing-worker-round1/cleanup-expired"
            }
            Self::SigningWorkerEcdsaPresignaturePut => {
                "/router-ab/do/signing-worker-ecdsa-presignature/put"
            }
            Self::SigningWorkerEcdsaPresignatureTake => {
                "/router-ab/do/signing-worker-ecdsa-presignature/take"
            }
            Self::SigningWorkerEcdsaPresignatureCleanupExpired => {
                "/router-ab/do/signing-worker-ecdsa-presignature/cleanup-expired"
            }
            Self::SigningWorkerEcdsaPresignaturePoolPut => {
                "/router-ab/do/signing-worker-ecdsa-presignature-pool/put"
            }
            Self::SigningWorkerEcdsaPresignaturePoolTake => {
                "/router-ab/do/signing-worker-ecdsa-presignature-pool/take"
            }
            Self::SigningWorkerEcdsaPresignaturePoolCleanupExpired => {
                "/router-ab/do/signing-worker-ecdsa-presignature-pool/cleanup-expired"
            }
            Self::SigningWorkerDirectActivationPut => {
                "/router-ab/do/signing-worker-direct-activation/put"
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
        request: &EcdsaThresholdPrfRequestV1,
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

/// Curve branch consuming a Wallet Session signing budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CloudflareRouterWalletBudgetCurveV1 {
    /// NEAR/Ed25519 normal signing.
    Ed25519,
    /// ECDSA-HSS EVM-family normal signing.
    #[serde(rename = "ecdsa")]
    EcdsaHss,
}

/// Signer binding authorized by one Wallet Session budget grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareRouterWalletBudgetSignerBindingV1 {
    /// Curve branch authorized for this budget.
    pub curve: CloudflareRouterWalletBudgetCurveV1,
    /// Threshold session or active-state session id.
    pub threshold_session_id: String,
    /// SigningWorker id authorized to consume the budget.
    pub signing_worker_id: String,
}

impl CloudflareRouterWalletBudgetSignerBindingV1 {
    /// Creates a validated signer binding.
    pub fn new(
        curve: CloudflareRouterWalletBudgetCurveV1,
        threshold_session_id: impl Into<String>,
        signing_worker_id: impl Into<String>,
    ) -> RouterAbProtocolResult<Self> {
        let binding = Self {
            curve,
            threshold_session_id: threshold_session_id.into(),
            signing_worker_id: signing_worker_id.into(),
        };
        binding.validate()?;
        Ok(binding)
    }

    /// Validates signer binding fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty(
            "wallet budget threshold_session_id",
            &self.threshold_session_id,
        )?;
        require_non_empty("wallet budget signing_worker_id", &self.signing_worker_id)
    }
}

/// Create-or-reuse request for a Wallet Session signing budget grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareRouterWalletBudgetPutGrantRequestV1 {
    /// Wallet Session signing grant id.
    pub signing_grant_id: String,
    /// Wallet/account id.
    pub wallet_id: String,
    /// Relying party id.
    pub rp_id: String,
    /// Curve/session/worker bindings allowed to consume this grant.
    pub authorized_signers: Vec<CloudflareRouterWalletBudgetSignerBindingV1>,
    /// Initial signature uses for this Wallet Session.
    pub initial_signature_uses: u32,
    /// Grant expiry in Unix milliseconds.
    pub expires_at_ms: u64,
    /// JWT id or issuer-side idempotency key.
    pub issuer_jwt_id: String,
    /// Current Worker time in Unix milliseconds.
    pub now_unix_ms: u64,
}

impl CloudflareRouterWalletBudgetPutGrantRequestV1 {
    /// Validates grant issuance fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("wallet budget signing_grant_id", &self.signing_grant_id)?;
        require_non_empty("wallet budget wallet_id", &self.wallet_id)?;
        require_non_empty("wallet budget rp_id", &self.rp_id)?;
        require_non_empty("wallet budget issuer_jwt_id", &self.issuer_jwt_id)?;
        if self.initial_signature_uses == 0 {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "wallet budget initial_signature_uses must be greater than zero",
            ));
        }
        require_positive_ms("wallet budget expires_at_ms", self.expires_at_ms)?;
        require_positive_ms("wallet budget now_unix_ms", self.now_unix_ms)?;
        if self.now_unix_ms >= self.expires_at_ms {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ExpiredLocalRequest,
                "wallet budget grant is already expired",
            ));
        }
        require_non_empty_vec("wallet budget authorized_signers", &self.authorized_signers)?;
        for signer in &self.authorized_signers {
            signer.validate()?;
        }
        Ok(())
    }
}

/// Reserve request for one Wallet Session signing operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareRouterWalletBudgetReserveRequestV1 {
    /// Wallet Session signing grant id.
    pub signing_grant_id: String,
    /// Curve branch consuming the budget.
    pub curve: CloudflareRouterWalletBudgetCurveV1,
    /// Threshold session or active-state session id.
    pub threshold_session_id: String,
    /// SigningWorker id consuming the budget.
    pub signing_worker_id: String,
    /// Canonical signing operation id independent of transport request id.
    pub operation_id: String,
    /// Canonical operation request digest.
    pub request_digest: PublicDigest32,
    /// Signature uses consumed by this operation.
    pub signature_uses: u32,
    /// Reservation expiry in Unix milliseconds.
    pub expires_at_ms: u64,
    /// Current Worker time in Unix milliseconds.
    pub now_unix_ms: u64,
}

impl CloudflareRouterWalletBudgetReserveRequestV1 {
    /// Validates reserve fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("wallet budget signing_grant_id", &self.signing_grant_id)?;
        require_non_empty(
            "wallet budget threshold_session_id",
            &self.threshold_session_id,
        )?;
        require_non_empty("wallet budget signing_worker_id", &self.signing_worker_id)?;
        require_non_empty("wallet budget operation_id", &self.operation_id)?;
        if self.signature_uses == 0 {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "wallet budget signature_uses must be greater than zero",
            ));
        }
        require_positive_ms(
            "wallet budget reservation expires_at_ms",
            self.expires_at_ms,
        )?;
        require_positive_ms("wallet budget reservation now_unix_ms", self.now_unix_ms)?;
        if self.now_unix_ms >= self.expires_at_ms {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ExpiredLocalRequest,
                "wallet budget reservation is already expired",
            ));
        }
        Ok(())
    }

    fn reservation_id(&self) -> String {
        router_wallet_budget_reservation_id_v1(
            &self.signing_worker_id,
            &self.operation_id,
            self.request_digest,
        )
    }
}

/// Identity for validating or committing an existing budget reservation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareRouterWalletBudgetReservationIdentityV1 {
    /// Wallet Session signing grant id.
    pub signing_grant_id: String,
    /// Reservation id returned by prepare.
    pub reservation_id: String,
    /// SigningWorker id consuming the budget.
    pub signing_worker_id: String,
    /// Canonical signing operation id.
    pub operation_id: String,
    /// Canonical operation request digest.
    pub request_digest: PublicDigest32,
    /// Current Worker time in Unix milliseconds.
    pub now_unix_ms: u64,
}

impl CloudflareRouterWalletBudgetReservationIdentityV1 {
    /// Creates a validated reservation identity.
    pub fn new(
        signing_grant_id: impl Into<String>,
        reservation_id: impl Into<String>,
        signing_worker_id: impl Into<String>,
        operation_id: impl Into<String>,
        request_digest: PublicDigest32,
        now_unix_ms: u64,
    ) -> RouterAbProtocolResult<Self> {
        let identity = Self {
            signing_grant_id: signing_grant_id.into(),
            reservation_id: reservation_id.into(),
            signing_worker_id: signing_worker_id.into(),
            operation_id: operation_id.into(),
            request_digest,
            now_unix_ms,
        };
        identity.validate()?;
        Ok(identity)
    }

    /// Validates identity fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("wallet budget signing_grant_id", &self.signing_grant_id)?;
        require_non_empty("wallet budget reservation_id", &self.reservation_id)?;
        require_non_empty("wallet budget signing_worker_id", &self.signing_worker_id)?;
        require_non_empty("wallet budget operation_id", &self.operation_id)?;
        require_positive_ms("wallet budget now_unix_ms", self.now_unix_ms)
    }
}

/// Release request for an uncommitted Wallet Session budget reservation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareRouterWalletBudgetReleaseRequestV1 {
    /// Wallet Session signing grant id.
    pub signing_grant_id: String,
    /// Reservation id to release.
    pub reservation_id: String,
    /// SigningWorker id that owns the reservation.
    pub signing_worker_id: String,
    /// Canonical signing operation id.
    pub operation_id: String,
    /// Canonical operation request digest.
    pub request_digest: PublicDigest32,
    /// Current Worker time in Unix milliseconds.
    pub now_unix_ms: u64,
}

impl CloudflareRouterWalletBudgetReleaseRequestV1 {
    /// Validates release fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("wallet budget signing_grant_id", &self.signing_grant_id)?;
        require_non_empty("wallet budget reservation_id", &self.reservation_id)?;
        require_non_empty("wallet budget signing_worker_id", &self.signing_worker_id)?;
        require_non_empty("wallet budget operation_id", &self.operation_id)?;
        require_positive_ms("wallet budget now_unix_ms", self.now_unix_ms)
    }
}

/// Status request for one Wallet Session signing budget grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareRouterWalletBudgetStatusRequestV1 {
    /// Wallet Session signing grant id.
    pub signing_grant_id: String,
    /// Current Worker time in Unix milliseconds.
    pub now_unix_ms: u64,
}

impl CloudflareRouterWalletBudgetStatusRequestV1 {
    /// Validates status fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("wallet budget signing_grant_id", &self.signing_grant_id)?;
        require_positive_ms("wallet budget now_unix_ms", self.now_unix_ms)
    }
}

/// Budget projection returned from the Wallet Session budget Durable Object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareRouterWalletBudgetStatusV1 {
    /// Wallet Session signing grant id.
    pub signing_grant_id: String,
    /// Remaining committed uses after finalized signatures.
    pub committed_remaining_uses: u32,
    /// Uses currently reserved by in-flight prepare requests.
    pub reserved_uses: u32,
    /// Uses available for a new reservation now.
    pub available_uses: u32,
    /// Monotonic record version for diagnostics and cache invalidation.
    pub projection_version: u64,
    /// Grant expiry in Unix milliseconds.
    pub expires_at_ms: u64,
}

impl CloudflareRouterWalletBudgetStatusV1 {
    /// Creates a validated status projection.
    pub fn new(
        signing_grant_id: impl Into<String>,
        committed_remaining_uses: u32,
        reserved_uses: u32,
        projection_version: u64,
        expires_at_ms: u64,
    ) -> RouterAbProtocolResult<Self> {
        let available_uses = committed_remaining_uses.saturating_sub(reserved_uses);
        let status = Self {
            signing_grant_id: signing_grant_id.into(),
            committed_remaining_uses,
            reserved_uses,
            available_uses,
            projection_version,
            expires_at_ms,
        };
        status.validate()?;
        Ok(status)
    }

    /// Validates status fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("wallet budget signing_grant_id", &self.signing_grant_id)?;
        require_positive_ms("wallet budget expires_at_ms", self.expires_at_ms)
    }
}

/// Wallet Session signing budget reservation status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CloudflareRouterWalletBudgetReservationStatusV1 {
    /// In-flight prepare reserved budget.
    Reserved,
    /// Finalize successfully committed the budget.
    Committed,
}

/// Stored Wallet Session signing budget reservation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareRouterWalletBudgetReservationRecordV1 {
    /// Reservation id.
    pub reservation_id: String,
    /// Curve branch.
    pub curve: CloudflareRouterWalletBudgetCurveV1,
    /// Threshold session or active-state session id.
    pub threshold_session_id: String,
    /// SigningWorker id.
    pub signing_worker_id: String,
    /// Canonical signing operation id.
    pub operation_id: String,
    /// Canonical operation request digest.
    pub request_digest: PublicDigest32,
    /// Signature uses consumed by this operation.
    pub signature_uses: u32,
    /// Reservation expiry in Unix milliseconds.
    pub expires_at_ms: u64,
    /// Reservation lifecycle status.
    pub status: CloudflareRouterWalletBudgetReservationStatusV1,
    /// Remaining committed uses after commit, or zero while reserved.
    pub remaining_uses_after_commit: u32,
}

impl CloudflareRouterWalletBudgetReservationRecordV1 {
    fn from_request(request: &CloudflareRouterWalletBudgetReserveRequestV1) -> Self {
        Self {
            reservation_id: request.reservation_id(),
            curve: request.curve,
            threshold_session_id: request.threshold_session_id.clone(),
            signing_worker_id: request.signing_worker_id.clone(),
            operation_id: request.operation_id.clone(),
            request_digest: request.request_digest,
            signature_uses: request.signature_uses,
            expires_at_ms: request.expires_at_ms,
            status: CloudflareRouterWalletBudgetReservationStatusV1::Reserved,
            remaining_uses_after_commit: 0,
        }
    }

    fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("wallet budget reservation_id", &self.reservation_id)?;
        require_non_empty(
            "wallet budget threshold_session_id",
            &self.threshold_session_id,
        )?;
        require_non_empty("wallet budget signing_worker_id", &self.signing_worker_id)?;
        require_non_empty("wallet budget operation_id", &self.operation_id)?;
        if self.signature_uses == 0 {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "wallet budget reservation signature_uses must be greater than zero",
            ));
        }
        require_positive_ms(
            "wallet budget reservation expires_at_ms",
            self.expires_at_ms,
        )
    }

    fn validate_identity(
        &self,
        identity: &CloudflareRouterWalletBudgetReservationIdentityV1,
    ) -> RouterAbProtocolResult<()> {
        self.validate()?;
        identity.validate()?;
        if self.reservation_id == identity.reservation_id
            && self.signing_worker_id == identity.signing_worker_id
            && self.operation_id == identity.operation_id
            && self.request_digest == identity.request_digest
        {
            return Ok(());
        }
        Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidGateDecision,
            "wallet budget reservation identity does not match",
        ))
    }
}

/// Stored Wallet Session signing budget grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareRouterWalletBudgetGrantRecordV1 {
    /// Wallet Session signing grant id.
    pub signing_grant_id: String,
    /// Wallet/account id.
    pub wallet_id: String,
    /// Relying party id.
    pub rp_id: String,
    /// Issuer-side idempotency key.
    pub issuer_jwt_id: String,
    /// Authorized curve/session/worker bindings.
    pub authorized_signers: Vec<CloudflareRouterWalletBudgetSignerBindingV1>,
    /// Initial signature uses issued for this grant.
    pub initial_signature_uses: u32,
    /// Remaining uses after committed signatures.
    pub committed_remaining_uses: u32,
    /// Grant expiry in Unix milliseconds.
    pub expires_at_ms: u64,
    /// Active and committed reservations keyed by reservation id.
    pub reservations: BTreeMap<String, CloudflareRouterWalletBudgetReservationRecordV1>,
    /// Committed operation identities keyed by canonical operation identity.
    pub committed_operations: BTreeMap<String, String>,
    /// Monotonic projection version.
    pub projection_version: u64,
}

impl CloudflareRouterWalletBudgetGrantRecordV1 {
    fn from_put_request(
        request: &CloudflareRouterWalletBudgetPutGrantRequestV1,
    ) -> RouterAbProtocolResult<Self> {
        request.validate()?;
        let record = Self {
            signing_grant_id: request.signing_grant_id.clone(),
            wallet_id: request.wallet_id.clone(),
            rp_id: request.rp_id.clone(),
            issuer_jwt_id: request.issuer_jwt_id.clone(),
            authorized_signers: request.authorized_signers.clone(),
            initial_signature_uses: request.initial_signature_uses,
            committed_remaining_uses: request.initial_signature_uses,
            expires_at_ms: request.expires_at_ms,
            reservations: BTreeMap::new(),
            committed_operations: BTreeMap::new(),
            projection_version: 1,
        };
        record.validate()?;
        Ok(record)
    }

    fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("wallet budget signing_grant_id", &self.signing_grant_id)?;
        require_non_empty("wallet budget wallet_id", &self.wallet_id)?;
        require_non_empty("wallet budget rp_id", &self.rp_id)?;
        require_non_empty("wallet budget issuer_jwt_id", &self.issuer_jwt_id)?;
        require_non_empty_vec("wallet budget authorized_signers", &self.authorized_signers)?;
        if self.initial_signature_uses == 0 {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "wallet budget initial_signature_uses must be greater than zero",
            ));
        }
        if self.committed_remaining_uses > self.initial_signature_uses {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "wallet budget committed remaining uses exceeds initial uses",
            ));
        }
        for signer in &self.authorized_signers {
            signer.validate()?;
        }
        for reservation in self.reservations.values() {
            reservation.validate()?;
        }
        require_positive_ms("wallet budget expires_at_ms", self.expires_at_ms)
    }

    fn validate_matches_put_request(
        &self,
        request: &CloudflareRouterWalletBudgetPutGrantRequestV1,
    ) -> RouterAbProtocolResult<()> {
        self.validate()?;
        request.validate()?;
        if self.signing_grant_id == request.signing_grant_id
            && self.wallet_id == request.wallet_id
            && self.rp_id == request.rp_id
            && self.issuer_jwt_id == request.issuer_jwt_id
            && self.authorized_signers == request.authorized_signers
            && self.initial_signature_uses == request.initial_signature_uses
            && self.expires_at_ms == request.expires_at_ms
        {
            return Ok(());
        }
        Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ReplayedLocalRequest,
            "wallet budget grant id is already stored for different material",
        ))
    }

    fn clean_expired_reservations(&mut self, now_unix_ms: u64) -> RouterAbProtocolResult<bool> {
        self.validate()?;
        require_positive_ms("wallet budget now_unix_ms", now_unix_ms)?;
        let before = self.reservations.len();
        self.reservations.retain(|_, reservation| {
            reservation.status == CloudflareRouterWalletBudgetReservationStatusV1::Committed
                || reservation.expires_at_ms > now_unix_ms
        });
        let changed = before != self.reservations.len();
        if changed {
            self.projection_version = self.projection_version.saturating_add(1);
        }
        Ok(changed)
    }

    fn status_at(
        &self,
        now_unix_ms: u64,
    ) -> RouterAbProtocolResult<CloudflareRouterWalletBudgetStatusV1> {
        self.validate()?;
        require_positive_ms("wallet budget now_unix_ms", now_unix_ms)?;
        if now_unix_ms >= self.expires_at_ms {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ExpiredLocalRequest,
                "wallet budget grant expired",
            ));
        }
        let reserved_uses = self
            .reservations
            .values()
            .filter(|reservation| {
                reservation.status == CloudflareRouterWalletBudgetReservationStatusV1::Reserved
                    && reservation.expires_at_ms > now_unix_ms
            })
            .try_fold(0u32, |total, reservation| {
                total
                    .checked_add(reservation.signature_uses)
                    .ok_or_else(|| {
                        RouterAbProtocolError::new(
                            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                            "wallet budget reserved uses overflow",
                        )
                    })
            })?;
        CloudflareRouterWalletBudgetStatusV1::new(
            self.signing_grant_id.clone(),
            self.committed_remaining_uses,
            reserved_uses,
            self.projection_version,
            self.expires_at_ms,
        )
    }

    fn require_authorized_signer(
        &self,
        request: &CloudflareRouterWalletBudgetReserveRequestV1,
    ) -> RouterAbProtocolResult<()> {
        self.validate()?;
        request.validate()?;
        if self.authorized_signers.iter().any(|signer| {
            signer.curve == request.curve
                && signer.threshold_session_id == request.threshold_session_id
                && signer.signing_worker_id == request.signing_worker_id
        }) {
            return Ok(());
        }
        Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            "wallet budget reserve signer is not authorized by grant",
        ))
    }

    fn reserve(
        &mut self,
        request: &CloudflareRouterWalletBudgetReserveRequestV1,
    ) -> RouterAbProtocolResult<String> {
        self.clean_expired_reservations(request.now_unix_ms)?;
        self.require_authorized_signer(request)?;
        let reservation_id = request.reservation_id();
        if let Some(existing) = self.reservations.get(&reservation_id) {
            existing.validate()?;
            if existing == &CloudflareRouterWalletBudgetReservationRecordV1::from_request(request) {
                return Ok(reservation_id);
            }
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ReplayedLocalRequest,
                "wallet budget reservation id is already stored for different material",
            ));
        }
        if self
            .committed_operations
            .contains_key(&router_wallet_budget_operation_key_v1(
                &request.signing_worker_id,
                &request.operation_id,
                request.request_digest,
            ))
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ReplayedLocalRequest,
                "wallet budget operation was already committed",
            ));
        }
        let status = self.status_at(request.now_unix_ms)?;
        if status.available_uses < request.signature_uses {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "wallet budget exhausted",
            ));
        }
        self.reservations.insert(
            reservation_id.clone(),
            CloudflareRouterWalletBudgetReservationRecordV1::from_request(request),
        );
        self.projection_version = self.projection_version.saturating_add(1);
        Ok(reservation_id)
    }

    fn validate_reservation(
        &mut self,
        identity: &CloudflareRouterWalletBudgetReservationIdentityV1,
    ) -> RouterAbProtocolResult<()> {
        self.clean_expired_reservations(identity.now_unix_ms)?;
        let reservation = self
            .reservations
            .get(&identity.reservation_id)
            .ok_or_else(|| {
                RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::MissingLocalBinding,
                    "wallet budget reservation is missing",
                )
            })?;
        reservation.validate_identity(identity)?;
        if reservation.status == CloudflareRouterWalletBudgetReservationStatusV1::Reserved
            && identity.now_unix_ms >= reservation.expires_at_ms
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ExpiredLocalRequest,
                "wallet budget reservation expired",
            ));
        }
        Ok(())
    }

    fn commit(
        &mut self,
        identity: &CloudflareRouterWalletBudgetReservationIdentityV1,
    ) -> RouterAbProtocolResult<()> {
        self.validate_reservation(identity)?;
        let reservation = self
            .reservations
            .get_mut(&identity.reservation_id)
            .ok_or_else(|| {
                RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::MissingLocalBinding,
                    "wallet budget reservation is missing",
                )
            })?;
        if reservation.status == CloudflareRouterWalletBudgetReservationStatusV1::Committed {
            return Ok(());
        }
        if self.committed_remaining_uses < reservation.signature_uses {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "wallet budget exhausted at commit",
            ));
        }
        self.committed_remaining_uses -= reservation.signature_uses;
        reservation.status = CloudflareRouterWalletBudgetReservationStatusV1::Committed;
        reservation.remaining_uses_after_commit = self.committed_remaining_uses;
        self.committed_operations.insert(
            router_wallet_budget_operation_key_v1(
                &reservation.signing_worker_id,
                &reservation.operation_id,
                reservation.request_digest,
            ),
            reservation.reservation_id.clone(),
        );
        self.projection_version = self.projection_version.saturating_add(1);
        Ok(())
    }

    fn release(
        &mut self,
        request: &CloudflareRouterWalletBudgetReleaseRequestV1,
    ) -> RouterAbProtocolResult<()> {
        self.clean_expired_reservations(request.now_unix_ms)?;
        let release_matches =
            self.reservations
                .get(&request.reservation_id)
                .is_some_and(|reservation| {
                    reservation.status == CloudflareRouterWalletBudgetReservationStatusV1::Reserved
                        && reservation.signing_worker_id == request.signing_worker_id
                        && reservation.operation_id == request.operation_id
                        && reservation.request_digest == request.request_digest
                });
        if release_matches && self.reservations.remove(&request.reservation_id).is_some() {
            self.projection_version = self.projection_version.saturating_add(1);
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
            .contains(&request.metadata.work_kind)
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

/// Request to repoint role-local root-share metadata after rewrapping custody.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareRootShareRewrapRequestV1 {
    /// Existing root-share identity being rewrapped.
    pub lookup: CloudflareRootShareLookupRequestV1,
    /// Replacement metadata pointing at the rewrapped sealed share.
    pub replacement_metadata: CloudflareRootShareStartupMetadataV1,
    /// Rewrap timestamp in Unix milliseconds.
    pub rewrapped_at_ms: u64,
}

impl CloudflareRootShareRewrapRequestV1 {
    /// Creates a validated root-share rewrap request.
    pub fn new(
        lookup: CloudflareRootShareLookupRequestV1,
        replacement_metadata: CloudflareRootShareStartupMetadataV1,
        rewrapped_at_ms: u64,
    ) -> RouterAbProtocolResult<Self> {
        let request = Self {
            lookup,
            replacement_metadata,
            rewrapped_at_ms,
        };
        request.validate()?;
        Ok(request)
    }

    /// Validates the replacement metadata is scoped to the looked-up root share.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.lookup.validate()?;
        self.replacement_metadata
            .validate_matches_lookup(&self.lookup)?;
        require_positive_ms("root-share rewrap rewrapped_at_ms", self.rewrapped_at_ms)
    }

    /// Validates the replacement is a pure custody rewrap of the existing metadata.
    pub fn validate_replaces(
        &self,
        existing: &CloudflareRootShareStartupMetadataV1,
    ) -> RouterAbProtocolResult<()> {
        self.validate()?;
        existing.validate_matches_lookup(&self.lookup)?;
        if existing.signer_id != self.replacement_metadata.signer_id
            || existing.signer_key_epoch != self.replacement_metadata.signer_key_epoch
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidSignerIdentity,
                "root-share rewrap cannot change signer identity or signer key epoch",
            ));
        }
        if existing.sealed_share_storage_key == self.replacement_metadata.sealed_share_storage_key {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "root-share rewrap must change the sealed-share storage key",
            ));
        }
        Ok(())
    }
}

/// Receipt returned after root-share metadata is repointed to rewrapped custody.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareRootShareRewrapReceiptV1 {
    /// Signer set id.
    pub signer_set_id: String,
    /// Signer role.
    pub signer_role: Role,
    /// Root-share epoch.
    pub root_share_epoch: RootShareEpoch,
    /// Previous sealed-share storage key.
    pub previous_sealed_share_storage_key: String,
    /// Replacement sealed-share storage key.
    pub replacement_sealed_share_storage_key: String,
    /// Rewrap timestamp in Unix milliseconds.
    pub rewrapped_at_ms: u64,
}

impl CloudflareRootShareRewrapReceiptV1 {
    /// Creates a validated root-share rewrap receipt.
    pub fn new(
        request: &CloudflareRootShareRewrapRequestV1,
        existing: &CloudflareRootShareStartupMetadataV1,
    ) -> RouterAbProtocolResult<Self> {
        request.validate_replaces(existing)?;
        let receipt = Self {
            signer_set_id: request.lookup.signer_set_id.clone(),
            signer_role: request.lookup.signer_role,
            root_share_epoch: request.lookup.root_share_epoch.clone(),
            previous_sealed_share_storage_key: existing.sealed_share_storage_key.clone(),
            replacement_sealed_share_storage_key: request
                .replacement_metadata
                .sealed_share_storage_key
                .clone(),
            rewrapped_at_ms: request.rewrapped_at_ms,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    /// Validates receipt identity and storage-key transition.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("signer_set_id", &self.signer_set_id)?;
        require_signer_role(self.signer_role)?;
        require_non_empty("root_share_epoch", self.root_share_epoch.as_str())?;
        require_non_empty(
            "previous_sealed_share_storage_key",
            &self.previous_sealed_share_storage_key,
        )?;
        require_non_empty(
            "replacement_sealed_share_storage_key",
            &self.replacement_sealed_share_storage_key,
        )?;
        if self.previous_sealed_share_storage_key == self.replacement_sealed_share_storage_key {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "root-share rewrap receipt must change sealed-share storage key",
            ));
        }
        require_positive_ms(
            "root-share rewrap receipt rewrapped_at_ms",
            self.rewrapped_at_ms,
        )
    }

    /// Validates this receipt corresponds to the supplied request and prior metadata.
    pub fn validate_for_request(
        &self,
        request: &CloudflareRootShareRewrapRequestV1,
    ) -> RouterAbProtocolResult<()> {
        self.validate()?;
        request.validate()?;
        if self.signer_set_id == request.lookup.signer_set_id
            && self.signer_role == request.lookup.signer_role
            && self.root_share_epoch == request.lookup.root_share_epoch
            && self.replacement_sealed_share_storage_key
                == request.replacement_metadata.sealed_share_storage_key
            && self.rewrapped_at_ms == request.rewrapped_at_ms
        {
            Ok(())
        } else {
            Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "root-share rewrap receipt does not match request",
            ))
        }
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

    /// Creates a lookup from an ECDSA-HSS normal-signing scope.
    pub fn from_ecdsa_hss_normal_signing_scope(
        scope: &RouterAbEcdsaHssNormalSigningScopeV1,
    ) -> RouterAbProtocolResult<Self> {
        scope.validate()?;
        Self::new(
            scope.wallet_id.clone(),
            scope.active_state_session_id()?,
            scope.signing_worker.server_id.clone(),
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

/// Persisted standard FROST round-one state produced from a Yao-derived scalar share.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct CloudflareEd25519Round1StateV1 {
    signing_nonces: Vec<u8>,
    #[zeroize(skip)]
    pub commitments: NormalSigningEd25519TwoPartyFrostCommitmentsV1,
}

impl core::fmt::Debug for CloudflareEd25519Round1StateV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("CloudflareEd25519Round1StateV1")
            .field("signing_nonces", &"[REDACTED]")
            .field("commitments", &self.commitments)
            .finish()
    }
}

impl CloudflareEd25519Round1StateV1 {
    /// Creates persisted state from freshly generated one-use FROST nonces.
    pub fn new(
        signing_nonces: frost_ed25519::round1::SigningNonces,
        commitments: frost_ed25519::round1::SigningCommitments,
    ) -> RouterAbProtocolResult<Self> {
        let signing_nonces = signing_nonces.serialize().map_err(|error| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                format!("failed to serialize SigningWorker FROST nonces: {error}"),
            )
        })?;
        let commitments = NormalSigningEd25519TwoPartyFrostCommitmentsV1::new(
            URL_SAFE_NO_PAD.encode(commitments.hiding().serialize().map_err(|error| {
                RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::MalformedWirePayload,
                    format!("failed to serialize hiding commitment: {error}"),
                )
            })?),
            URL_SAFE_NO_PAD.encode(commitments.binding().serialize().map_err(|error| {
                RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::MalformedWirePayload,
                    format!("failed to serialize binding commitment: {error}"),
                )
            })?),
        )?;
        let state = Self {
            signing_nonces,
            commitments,
        };
        state.validate()?;
        Ok(state)
    }

    pub(crate) fn signing_nonces(
        &self,
    ) -> RouterAbProtocolResult<frost_ed25519::round1::SigningNonces> {
        frost_ed25519::round1::SigningNonces::deserialize(&self.signing_nonces).map_err(|error| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                format!("invalid persisted SigningWorker FROST nonces: {error}"),
            )
        })
    }

    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.commitments.validate()?;
        let nonces = self.signing_nonces()?;
        let expected = NormalSigningEd25519TwoPartyFrostCommitmentsV1::new(
            URL_SAFE_NO_PAD.encode(nonces.commitments().hiding().serialize().map_err(|error| {
                RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::MalformedWirePayload,
                    format!("failed to validate hiding commitment: {error}"),
                )
            })?),
            URL_SAFE_NO_PAD.encode(nonces.commitments().binding().serialize().map_err(
                |error| {
                    RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::MalformedWirePayload,
                        format!("failed to validate binding commitment: {error}"),
                    )
                },
            )?),
        )?;
        if expected == self.commitments {
            return Ok(());
        }
        Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "persisted SigningWorker FROST nonces do not match commitments",
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
    pub round1_state: CloudflareEd25519Round1StateV1,
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
        round1_state: CloudflareEd25519Round1StateV1,
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
    pub server_commitments: NormalSigningEd25519TwoPartyFrostCommitmentsV1,
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
            server_commitments: record.round1_state.commitments.clone(),
            stored,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    /// Validates receipt fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.active_signing_worker_state.validate()?;
        require_non_empty("server_round1_handle", &self.server_round1_handle)?;
        self.server_commitments.validate()
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

/// Stored SigningWorker ECDSA presignature material for one ECDSA-HSS signing request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSigningWorkerEcdsaPresignatureRecordV1 {
    /// Active SigningWorker descriptor that owns this presignature.
    pub active_signing_worker_state: ActiveSigningWorkerStateV1,
    /// SigningWorker-local presignature id returned by the signer backend.
    pub server_presignature_id: String,
    /// Canonical Router-admitted ECDSA-HSS signing request digest.
    pub request_digest: PublicDigest32,
    /// Router-admitted 32-byte EVM digest this presignature may sign.
    pub admitted_signing_digest: PublicDigest32,
    /// Compressed secp256k1 presignature R point encoded as unpadded base64url.
    pub server_big_r33_b64u: String,
    /// Public 32-byte rerandomization entropy used with this presignature.
    pub rerandomization_entropy32_b64u: String,
    /// SigningWorker-local ECDSA presignature k share encoded as unpadded base64url.
    pub server_k_share32_b64u: String,
    /// SigningWorker-local ECDSA presignature sigma share encoded as unpadded base64url.
    pub server_sigma_share32_b64u: String,
    /// Creation timestamp in Unix milliseconds.
    pub created_at_ms: u64,
    /// Expiry timestamp in Unix milliseconds.
    pub expires_at_ms: u64,
}

impl CloudflareSigningWorkerEcdsaPresignatureRecordV1 {
    /// Creates a validated ECDSA presignature record.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        active_signing_worker_state: ActiveSigningWorkerStateV1,
        server_presignature_id: impl Into<String>,
        request_digest: PublicDigest32,
        admitted_signing_digest: PublicDigest32,
        server_big_r33_b64u: impl Into<String>,
        rerandomization_entropy32_b64u: impl Into<String>,
        server_k_share32_b64u: impl Into<String>,
        server_sigma_share32_b64u: impl Into<String>,
        created_at_ms: u64,
        expires_at_ms: u64,
    ) -> RouterAbProtocolResult<Self> {
        let record = Self {
            active_signing_worker_state,
            server_presignature_id: server_presignature_id.into(),
            request_digest,
            admitted_signing_digest,
            server_big_r33_b64u: server_big_r33_b64u.into(),
            rerandomization_entropy32_b64u: rerandomization_entropy32_b64u.into(),
            server_k_share32_b64u: server_k_share32_b64u.into(),
            server_sigma_share32_b64u: server_sigma_share32_b64u.into(),
            created_at_ms,
            expires_at_ms,
        };
        record.validate()?;
        Ok(record)
    }

    /// Validates persisted ECDSA presignature state and lifecycle timing.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.active_signing_worker_state.validate()?;
        require_non_empty("server_presignature_id", &self.server_presignature_id)?;
        validate_compressed_secp256k1_point_b64u_v1(
            "server_big_r33_b64u",
            &self.server_big_r33_b64u,
        )?;
        validate_base64url_fixed_len_v1(
            "rerandomization_entropy32_b64u",
            &self.rerandomization_entropy32_b64u,
            32,
        )?;
        validate_base64url_fixed_len_v1("server_k_share32_b64u", &self.server_k_share32_b64u, 32)?;
        validate_base64url_fixed_len_v1(
            "server_sigma_share32_b64u",
            &self.server_sigma_share32_b64u,
            32,
        )?;
        require_positive_ms(
            "SigningWorker ECDSA presignature created_at_ms",
            self.created_at_ms,
        )?;
        require_positive_ms(
            "SigningWorker ECDSA presignature expires_at_ms",
            self.expires_at_ms,
        )?;
        if self.expires_at_ms > self.created_at_ms {
            return Ok(());
        }
        Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidTimeRange,
            "SigningWorker ECDSA presignature expiry must be after creation",
        ))
    }

    /// Validates this record is live and matches the lookup used to load it.
    pub fn validate_for_lookup(
        &self,
        lookup: &CloudflareSigningWorkerEcdsaPresignatureLookupV1,
    ) -> RouterAbProtocolResult<()> {
        self.validate()?;
        lookup.validate()?;
        if lookup.now_unix_ms >= self.expires_at_ms {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ExpiredLocalRequest,
                "SigningWorker ECDSA presignature expired",
            ));
        }
        if self.active_signing_worker_state == lookup.active_signing_worker_state
            && self.server_presignature_id == lookup.server_presignature_id
            && self.request_digest == lookup.request_digest
            && self.admitted_signing_digest == lookup.admitted_signing_digest
        {
            return Ok(());
        }
        Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "SigningWorker ECDSA presignature record does not match lookup",
        ))
    }
}

/// Lookup for one stored SigningWorker ECDSA presignature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSigningWorkerEcdsaPresignatureLookupV1 {
    /// Active SigningWorker descriptor that owns this presignature.
    pub active_signing_worker_state: ActiveSigningWorkerStateV1,
    /// SigningWorker-local presignature id returned by the signer backend.
    pub server_presignature_id: String,
    /// Expected canonical Router-admitted ECDSA-HSS signing request digest.
    pub request_digest: PublicDigest32,
    /// Expected Router-admitted 32-byte EVM digest.
    pub admitted_signing_digest: PublicDigest32,
    /// Current time for expiry enforcement.
    pub now_unix_ms: u64,
}

impl CloudflareSigningWorkerEcdsaPresignatureLookupV1 {
    /// Creates a validated ECDSA presignature lookup.
    pub fn new(
        active_signing_worker_state: ActiveSigningWorkerStateV1,
        server_presignature_id: impl Into<String>,
        request_digest: PublicDigest32,
        admitted_signing_digest: PublicDigest32,
        now_unix_ms: u64,
    ) -> RouterAbProtocolResult<Self> {
        let lookup = Self {
            active_signing_worker_state,
            server_presignature_id: server_presignature_id.into(),
            request_digest,
            admitted_signing_digest,
            now_unix_ms,
        };
        lookup.validate()?;
        Ok(lookup)
    }

    /// Validates lookup fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.active_signing_worker_state.validate()?;
        require_non_empty("server_presignature_id", &self.server_presignature_id)?;
        require_positive_ms(
            "SigningWorker ECDSA presignature lookup now_unix_ms",
            self.now_unix_ms,
        )
    }
}

/// Receipt for a stored SigningWorker ECDSA presignature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSigningWorkerEcdsaPresignaturePutReceiptV1 {
    /// Active SigningWorker descriptor that owns this presignature.
    pub active_signing_worker_state: ActiveSigningWorkerStateV1,
    /// SigningWorker-local presignature id returned by the signer backend.
    pub server_presignature_id: String,
    /// Canonical Router-admitted ECDSA-HSS signing request digest.
    pub request_digest: PublicDigest32,
    /// Router-admitted 32-byte EVM digest this presignature may sign.
    pub admitted_signing_digest: PublicDigest32,
    /// Compressed secp256k1 presignature R point encoded as unpadded base64url.
    pub server_big_r33_b64u: String,
    /// Public 32-byte rerandomization entropy used with this presignature.
    pub rerandomization_entropy32_b64u: String,
    /// Whether storage changed.
    pub stored: bool,
}

impl CloudflareSigningWorkerEcdsaPresignaturePutReceiptV1 {
    /// Creates a validated ECDSA presignature put receipt from the stored record.
    pub fn from_record(
        record: &CloudflareSigningWorkerEcdsaPresignatureRecordV1,
        stored: bool,
    ) -> RouterAbProtocolResult<Self> {
        record.validate()?;
        let receipt = Self {
            active_signing_worker_state: record.active_signing_worker_state.clone(),
            server_presignature_id: record.server_presignature_id.clone(),
            request_digest: record.request_digest,
            admitted_signing_digest: record.admitted_signing_digest,
            server_big_r33_b64u: record.server_big_r33_b64u.clone(),
            rerandomization_entropy32_b64u: record.rerandomization_entropy32_b64u.clone(),
            stored,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    /// Validates receipt fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.active_signing_worker_state.validate()?;
        require_non_empty("server_presignature_id", &self.server_presignature_id)?;
        validate_compressed_secp256k1_point_b64u_v1(
            "server_big_r33_b64u",
            &self.server_big_r33_b64u,
        )?;
        validate_base64url_fixed_len_v1(
            "rerandomization_entropy32_b64u",
            &self.rerandomization_entropy32_b64u,
            32,
        )?;
        Ok(())
    }

    /// Validates receipt identity against the record that created it.
    pub fn validate_for_record(
        &self,
        record: &CloudflareSigningWorkerEcdsaPresignatureRecordV1,
    ) -> RouterAbProtocolResult<()> {
        self.validate()?;
        record.validate()?;
        if self.active_signing_worker_state == record.active_signing_worker_state
            && self.server_presignature_id == record.server_presignature_id
            && self.request_digest == record.request_digest
            && self.admitted_signing_digest == record.admitted_signing_digest
            && self.server_big_r33_b64u == record.server_big_r33_b64u
            && self.rerandomization_entropy32_b64u == record.rerandomization_entropy32_b64u
        {
            return Ok(());
        }
        Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "SigningWorker ECDSA presignature put receipt does not match record",
        ))
    }
}

/// Stored unbound SigningWorker ECDSA presignature material for a later prepare request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSigningWorkerEcdsaPresignaturePoolRecordV1 {
    /// Active SigningWorker descriptor that owns this presignature.
    pub active_signing_worker_state: ActiveSigningWorkerStateV1,
    /// Client-selected presignature id shared by the client and SigningWorker.
    pub server_presignature_id: String,
    /// Compressed secp256k1 presignature R point encoded as unpadded base64url.
    pub server_big_r33_b64u: String,
    /// SigningWorker-local ECDSA presignature k share encoded as unpadded base64url.
    pub server_k_share32_b64u: String,
    /// SigningWorker-local ECDSA presignature sigma share encoded as unpadded base64url.
    pub server_sigma_share32_b64u: String,
    /// Creation timestamp in Unix milliseconds.
    pub created_at_ms: u64,
    /// Expiry timestamp in Unix milliseconds.
    pub expires_at_ms: u64,
}

impl CloudflareSigningWorkerEcdsaPresignaturePoolRecordV1 {
    /// Creates a validated unbound ECDSA presignature pool record.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        active_signing_worker_state: ActiveSigningWorkerStateV1,
        server_presignature_id: impl Into<String>,
        server_big_r33_b64u: impl Into<String>,
        server_k_share32_b64u: impl Into<String>,
        server_sigma_share32_b64u: impl Into<String>,
        created_at_ms: u64,
        expires_at_ms: u64,
    ) -> RouterAbProtocolResult<Self> {
        let record = Self {
            active_signing_worker_state,
            server_presignature_id: server_presignature_id.into(),
            server_big_r33_b64u: server_big_r33_b64u.into(),
            server_k_share32_b64u: server_k_share32_b64u.into(),
            server_sigma_share32_b64u: server_sigma_share32_b64u.into(),
            created_at_ms,
            expires_at_ms,
        };
        record.validate()?;
        Ok(record)
    }

    /// Validates persisted unbound ECDSA presignature state and lifecycle timing.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.active_signing_worker_state.validate()?;
        require_non_empty("server_presignature_id", &self.server_presignature_id)?;
        validate_compressed_secp256k1_point_b64u_v1(
            "server_big_r33_b64u",
            &self.server_big_r33_b64u,
        )?;
        validate_base64url_fixed_len_v1("server_k_share32_b64u", &self.server_k_share32_b64u, 32)?;
        validate_base64url_fixed_len_v1(
            "server_sigma_share32_b64u",
            &self.server_sigma_share32_b64u,
            32,
        )?;
        require_positive_ms(
            "SigningWorker ECDSA presignature pool created_at_ms",
            self.created_at_ms,
        )?;
        require_positive_ms(
            "SigningWorker ECDSA presignature pool expires_at_ms",
            self.expires_at_ms,
        )?;
        if self.expires_at_ms > self.created_at_ms {
            return Ok(());
        }
        Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidTimeRange,
            "SigningWorker ECDSA presignature pool expiry must be after creation",
        ))
    }

    /// Validates this pool record is live and matches the lookup used to reserve it.
    pub fn validate_for_lookup(
        &self,
        lookup: &CloudflareSigningWorkerEcdsaPresignaturePoolLookupV1,
    ) -> RouterAbProtocolResult<()> {
        self.validate()?;
        lookup.validate()?;
        if lookup.now_unix_ms >= self.expires_at_ms {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ExpiredLocalRequest,
                "SigningWorker ECDSA presignature pool record expired",
            ));
        }
        if self.active_signing_worker_state == lookup.active_signing_worker_state
            && self.server_presignature_id == lookup.server_presignature_id
        {
            return Ok(());
        }
        Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "SigningWorker ECDSA presignature pool record does not match lookup",
        ))
    }

    /// Converts this unbound record into a request-bound one-use presignature record.
    pub fn to_request_bound_record(
        &self,
        request_digest: PublicDigest32,
        admitted_signing_digest: PublicDigest32,
        rerandomization_entropy32_b64u: impl Into<String>,
        created_at_ms: u64,
        expires_at_ms: u64,
    ) -> RouterAbProtocolResult<CloudflareSigningWorkerEcdsaPresignatureRecordV1> {
        self.validate()?;
        if created_at_ms >= self.expires_at_ms {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ExpiredLocalRequest,
                "SigningWorker ECDSA presignature pool record expired before binding",
            ));
        }
        if expires_at_ms > self.expires_at_ms {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidTimeRange,
                "SigningWorker ECDSA presignature pool record expires before prepare request",
            ));
        }
        CloudflareSigningWorkerEcdsaPresignatureRecordV1::new(
            self.active_signing_worker_state.clone(),
            self.server_presignature_id.clone(),
            request_digest,
            admitted_signing_digest,
            self.server_big_r33_b64u.clone(),
            rerandomization_entropy32_b64u,
            self.server_k_share32_b64u.clone(),
            self.server_sigma_share32_b64u.clone(),
            created_at_ms,
            expires_at_ms,
        )
    }
}

/// Lookup used to reserve one unbound SigningWorker ECDSA presignature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSigningWorkerEcdsaPresignaturePoolLookupV1 {
    /// Active SigningWorker descriptor that owns this presignature.
    pub active_signing_worker_state: ActiveSigningWorkerStateV1,
    /// Client-selected presignature id shared by the client and SigningWorker.
    pub server_presignature_id: String,
    /// Current time for expiry enforcement.
    pub now_unix_ms: u64,
}

impl CloudflareSigningWorkerEcdsaPresignaturePoolLookupV1 {
    /// Creates a validated ECDSA presignature pool lookup.
    pub fn new(
        active_signing_worker_state: ActiveSigningWorkerStateV1,
        server_presignature_id: impl Into<String>,
        now_unix_ms: u64,
    ) -> RouterAbProtocolResult<Self> {
        let lookup = Self {
            active_signing_worker_state,
            server_presignature_id: server_presignature_id.into(),
            now_unix_ms,
        };
        lookup.validate()?;
        Ok(lookup)
    }

    /// Validates lookup fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.active_signing_worker_state.validate()?;
        require_non_empty("server_presignature_id", &self.server_presignature_id)?;
        require_positive_ms(
            "SigningWorker ECDSA presignature pool lookup now_unix_ms",
            self.now_unix_ms,
        )
    }
}

/// Receipt for a stored unbound SigningWorker ECDSA presignature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSigningWorkerEcdsaPresignaturePoolPutReceiptV1 {
    /// Active SigningWorker descriptor that owns this presignature.
    pub active_signing_worker_state: ActiveSigningWorkerStateV1,
    /// Client-selected presignature id shared by the client and SigningWorker.
    pub server_presignature_id: String,
    /// Compressed secp256k1 presignature R point encoded as unpadded base64url.
    pub server_big_r33_b64u: String,
    /// Whether storage changed.
    pub stored: bool,
}

impl CloudflareSigningWorkerEcdsaPresignaturePoolPutReceiptV1 {
    /// Creates a validated ECDSA presignature pool put receipt from the stored record.
    pub fn from_record(
        record: &CloudflareSigningWorkerEcdsaPresignaturePoolRecordV1,
        stored: bool,
    ) -> RouterAbProtocolResult<Self> {
        record.validate()?;
        let receipt = Self {
            active_signing_worker_state: record.active_signing_worker_state.clone(),
            server_presignature_id: record.server_presignature_id.clone(),
            server_big_r33_b64u: record.server_big_r33_b64u.clone(),
            stored,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    /// Validates receipt fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.active_signing_worker_state.validate()?;
        require_non_empty("server_presignature_id", &self.server_presignature_id)?;
        validate_compressed_secp256k1_point_b64u_v1(
            "server_big_r33_b64u",
            &self.server_big_r33_b64u,
        )
    }

    /// Validates receipt identity against the record that created it.
    pub fn validate_for_record(
        &self,
        record: &CloudflareSigningWorkerEcdsaPresignaturePoolRecordV1,
    ) -> RouterAbProtocolResult<()> {
        self.validate()?;
        record.validate()?;
        if self.active_signing_worker_state == record.active_signing_worker_state
            && self.server_presignature_id == record.server_presignature_id
            && self.server_big_r33_b64u == record.server_big_r33_b64u
        {
            return Ok(());
        }
        Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "SigningWorker ECDSA presignature pool put receipt does not match record",
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
    /// Repoint root-share startup metadata after server-side rewrap.
    RootShareRewrapStartupMetadata {
        /// Rewrap request.
        request: CloudflareRootShareRewrapRequestV1,
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
    /// Create or reuse a Wallet Session signing budget grant.
    RouterWalletBudgetPutGrant {
        /// Grant put request.
        request: CloudflareRouterWalletBudgetPutGrantRequestV1,
    },
    /// Reserve Wallet Session signing budget before prepare.
    RouterWalletBudgetReserve {
        /// Reservation request.
        request: CloudflareRouterWalletBudgetReserveRequestV1,
    },
    /// Validate Wallet Session signing budget before finalize.
    RouterWalletBudgetValidate {
        /// Reservation identity.
        identity: CloudflareRouterWalletBudgetReservationIdentityV1,
    },
    /// Commit Wallet Session signing budget after successful finalize.
    RouterWalletBudgetCommit {
        /// Reservation identity.
        identity: CloudflareRouterWalletBudgetReservationIdentityV1,
    },
    /// Release uncommitted Wallet Session signing budget.
    RouterWalletBudgetRelease {
        /// Release request.
        request: CloudflareRouterWalletBudgetReleaseRequestV1,
    },
    /// Read Wallet Session signing budget status.
    RouterWalletBudgetStatus {
        /// Status request.
        request: CloudflareRouterWalletBudgetStatusRequestV1,
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
    /// Store one direct Deriver activation delivery.
    SigningWorkerDirectActivationPut {
        /// Single-Deriver direct activation delivery.
        delivery: CloudflareSigningWorkerDirectRecipientProofBundleActivationDeliveryV1,
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
    /// Store SigningWorker ECDSA presignature material.
    SigningWorkerEcdsaPresignaturePut {
        /// ECDSA presignature record.
        record: CloudflareSigningWorkerEcdsaPresignatureRecordV1,
    },
    /// Take SigningWorker ECDSA presignature material.
    SigningWorkerEcdsaPresignatureTake {
        /// ECDSA presignature lookup.
        lookup: CloudflareSigningWorkerEcdsaPresignatureLookupV1,
    },
    /// Remove expired SigningWorker ECDSA presignature records.
    SigningWorkerEcdsaPresignatureCleanupExpired {
        /// Cleanup request.
        cleanup: CloudflareExpiredStateCleanupRequestV1,
    },
    /// Store unbound SigningWorker ECDSA presignature material.
    SigningWorkerEcdsaPresignaturePoolPut {
        /// Unbound ECDSA presignature pool record.
        record: CloudflareSigningWorkerEcdsaPresignaturePoolRecordV1,
    },
    /// Reserve unbound SigningWorker ECDSA presignature material.
    SigningWorkerEcdsaPresignaturePoolTake {
        /// Unbound ECDSA presignature pool lookup.
        lookup: CloudflareSigningWorkerEcdsaPresignaturePoolLookupV1,
    },
    /// Remove expired unbound SigningWorker ECDSA presignature records.
    SigningWorkerEcdsaPresignaturePoolCleanupExpired {
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

    /// Creates a root-share startup metadata rewrap request.
    pub fn root_share_rewrap_startup_metadata(
        request: CloudflareRootShareRewrapRequestV1,
    ) -> RouterAbProtocolResult<Self> {
        let request = Self::RootShareRewrapStartupMetadata { request };
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

    /// Creates a Wallet Session budget grant put request.
    pub fn router_wallet_budget_put_grant(
        request: CloudflareRouterWalletBudgetPutGrantRequestV1,
    ) -> RouterAbProtocolResult<Self> {
        let request = Self::RouterWalletBudgetPutGrant { request };
        request.validate()?;
        Ok(request)
    }

    /// Creates a Wallet Session budget reserve request.
    pub fn router_wallet_budget_reserve(
        request: CloudflareRouterWalletBudgetReserveRequestV1,
    ) -> RouterAbProtocolResult<Self> {
        let request = Self::RouterWalletBudgetReserve { request };
        request.validate()?;
        Ok(request)
    }

    /// Creates a Wallet Session budget validate request.
    pub fn router_wallet_budget_validate(
        identity: CloudflareRouterWalletBudgetReservationIdentityV1,
    ) -> RouterAbProtocolResult<Self> {
        let request = Self::RouterWalletBudgetValidate { identity };
        request.validate()?;
        Ok(request)
    }

    /// Creates a Wallet Session budget commit request.
    pub fn router_wallet_budget_commit(
        identity: CloudflareRouterWalletBudgetReservationIdentityV1,
    ) -> RouterAbProtocolResult<Self> {
        let request = Self::RouterWalletBudgetCommit { identity };
        request.validate()?;
        Ok(request)
    }

    /// Creates a Wallet Session budget release request.
    pub fn router_wallet_budget_release(
        request: CloudflareRouterWalletBudgetReleaseRequestV1,
    ) -> RouterAbProtocolResult<Self> {
        let request = Self::RouterWalletBudgetRelease { request };
        request.validate()?;
        Ok(request)
    }

    /// Creates a Wallet Session budget status request.
    pub fn router_wallet_budget_status(
        request: CloudflareRouterWalletBudgetStatusRequestV1,
    ) -> RouterAbProtocolResult<Self> {
        let request = Self::RouterWalletBudgetStatus { request };
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

    /// Creates a direct SigningWorker activation delivery put request.
    pub fn signing_worker_direct_activation_put(
        delivery: CloudflareSigningWorkerDirectRecipientProofBundleActivationDeliveryV1,
    ) -> RouterAbProtocolResult<Self> {
        let request = Self::SigningWorkerDirectActivationPut { delivery };
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

    /// Creates a SigningWorker ECDSA presignature put request.
    pub fn signing_worker_ecdsa_presignature_put(
        record: CloudflareSigningWorkerEcdsaPresignatureRecordV1,
    ) -> RouterAbProtocolResult<Self> {
        let request = Self::SigningWorkerEcdsaPresignaturePut { record };
        request.validate()?;
        Ok(request)
    }

    /// Creates a SigningWorker ECDSA presignature take request.
    pub fn signing_worker_ecdsa_presignature_take(
        lookup: CloudflareSigningWorkerEcdsaPresignatureLookupV1,
    ) -> RouterAbProtocolResult<Self> {
        let request = Self::SigningWorkerEcdsaPresignatureTake { lookup };
        request.validate()?;
        Ok(request)
    }

    /// Creates an expired SigningWorker ECDSA presignature cleanup request.
    pub fn signing_worker_ecdsa_presignature_cleanup_expired(
        cleanup: CloudflareExpiredStateCleanupRequestV1,
    ) -> RouterAbProtocolResult<Self> {
        let request = Self::SigningWorkerEcdsaPresignatureCleanupExpired { cleanup };
        request.validate()?;
        Ok(request)
    }

    /// Creates an unbound SigningWorker ECDSA presignature pool put request.
    pub fn signing_worker_ecdsa_presignature_pool_put(
        record: CloudflareSigningWorkerEcdsaPresignaturePoolRecordV1,
    ) -> RouterAbProtocolResult<Self> {
        let request = Self::SigningWorkerEcdsaPresignaturePoolPut { record };
        request.validate()?;
        Ok(request)
    }

    /// Creates an unbound SigningWorker ECDSA presignature pool take request.
    pub fn signing_worker_ecdsa_presignature_pool_take(
        lookup: CloudflareSigningWorkerEcdsaPresignaturePoolLookupV1,
    ) -> RouterAbProtocolResult<Self> {
        let request = Self::SigningWorkerEcdsaPresignaturePoolTake { lookup };
        request.validate()?;
        Ok(request)
    }

    /// Creates an expired unbound SigningWorker ECDSA presignature pool cleanup request.
    pub fn signing_worker_ecdsa_presignature_pool_cleanup_expired(
        cleanup: CloudflareExpiredStateCleanupRequestV1,
    ) -> RouterAbProtocolResult<Self> {
        let request = Self::SigningWorkerEcdsaPresignaturePoolCleanupExpired { cleanup };
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
            Self::RootShareRewrapStartupMetadata { .. } => {
                CloudflareDurableObjectOperationKindV1::RootShareRewrapStartupMetadata
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
            Self::RouterWalletBudgetPutGrant { .. } => {
                CloudflareDurableObjectOperationKindV1::RouterWalletBudgetPutGrant
            }
            Self::RouterWalletBudgetReserve { .. } => {
                CloudflareDurableObjectOperationKindV1::RouterWalletBudgetReserve
            }
            Self::RouterWalletBudgetValidate { .. } => {
                CloudflareDurableObjectOperationKindV1::RouterWalletBudgetValidate
            }
            Self::RouterWalletBudgetCommit { .. } => {
                CloudflareDurableObjectOperationKindV1::RouterWalletBudgetCommit
            }
            Self::RouterWalletBudgetRelease { .. } => {
                CloudflareDurableObjectOperationKindV1::RouterWalletBudgetRelease
            }
            Self::RouterWalletBudgetStatus { .. } => {
                CloudflareDurableObjectOperationKindV1::RouterWalletBudgetStatus
            }
            Self::SigningWorkerOutputActivate { .. } => {
                CloudflareDurableObjectOperationKindV1::SigningWorkerOutputActivate
            }
            Self::SigningWorkerDirectActivationPut { .. } => {
                CloudflareDurableObjectOperationKindV1::SigningWorkerDirectActivationPut
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
            Self::SigningWorkerEcdsaPresignaturePut { .. } => {
                CloudflareDurableObjectOperationKindV1::SigningWorkerEcdsaPresignaturePut
            }
            Self::SigningWorkerEcdsaPresignatureTake { .. } => {
                CloudflareDurableObjectOperationKindV1::SigningWorkerEcdsaPresignatureTake
            }
            Self::SigningWorkerEcdsaPresignatureCleanupExpired { .. } => {
                CloudflareDurableObjectOperationKindV1::SigningWorkerEcdsaPresignatureCleanupExpired
            }
            Self::SigningWorkerEcdsaPresignaturePoolPut { .. } => {
                CloudflareDurableObjectOperationKindV1::SigningWorkerEcdsaPresignaturePoolPut
            }
            Self::SigningWorkerEcdsaPresignaturePoolTake { .. } => {
                CloudflareDurableObjectOperationKindV1::SigningWorkerEcdsaPresignaturePoolTake
            }
            Self::SigningWorkerEcdsaPresignaturePoolCleanupExpired { .. } => {
                CloudflareDurableObjectOperationKindV1::SigningWorkerEcdsaPresignaturePoolCleanupExpired
            }
        }
    }

    /// Returns the Durable Object scope required by this operation.
    pub fn required_scope(&self) -> CloudflareDurableObjectScopeV1 {
        match self {
            Self::RootShareHas { lookup } | Self::RootShareStartupMetadata { lookup } => {
                lookup.expected_scope()
            }
            Self::RootShareRewrapStartupMetadata { request } => request.lookup.expected_scope(),
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
            Self::RouterWalletBudgetPutGrant { .. }
            | Self::RouterWalletBudgetReserve { .. }
            | Self::RouterWalletBudgetValidate { .. }
            | Self::RouterWalletBudgetCommit { .. }
            | Self::RouterWalletBudgetRelease { .. }
            | Self::RouterWalletBudgetStatus { .. } => {
                CloudflareDurableObjectScopeV1::RouterWalletBudget
            }
            Self::SigningWorkerOutputActivate { .. }
            | Self::SigningWorkerOutputActiveStateGet { .. }
            | Self::SigningWorkerOutputMaterialGet { .. }
            | Self::SigningWorkerRound1Put { .. }
            | Self::SigningWorkerRound1Take { .. }
            | Self::SigningWorkerRound1CleanupExpired { .. }
            | Self::SigningWorkerEcdsaPresignaturePut { .. }
            | Self::SigningWorkerEcdsaPresignatureTake { .. }
            | Self::SigningWorkerEcdsaPresignatureCleanupExpired { .. }
            | Self::SigningWorkerEcdsaPresignaturePoolPut { .. }
            | Self::SigningWorkerEcdsaPresignaturePoolTake { .. }
            | Self::SigningWorkerEcdsaPresignaturePoolCleanupExpired { .. }
            | Self::SigningWorkerDirectActivationPut { .. } => {
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
            Self::RootShareRewrapStartupMetadata { request } => request.validate(),
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
            Self::RouterWalletBudgetPutGrant { request } => request.validate(),
            Self::RouterWalletBudgetReserve { request } => request.validate(),
            Self::RouterWalletBudgetValidate { identity }
            | Self::RouterWalletBudgetCommit { identity } => identity.validate(),
            Self::RouterWalletBudgetRelease { request } => request.validate(),
            Self::RouterWalletBudgetStatus { request } => request.validate(),
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
            Self::SigningWorkerEcdsaPresignaturePut { record } => record.validate(),
            Self::SigningWorkerEcdsaPresignatureTake { lookup } => lookup.validate(),
            Self::SigningWorkerEcdsaPresignatureCleanupExpired { cleanup } => cleanup.validate(),
            Self::SigningWorkerEcdsaPresignaturePoolPut { record } => record.validate(),
            Self::SigningWorkerEcdsaPresignaturePoolTake { lookup } => lookup.validate(),
            Self::SigningWorkerEcdsaPresignaturePoolCleanupExpired { cleanup } => {
                cleanup.validate()
            }
            Self::SigningWorkerDirectActivationPut { delivery } => delivery.validate(),
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
    /// Root-share startup metadata rewrap response.
    RootShareRewrapStartupMetadata {
        /// Rewrap receipt.
        receipt: CloudflareRootShareRewrapReceiptV1,
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
    /// Wallet Session budget grant put response.
    RouterWalletBudgetGrantPut {
        /// Current budget status.
        status: CloudflareRouterWalletBudgetStatusV1,
    },
    /// Wallet Session budget reserve response.
    RouterWalletBudgetReserved {
        /// Reservation id.
        reservation_id: String,
        /// Current budget status.
        status: CloudflareRouterWalletBudgetStatusV1,
    },
    /// Wallet Session budget validate response.
    RouterWalletBudgetValidated {
        /// Reservation id.
        reservation_id: String,
        /// Current budget status.
        status: CloudflareRouterWalletBudgetStatusV1,
    },
    /// Wallet Session budget commit response.
    RouterWalletBudgetCommitted {
        /// Reservation id.
        reservation_id: String,
        /// Current budget status.
        status: CloudflareRouterWalletBudgetStatusV1,
    },
    /// Wallet Session budget release response.
    RouterWalletBudgetReleased {
        /// Reservation id.
        reservation_id: String,
        /// Current budget status.
        status: CloudflareRouterWalletBudgetStatusV1,
    },
    /// Wallet Session budget status response.
    RouterWalletBudgetStatus {
        /// Current budget status.
        status: CloudflareRouterWalletBudgetStatusV1,
    },
    /// SigningWorker-output activation response.
    SigningWorkerOutputActivate {
        /// Activation receipt.
        receipt: CloudflareSigningWorkerOutputActivationReceiptV1,
    },
    /// Direct activation delivery storage response.
    SigningWorkerDirectActivationPut {
        /// Pending or ready direct activation outcome.
        outcome: Box<CloudflareSigningWorkerDirectRecipientProofBundleActivationPutOutcomeV1>,
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
    /// SigningWorker ECDSA presignature put response.
    SigningWorkerEcdsaPresignaturePut {
        /// Put receipt.
        receipt: CloudflareSigningWorkerEcdsaPresignaturePutReceiptV1,
    },
    /// SigningWorker ECDSA presignature take response.
    SigningWorkerEcdsaPresignatureTake {
        /// Stored ECDSA presignature record.
        record: CloudflareSigningWorkerEcdsaPresignatureRecordV1,
    },
    /// Expired SigningWorker ECDSA presignature cleanup response.
    SigningWorkerEcdsaPresignatureCleanupExpired {
        /// Cleanup report.
        report: CloudflareExpiredStateCleanupReportV1,
    },
    /// SigningWorker unbound ECDSA presignature pool put response.
    SigningWorkerEcdsaPresignaturePoolPut {
        /// Put receipt.
        receipt: CloudflareSigningWorkerEcdsaPresignaturePoolPutReceiptV1,
    },
    /// SigningWorker unbound ECDSA presignature pool take response.
    SigningWorkerEcdsaPresignaturePoolTake {
        /// Stored unbound ECDSA presignature pool record.
        record: CloudflareSigningWorkerEcdsaPresignaturePoolRecordV1,
    },
    /// Expired SigningWorker unbound ECDSA presignature pool cleanup response.
    SigningWorkerEcdsaPresignaturePoolCleanupExpired {
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

    /// Creates a root-share rewrap receipt response.
    pub fn root_share_rewrap_startup_metadata(
        receipt: CloudflareRootShareRewrapReceiptV1,
    ) -> RouterAbProtocolResult<Self> {
        let response = Self::RootShareRewrapStartupMetadata { receipt };
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

    /// Creates a Wallet Session budget grant put response.
    pub fn router_wallet_budget_grant_put(
        status: CloudflareRouterWalletBudgetStatusV1,
    ) -> RouterAbProtocolResult<Self> {
        let response = Self::RouterWalletBudgetGrantPut { status };
        response.validate()?;
        Ok(response)
    }

    /// Creates a Wallet Session budget reserve response.
    pub fn router_wallet_budget_reserved(
        reservation_id: impl Into<String>,
        status: CloudflareRouterWalletBudgetStatusV1,
    ) -> RouterAbProtocolResult<Self> {
        let response = Self::RouterWalletBudgetReserved {
            reservation_id: reservation_id.into(),
            status,
        };
        response.validate()?;
        Ok(response)
    }

    /// Creates a Wallet Session budget validate response.
    pub fn router_wallet_budget_validated(
        reservation_id: impl Into<String>,
        status: CloudflareRouterWalletBudgetStatusV1,
    ) -> RouterAbProtocolResult<Self> {
        let response = Self::RouterWalletBudgetValidated {
            reservation_id: reservation_id.into(),
            status,
        };
        response.validate()?;
        Ok(response)
    }

    /// Creates a Wallet Session budget commit response.
    pub fn router_wallet_budget_committed(
        reservation_id: impl Into<String>,
        status: CloudflareRouterWalletBudgetStatusV1,
    ) -> RouterAbProtocolResult<Self> {
        let response = Self::RouterWalletBudgetCommitted {
            reservation_id: reservation_id.into(),
            status,
        };
        response.validate()?;
        Ok(response)
    }

    /// Creates a Wallet Session budget release response.
    pub fn router_wallet_budget_released(
        reservation_id: impl Into<String>,
        status: CloudflareRouterWalletBudgetStatusV1,
    ) -> RouterAbProtocolResult<Self> {
        let response = Self::RouterWalletBudgetReleased {
            reservation_id: reservation_id.into(),
            status,
        };
        response.validate()?;
        Ok(response)
    }

    /// Creates a Wallet Session budget status response.
    pub fn router_wallet_budget_status(
        status: CloudflareRouterWalletBudgetStatusV1,
    ) -> RouterAbProtocolResult<Self> {
        let response = Self::RouterWalletBudgetStatus { status };
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

    /// Creates a direct activation delivery storage response.
    pub fn signing_worker_direct_activation_put(
        outcome: CloudflareSigningWorkerDirectRecipientProofBundleActivationPutOutcomeV1,
    ) -> RouterAbProtocolResult<Self> {
        let response = Self::SigningWorkerDirectActivationPut {
            outcome: Box::new(outcome),
        };
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

    /// Creates a SigningWorker ECDSA presignature put response.
    pub fn signing_worker_ecdsa_presignature_put(
        receipt: CloudflareSigningWorkerEcdsaPresignaturePutReceiptV1,
    ) -> RouterAbProtocolResult<Self> {
        let response = Self::SigningWorkerEcdsaPresignaturePut { receipt };
        response.validate()?;
        Ok(response)
    }

    /// Creates a SigningWorker ECDSA presignature take response.
    pub fn signing_worker_ecdsa_presignature_take(
        record: CloudflareSigningWorkerEcdsaPresignatureRecordV1,
    ) -> RouterAbProtocolResult<Self> {
        let response = Self::SigningWorkerEcdsaPresignatureTake { record };
        response.validate()?;
        Ok(response)
    }

    /// Creates an expired SigningWorker ECDSA presignature cleanup response.
    pub fn signing_worker_ecdsa_presignature_cleanup_expired(
        report: CloudflareExpiredStateCleanupReportV1,
    ) -> RouterAbProtocolResult<Self> {
        let response = Self::SigningWorkerEcdsaPresignatureCleanupExpired { report };
        response.validate()?;
        Ok(response)
    }

    /// Creates a SigningWorker unbound ECDSA presignature pool put response.
    pub fn signing_worker_ecdsa_presignature_pool_put(
        receipt: CloudflareSigningWorkerEcdsaPresignaturePoolPutReceiptV1,
    ) -> RouterAbProtocolResult<Self> {
        let response = Self::SigningWorkerEcdsaPresignaturePoolPut { receipt };
        response.validate()?;
        Ok(response)
    }

    /// Creates a SigningWorker unbound ECDSA presignature pool take response.
    pub fn signing_worker_ecdsa_presignature_pool_take(
        record: CloudflareSigningWorkerEcdsaPresignaturePoolRecordV1,
    ) -> RouterAbProtocolResult<Self> {
        let response = Self::SigningWorkerEcdsaPresignaturePoolTake { record };
        response.validate()?;
        Ok(response)
    }

    /// Creates an expired SigningWorker unbound ECDSA presignature pool cleanup response.
    pub fn signing_worker_ecdsa_presignature_pool_cleanup_expired(
        report: CloudflareExpiredStateCleanupReportV1,
    ) -> RouterAbProtocolResult<Self> {
        let response = Self::SigningWorkerEcdsaPresignaturePoolCleanupExpired { report };
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
            Self::RootShareRewrapStartupMetadata { .. } => {
                CloudflareDurableObjectOperationKindV1::RootShareRewrapStartupMetadata
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
            Self::RouterWalletBudgetGrantPut { .. } => {
                CloudflareDurableObjectOperationKindV1::RouterWalletBudgetPutGrant
            }
            Self::RouterWalletBudgetReserved { .. } => {
                CloudflareDurableObjectOperationKindV1::RouterWalletBudgetReserve
            }
            Self::RouterWalletBudgetValidated { .. } => {
                CloudflareDurableObjectOperationKindV1::RouterWalletBudgetValidate
            }
            Self::RouterWalletBudgetCommitted { .. } => {
                CloudflareDurableObjectOperationKindV1::RouterWalletBudgetCommit
            }
            Self::RouterWalletBudgetReleased { .. } => {
                CloudflareDurableObjectOperationKindV1::RouterWalletBudgetRelease
            }
            Self::RouterWalletBudgetStatus { .. } => {
                CloudflareDurableObjectOperationKindV1::RouterWalletBudgetStatus
            }
            Self::SigningWorkerOutputActivate { .. } => {
                CloudflareDurableObjectOperationKindV1::SigningWorkerOutputActivate
            }
            Self::SigningWorkerDirectActivationPut { .. } => {
                CloudflareDurableObjectOperationKindV1::SigningWorkerDirectActivationPut
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
            Self::SigningWorkerEcdsaPresignaturePut { .. } => {
                CloudflareDurableObjectOperationKindV1::SigningWorkerEcdsaPresignaturePut
            }
            Self::SigningWorkerEcdsaPresignatureTake { .. } => {
                CloudflareDurableObjectOperationKindV1::SigningWorkerEcdsaPresignatureTake
            }
            Self::SigningWorkerEcdsaPresignatureCleanupExpired { .. } => {
                CloudflareDurableObjectOperationKindV1::SigningWorkerEcdsaPresignatureCleanupExpired
            }
            Self::SigningWorkerEcdsaPresignaturePoolPut { .. } => {
                CloudflareDurableObjectOperationKindV1::SigningWorkerEcdsaPresignaturePoolPut
            }
            Self::SigningWorkerEcdsaPresignaturePoolTake { .. } => {
                CloudflareDurableObjectOperationKindV1::SigningWorkerEcdsaPresignaturePoolTake
            }
            Self::SigningWorkerEcdsaPresignaturePoolCleanupExpired { .. } => {
                CloudflareDurableObjectOperationKindV1::SigningWorkerEcdsaPresignaturePoolCleanupExpired
            }
        }
    }

    /// Validates response fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        match self {
            Self::RootShareHas { .. } => Ok(()),
            Self::RootShareStartupMetadata { metadata } => metadata.validate(),
            Self::RootShareRewrapStartupMetadata { receipt } => receipt.validate(),
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
            Self::RouterWalletBudgetGrantPut { status }
            | Self::RouterWalletBudgetStatus { status } => status.validate(),
            Self::RouterWalletBudgetReserved {
                reservation_id,
                status,
            }
            | Self::RouterWalletBudgetValidated {
                reservation_id,
                status,
            }
            | Self::RouterWalletBudgetCommitted {
                reservation_id,
                status,
            }
            | Self::RouterWalletBudgetReleased {
                reservation_id,
                status,
            } => {
                require_non_empty("wallet budget reservation_id", reservation_id)?;
                status.validate()
            }
            Self::SigningWorkerOutputActivate { receipt } => receipt.validate(),
            Self::SigningWorkerDirectActivationPut { outcome } => outcome.validate(),
            Self::SigningWorkerOutputActiveStateGet {
                active_signing_worker_state,
            } => active_signing_worker_state.validate(),
            Self::SigningWorkerOutputMaterialGet { material } => material.validate(),
            Self::SigningWorkerRound1Put { receipt } => receipt.validate(),
            Self::SigningWorkerRound1Take { record } => record.validate(),
            Self::SigningWorkerRound1CleanupExpired { report } => report.validate(),
            Self::SigningWorkerEcdsaPresignaturePut { receipt } => receipt.validate(),
            Self::SigningWorkerEcdsaPresignatureTake { record } => record.validate(),
            Self::SigningWorkerEcdsaPresignatureCleanupExpired { report } => report.validate(),
            Self::SigningWorkerEcdsaPresignaturePoolPut { receipt } => receipt.validate(),
            Self::SigningWorkerEcdsaPresignaturePoolTake { record } => record.validate(),
            Self::SigningWorkerEcdsaPresignaturePoolCleanupExpired { report } => report.validate(),
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
                Self::RootShareRewrapStartupMetadata { receipt },
                CloudflareDurableObjectRequestV1::RootShareRewrapStartupMetadata { request },
            ) => receipt.validate_for_request(request),
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
                Self::RouterWalletBudgetGrantPut { status },
                CloudflareDurableObjectRequestV1::RouterWalletBudgetPutGrant { request },
            ) => {
                if status.signing_grant_id == request.signing_grant_id {
                    Ok(())
                } else {
                    Err(RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                        "wallet budget grant response does not match request",
                    ))
                }
            }
            (
                Self::RouterWalletBudgetStatus { status },
                CloudflareDurableObjectRequestV1::RouterWalletBudgetStatus { request },
            ) => {
                if status.signing_grant_id == request.signing_grant_id {
                    Ok(())
                } else {
                    Err(RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                        "wallet budget response grant id does not match request",
                    ))
                }
            }
            (
                Self::RouterWalletBudgetReserved {
                    reservation_id,
                    status,
                },
                CloudflareDurableObjectRequestV1::RouterWalletBudgetReserve { request },
            ) => {
                if status.signing_grant_id == request.signing_grant_id
                    && reservation_id == &request.reservation_id()
                {
                    Ok(())
                } else {
                    Err(RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                        "wallet budget reserve response does not match request",
                    ))
                }
            }
            (
                Self::RouterWalletBudgetValidated {
                    reservation_id,
                    status,
                },
                CloudflareDurableObjectRequestV1::RouterWalletBudgetValidate { identity },
            )
            | (
                Self::RouterWalletBudgetCommitted {
                    reservation_id,
                    status,
                },
                CloudflareDurableObjectRequestV1::RouterWalletBudgetCommit { identity },
            ) => {
                if status.signing_grant_id == identity.signing_grant_id
                    && reservation_id == &identity.reservation_id
                {
                    Ok(())
                } else {
                    Err(RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                        "wallet budget reservation response does not match request",
                    ))
                }
            }
            (
                Self::RouterWalletBudgetReleased {
                    reservation_id,
                    status,
                },
                CloudflareDurableObjectRequestV1::RouterWalletBudgetRelease { request },
            ) => {
                if status.signing_grant_id == request.signing_grant_id
                    && reservation_id == &request.reservation_id
                {
                    Ok(())
                } else {
                    Err(RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                        "wallet budget release response does not match request",
                    ))
                }
            }
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
                Self::SigningWorkerDirectActivationPut { outcome },
                CloudflareDurableObjectRequestV1::SigningWorkerDirectActivationPut { delivery },
            ) => outcome.validate_for_delivery(delivery),
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
            (
                Self::SigningWorkerEcdsaPresignaturePut { receipt },
                CloudflareDurableObjectRequestV1::SigningWorkerEcdsaPresignaturePut { record },
            ) => receipt.validate_for_record(record),
            (
                Self::SigningWorkerEcdsaPresignatureTake { record },
                CloudflareDurableObjectRequestV1::SigningWorkerEcdsaPresignatureTake { lookup },
            ) => record.validate_for_lookup(lookup),
            (
                Self::SigningWorkerEcdsaPresignaturePoolPut { receipt },
                CloudflareDurableObjectRequestV1::SigningWorkerEcdsaPresignaturePoolPut { record },
            ) => receipt.validate_for_record(record),
            (
                Self::SigningWorkerEcdsaPresignaturePoolTake { record },
                CloudflareDurableObjectRequestV1::SigningWorkerEcdsaPresignaturePoolTake { lookup },
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
            CloudflareDurableObjectRequestV1::RootShareRewrapStartupMetadata { request } => {
                format!(
                    "{}root-share/{}/{}/{}",
                    self.binding.key_prefix,
                    request.lookup.signer_set_id,
                    request.lookup.signer_role.as_str(),
                    request.lookup.root_share_epoch.as_str()
                )
            }
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
            CloudflareDurableObjectRequestV1::RouterWalletBudgetPutGrant { request } => {
                format!(
                    "{}wallet-budget/{}",
                    self.binding.key_prefix, request.signing_grant_id
                )
            }
            CloudflareDurableObjectRequestV1::RouterWalletBudgetReserve { request } => {
                format!(
                    "{}wallet-budget/{}",
                    self.binding.key_prefix, request.signing_grant_id
                )
            }
            CloudflareDurableObjectRequestV1::RouterWalletBudgetValidate { identity }
            | CloudflareDurableObjectRequestV1::RouterWalletBudgetCommit { identity } => {
                format!(
                    "{}wallet-budget/{}",
                    self.binding.key_prefix, identity.signing_grant_id
                )
            }
            CloudflareDurableObjectRequestV1::RouterWalletBudgetRelease { request } => {
                format!(
                    "{}wallet-budget/{}",
                    self.binding.key_prefix, request.signing_grant_id
                )
            }
            CloudflareDurableObjectRequestV1::RouterWalletBudgetStatus { request } => {
                format!(
                    "{}wallet-budget/{}",
                    self.binding.key_prefix, request.signing_grant_id
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
            CloudflareDurableObjectRequestV1::SigningWorkerDirectActivationPut {
                delivery,
            } => format!(
                "{}signing-worker-direct-activation/{}/{}",
                self.binding.key_prefix,
                delivery.activation_context.lifecycle().lifecycle_id,
                digest_hex(delivery.activation_context.transcript_digest())
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
            CloudflareDurableObjectRequestV1::SigningWorkerEcdsaPresignaturePut { record } => {
                format!(
                    "{}signing-worker-ecdsa-presignature/{}/{}/{}/{}",
                    self.binding.key_prefix,
                    record.active_signing_worker_state.account_id,
                    record.active_signing_worker_state.session_id,
                    record.active_signing_worker_state.signing_worker.server_id,
                    record.server_presignature_id
                )
            }
            CloudflareDurableObjectRequestV1::SigningWorkerEcdsaPresignatureTake { lookup } => {
                format!(
                    "{}signing-worker-ecdsa-presignature/{}/{}/{}/{}",
                    self.binding.key_prefix,
                    lookup.active_signing_worker_state.account_id,
                    lookup.active_signing_worker_state.session_id,
                    lookup.active_signing_worker_state.signing_worker.server_id,
                    lookup.server_presignature_id
                )
            }
            CloudflareDurableObjectRequestV1::SigningWorkerEcdsaPresignatureCleanupExpired {
                ..
            } => self.signing_worker_ecdsa_presignature_storage_prefix(),
            CloudflareDurableObjectRequestV1::SigningWorkerEcdsaPresignaturePoolPut {
                record,
            } => {
                format!(
                    "{}signing-worker-ecdsa-presignature-pool/{}/{}/{}/{}",
                    self.binding.key_prefix,
                    record.active_signing_worker_state.account_id,
                    record.active_signing_worker_state.session_id,
                    record.active_signing_worker_state.signing_worker.server_id,
                    record.server_presignature_id
                )
            }
            CloudflareDurableObjectRequestV1::SigningWorkerEcdsaPresignaturePoolTake {
                lookup,
            } => {
                format!(
                    "{}signing-worker-ecdsa-presignature-pool/{}/{}/{}/{}",
                    self.binding.key_prefix,
                    lookup.active_signing_worker_state.account_id,
                    lookup.active_signing_worker_state.session_id,
                    lookup.active_signing_worker_state.signing_worker.server_id,
                    lookup.server_presignature_id
                )
            }
            CloudflareDurableObjectRequestV1::SigningWorkerEcdsaPresignaturePoolCleanupExpired {
                ..
            } => self.signing_worker_ecdsa_presignature_pool_storage_prefix(),
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

    /// Returns the prefix used by Wallet Session budget storage records.
    pub fn wallet_budget_storage_prefix(&self) -> String {
        format!("{}wallet-budget/", self.binding.key_prefix)
    }

    /// Returns the prefix used by SigningWorker round-1 storage records.
    pub fn signing_worker_round1_storage_prefix(&self) -> String {
        format!("{}signing-worker-round1/", self.binding.key_prefix)
    }

    /// Returns the prefix used by SigningWorker ECDSA presignature storage records.
    pub fn signing_worker_ecdsa_presignature_storage_prefix(&self) -> String {
        format!(
            "{}signing-worker-ecdsa-presignature/",
            self.binding.key_prefix
        )
    }

    /// Returns the prefix used by unbound SigningWorker ECDSA presignature pool records.
    pub fn signing_worker_ecdsa_presignature_pool_storage_prefix(&self) -> String {
        format!(
            "{}signing-worker-ecdsa-presignature-pool/",
            self.binding.key_prefix
        )
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

    /// Stores root-share startup metadata by storage key.
    fn put_root_share_startup_metadata(
        &mut self,
        storage_key: &str,
        metadata: CloudflareRootShareStartupMetadataV1,
    ) -> RouterAbProtocolResult<()>;

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

    /// Reads a Wallet Session budget grant by storage key.
    fn router_wallet_budget(
        &self,
        storage_key: &str,
    ) -> RouterAbProtocolResult<Option<CloudflareRouterWalletBudgetGrantRecordV1>>;

    /// Stores a Wallet Session budget grant by storage key.
    fn put_router_wallet_budget(
        &mut self,
        storage_key: &str,
        record: CloudflareRouterWalletBudgetGrantRecordV1,
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

    /// Reads a pending direct SigningWorker activation delivery by storage key.
    fn signing_worker_direct_activation(
        &self,
        storage_key: &str,
    ) -> RouterAbProtocolResult<
        Option<CloudflareSigningWorkerDirectRecipientProofBundleActivationPendingRecordV1>,
    >;

    /// Stores a pending direct SigningWorker activation delivery.
    fn put_signing_worker_direct_activation(
        &mut self,
        storage_key: &str,
        record: CloudflareSigningWorkerDirectRecipientProofBundleActivationPendingRecordV1,
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

    /// Reads SigningWorker ECDSA presignature material by storage key.
    fn signing_worker_ecdsa_presignature(
        &self,
        storage_key: &str,
    ) -> RouterAbProtocolResult<Option<CloudflareSigningWorkerEcdsaPresignatureRecordV1>>;

    /// Stores SigningWorker ECDSA presignature material.
    fn put_signing_worker_ecdsa_presignature(
        &mut self,
        storage_key: &str,
        record: CloudflareSigningWorkerEcdsaPresignatureRecordV1,
    ) -> RouterAbProtocolResult<()>;

    /// Removes and returns SigningWorker ECDSA presignature material.
    fn take_signing_worker_ecdsa_presignature(
        &mut self,
        storage_key: &str,
    ) -> RouterAbProtocolResult<Option<CloudflareSigningWorkerEcdsaPresignatureRecordV1>>;

    /// Removes expired SigningWorker ECDSA presignature records.
    fn cleanup_expired_signing_worker_ecdsa_presignature_records(
        &mut self,
        now_unix_ms: u64,
    ) -> RouterAbProtocolResult<CloudflareExpiredStateCleanupReportV1>;

    /// Reads unbound SigningWorker ECDSA presignature pool material by storage key.
    fn signing_worker_ecdsa_presignature_pool(
        &self,
        storage_key: &str,
    ) -> RouterAbProtocolResult<Option<CloudflareSigningWorkerEcdsaPresignaturePoolRecordV1>>;

    /// Stores unbound SigningWorker ECDSA presignature pool material.
    fn put_signing_worker_ecdsa_presignature_pool(
        &mut self,
        storage_key: &str,
        record: CloudflareSigningWorkerEcdsaPresignaturePoolRecordV1,
    ) -> RouterAbProtocolResult<()>;

    /// Removes and returns unbound SigningWorker ECDSA presignature pool material.
    fn take_signing_worker_ecdsa_presignature_pool(
        &mut self,
        storage_key: &str,
    ) -> RouterAbProtocolResult<Option<CloudflareSigningWorkerEcdsaPresignaturePoolRecordV1>>;

    /// Removes expired unbound SigningWorker ECDSA presignature pool records.
    fn cleanup_expired_signing_worker_ecdsa_presignature_pool_records(
        &mut self,
        now_unix_ms: u64,
    ) -> RouterAbProtocolResult<CloudflareExpiredStateCleanupReportV1>;
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
        | CloudflareDurableObjectScopeV1::RouterAbuse
        | CloudflareDurableObjectScopeV1::RouterWalletBudget => Ok(CloudflareWorkerRoleV1::Router),
        CloudflareDurableObjectScopeV1::SignerRootShare {
            role: Role::SignerA,
        } => Ok(CloudflareWorkerRoleV1::DeriverA),
        CloudflareDurableObjectScopeV1::SignerRootShare {
            role: Role::SignerB,
        } => Ok(CloudflareWorkerRoleV1::DeriverB),
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
fn cloudflare_signing_worker_ecdsa_presignature_expires_at_ms_v1(
    record: &CloudflareSigningWorkerEcdsaPresignatureRecordV1,
) -> u64 {
    record.expires_at_ms
}

#[cfg(feature = "workers-rs")]
fn cloudflare_signing_worker_ecdsa_presignature_pool_expires_at_ms_v1(
    record: &CloudflareSigningWorkerEcdsaPresignaturePoolRecordV1,
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

fn validate_compressed_secp256k1_point_b64u_v1(
    field_name: &str,
    value: &str,
) -> RouterAbProtocolResult<()> {
    let bytes = validate_base64url_fixed_len_v1(field_name, value, 33)?;
    if matches!(bytes[0], 0x02 | 0x03) {
        return Ok(());
    }
    Err(RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::MalformedWirePayload,
        format!("{field_name} must use a compressed secp256k1 point prefix"),
    ))
}

fn validate_base64url_fixed_len_v1(
    field_name: &str,
    value: &str,
    expected_len: usize,
) -> RouterAbProtocolResult<Vec<u8>> {
    require_non_empty(field_name, value)?;
    let bytes = URL_SAFE_NO_PAD.decode(value).map_err(|err| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("{field_name} must be unpadded base64url: {err}"),
        )
    })?;
    if bytes.len() == expected_len {
        return Ok(bytes);
    }
    Err(RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::MalformedWirePayload,
        format!("{field_name} must decode to {expected_len} bytes"),
    ))
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

fn router_wallet_budget_operation_key_v1(
    signing_worker_id: &str,
    operation_id: &str,
    request_digest: PublicDigest32,
) -> String {
    format!(
        "{}/{}/{}",
        signing_worker_id,
        operation_id,
        digest_hex(request_digest)
    )
}

fn router_wallet_budget_reservation_id_v1(
    signing_worker_id: &str,
    operation_id: &str,
    request_digest: PublicDigest32,
) -> String {
    format!(
        "wbudg-res/{}",
        router_wallet_budget_operation_key_v1(signing_worker_id, operation_id, request_digest)
    )
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
