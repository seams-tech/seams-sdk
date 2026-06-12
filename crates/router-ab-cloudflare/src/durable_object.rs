use std::collections::BTreeMap;

use router_ab_core::{PublicDigest32, Role, RootShareEpoch};
use router_ab_core::{
    RelayerActivationPayloadV1, RouterAbLifecycleStateV1, RouterAbProtocolError,
    RouterAbProtocolErrorCode, RouterAbProtocolResult,
};
#[cfg(feature = "workers-rs")]
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::{
    CloudflareDurableObjectBindingV1, CloudflareDurableObjectScopeV1, CloudflareWorkerRoleV1,
};
#[cfg(feature = "workers-rs")]
use crate::{
    ROUTER_LIFECYCLE_DO_BINDING_ENV, ROUTER_LIFECYCLE_DO_KEY_PREFIX_ENV,
    ROUTER_LIFECYCLE_DO_OBJECT_ENV, ROUTER_REPLAY_DO_BINDING_ENV, ROUTER_REPLAY_DO_KEY_PREFIX_ENV,
    ROUTER_REPLAY_DO_OBJECT_ENV, SIGNER_A_RELAYER_OUTPUT_DO_BINDING_ENV,
    SIGNER_A_RELAYER_OUTPUT_DO_KEY_PREFIX_ENV, SIGNER_A_RELAYER_OUTPUT_DO_OBJECT_ENV,
    SIGNER_A_ROOT_SHARE_DO_BINDING_ENV, SIGNER_A_ROOT_SHARE_DO_KEY_PREFIX_ENV,
    SIGNER_A_ROOT_SHARE_DO_OBJECT_ENV, SIGNER_B_ROOT_SHARE_DO_BINDING_ENV,
    SIGNER_B_ROOT_SHARE_DO_KEY_PREFIX_ENV, SIGNER_B_ROOT_SHARE_DO_OBJECT_ENV,
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

/// Signer A relayer-output Durable Object class.
#[cfg(feature = "workers-rs")]
#[worker::durable_object(fetch)]
pub struct RouterAbSignerARelayerOutputDurableObject {
    state: worker::State,
    env: worker::Env,
}

#[cfg(feature = "workers-rs")]
impl worker::DurableObject for RouterAbSignerARelayerOutputDurableObject {
    fn new(state: worker::State, env: worker::Env) -> Self {
        Self { state, env }
    }

    async fn fetch(&self, request: worker::Request) -> worker::Result<worker::Response> {
        handle_cloudflare_durable_object_class_fetch_v1(
            CloudflareDurableObjectScopeV1::signer_a_relayer_output(),
            SIGNER_A_RELAYER_OUTPUT_DO_BINDING_ENV,
            SIGNER_A_RELAYER_OUTPUT_DO_OBJECT_ENV,
            SIGNER_A_RELAYER_OUTPUT_DO_KEY_PREFIX_ENV,
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
    /// Persist public Router lifecycle state.
    RouterLifecyclePutPublicState,
    /// Activate relayer-output material for the designated relayer.
    RelayerOutputActivate,
}

impl CloudflareDurableObjectOperationKindV1 {
    /// Returns the stable operation label.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RootShareHas => "root_share.has",
            Self::RootShareStartupMetadata => "root_share.startup_metadata",
            Self::RouterReplayReserve => "router_replay.reserve",
            Self::RouterLifecyclePutPublicState => "router_lifecycle.put_public_state",
            Self::RelayerOutputActivate => "relayer_output.activate",
        }
    }

    /// Returns the internal HTTP path used by the Worker-to-Durable-Object call.
    pub fn path(self) -> &'static str {
        match self {
            Self::RootShareHas => "/router-ab/do/v1/root-share/has",
            Self::RootShareStartupMetadata => "/router-ab/do/v1/root-share/startup-metadata",
            Self::RouterReplayReserve => "/router-ab/do/v1/router-replay/reserve",
            Self::RouterLifecyclePutPublicState => "/router-ab/do/v1/router-lifecycle/put",
            Self::RelayerOutputActivate => "/router-ab/do/v1/relayer-output/activate",
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

/// Relayer-output activation receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareRelayerOutputActivationReceiptV1 {
    /// Lifecycle id activated by the relayer.
    pub lifecycle_id: String,
    /// Relayer id that accepted activation.
    pub relayer_id: String,
    /// Public transcript digest.
    pub transcript_digest: PublicDigest32,
    /// Whether activation was stored.
    pub activated: bool,
}

impl CloudflareRelayerOutputActivationReceiptV1 {
    /// Creates a validated relayer-output activation receipt.
    pub fn new(
        lifecycle_id: impl Into<String>,
        relayer_id: impl Into<String>,
        transcript_digest: PublicDigest32,
        activated: bool,
    ) -> RouterAbProtocolResult<Self> {
        let receipt = Self {
            lifecycle_id: lifecycle_id.into(),
            relayer_id: relayer_id.into(),
            transcript_digest,
            activated,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    /// Validates relayer-output activation receipt fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("lifecycle_id", &self.lifecycle_id)?;
        require_non_empty("relayer_id", &self.relayer_id)
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
    /// Store public lifecycle state.
    RouterLifecyclePutPublicState {
        /// Public lifecycle state.
        state: RouterAbLifecycleStateV1,
    },
    /// Activate relayer-output material.
    RelayerOutputActivate {
        /// Relayer activation payload.
        activation: RelayerActivationPayloadV1,
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

    /// Creates a public lifecycle persistence request.
    pub fn router_lifecycle_put_public_state(
        state: RouterAbLifecycleStateV1,
    ) -> RouterAbProtocolResult<Self> {
        let request = Self::RouterLifecyclePutPublicState { state };
        request.validate()?;
        Ok(request)
    }

    /// Creates a relayer-output activation request.
    pub fn relayer_output_activate(
        activation: RelayerActivationPayloadV1,
    ) -> RouterAbProtocolResult<Self> {
        let request = Self::RelayerOutputActivate { activation };
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
            Self::RouterLifecyclePutPublicState { .. } => {
                CloudflareDurableObjectOperationKindV1::RouterLifecyclePutPublicState
            }
            Self::RelayerOutputActivate { .. } => {
                CloudflareDurableObjectOperationKindV1::RelayerOutputActivate
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
            Self::RouterLifecyclePutPublicState { .. } => {
                CloudflareDurableObjectScopeV1::RouterLifecycle
            }
            Self::RelayerOutputActivate { .. } => {
                CloudflareDurableObjectScopeV1::signer_a_relayer_output()
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
            Self::RouterLifecyclePutPublicState { state } => validate_lifecycle_state(state),
            Self::RelayerOutputActivate { activation } => activation.validate(),
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
    /// Lifecycle persistence response.
    RouterLifecyclePutPublicState {
        /// Lifecycle receipt.
        receipt: CloudflareLifecyclePutReceiptV1,
    },
    /// Relayer-output activation response.
    RelayerOutputActivate {
        /// Activation receipt.
        receipt: CloudflareRelayerOutputActivationReceiptV1,
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

    /// Creates a lifecycle persistence response.
    pub fn router_lifecycle_put_public_state(
        receipt: CloudflareLifecyclePutReceiptV1,
    ) -> RouterAbProtocolResult<Self> {
        let response = Self::RouterLifecyclePutPublicState { receipt };
        response.validate()?;
        Ok(response)
    }

    /// Creates a relayer-output activation response.
    pub fn relayer_output_activate(
        receipt: CloudflareRelayerOutputActivationReceiptV1,
    ) -> RouterAbProtocolResult<Self> {
        let response = Self::RelayerOutputActivate { receipt };
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
            Self::RouterLifecyclePutPublicState { .. } => {
                CloudflareDurableObjectOperationKindV1::RouterLifecyclePutPublicState
            }
            Self::RelayerOutputActivate { .. } => {
                CloudflareDurableObjectOperationKindV1::RelayerOutputActivate
            }
        }
    }

    /// Validates response fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        match self {
            Self::RootShareHas { .. } => Ok(()),
            Self::RootShareStartupMetadata { metadata } => metadata.validate(),
            Self::RouterReplayReserve { response } => response.validate(),
            Self::RouterLifecyclePutPublicState { receipt } => receipt.validate(),
            Self::RelayerOutputActivate { receipt } => receipt.validate(),
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
                Self::RelayerOutputActivate { receipt },
                CloudflareDurableObjectRequestV1::RelayerOutputActivate { activation },
            ) => {
                if receipt.lifecycle_id == activation.lifecycle_id
                    && receipt.relayer_id == activation.relayer.relayer_id
                    && receipt.transcript_digest == activation.transcript_digest
                {
                    Ok(())
                } else {
                    Err(RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                        "relayer activation receipt does not match request",
                    ))
                }
            }
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
            CloudflareDurableObjectRequestV1::RouterLifecyclePutPublicState { state } => {
                format!(
                    "{}lifecycle/{}",
                    self.binding.key_prefix,
                    state.scope().lifecycle_id
                )
            }
            CloudflareDurableObjectRequestV1::RelayerOutputActivate { activation } => format!(
                "{}relayer-output/{}/{}",
                self.binding.key_prefix,
                activation.lifecycle_id,
                digest_hex(activation.transcript_digest)
            ),
        }
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

    /// Stores public Router lifecycle state.
    fn put_router_lifecycle_state(
        &mut self,
        storage_key: &str,
        state: RouterAbLifecycleStateV1,
    ) -> RouterAbProtocolResult<()>;

    /// Reads relayer-output activation by storage key.
    fn relayer_output_activation(
        &self,
        storage_key: &str,
    ) -> RouterAbProtocolResult<Option<RelayerActivationPayloadV1>>;

    /// Stores relayer-output activation.
    fn put_relayer_output_activation(
        &mut self,
        storage_key: &str,
        activation: RelayerActivationPayloadV1,
    ) -> RouterAbProtocolResult<()>;
}

/// Deterministic in-memory Durable Object storage used by tests and local checks.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CloudflareDurableObjectMemoryStorageV1 {
    root_share_metadata: BTreeMap<String, CloudflareRootShareStartupMetadataV1>,
    replay_by_request_id: BTreeMap<String, CloudflareReplayReserveRequestV1>,
    replay_by_storage_key: BTreeMap<String, CloudflareReplayReserveRequestV1>,
    lifecycle_states: BTreeMap<String, RouterAbLifecycleStateV1>,
    relayer_activations: BTreeMap<String, RelayerActivationPayloadV1>,
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

    /// Reads a stored lifecycle state for tests and local smoke checks.
    pub fn lifecycle_state(&self, storage_key: &str) -> Option<&RouterAbLifecycleStateV1> {
        self.lifecycle_states.get(storage_key)
    }

    /// Reads a stored relayer activation for tests and local smoke checks.
    pub fn relayer_activation(&self, storage_key: &str) -> Option<&RelayerActivationPayloadV1> {
        self.relayer_activations.get(storage_key)
    }

    /// Reads a transcript-bound replay reservation for tests and local smoke checks.
    pub fn replay_reservation(
        &self,
        storage_key: &str,
    ) -> Option<&CloudflareReplayReserveRequestV1> {
        self.replay_by_storage_key.get(storage_key)
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

    fn relayer_output_activation(
        &self,
        storage_key: &str,
    ) -> RouterAbProtocolResult<Option<RelayerActivationPayloadV1>> {
        require_non_empty("storage_key", storage_key)?;
        Ok(self.relayer_activations.get(storage_key).cloned())
    }

    fn put_relayer_output_activation(
        &mut self,
        storage_key: &str,
        activation: RelayerActivationPayloadV1,
    ) -> RouterAbProtocolResult<()> {
        require_non_empty("storage_key", storage_key)?;
        activation.validate()?;
        self.relayer_activations
            .insert(storage_key.to_owned(), activation);
        Ok(())
    }
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
        CloudflareDurableObjectRequestV1::RouterLifecyclePutPublicState { state } => {
            storage.put_router_lifecycle_state(&storage_key, state.clone())?;
            CloudflareDurableObjectResponseV1::router_lifecycle_put_public_state(
                CloudflareLifecyclePutReceiptV1::new(state.scope().lifecycle_id.clone(), true)?,
            )?
        }
        CloudflareDurableObjectRequestV1::RelayerOutputActivate { activation } => {
            let activated = match storage.relayer_output_activation(&storage_key)? {
                Some(existing) => {
                    if existing == *activation {
                        false
                    } else {
                        return Err(RouterAbProtocolError::new(
                            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                            "relayer-output activation conflicts with existing activation",
                        ));
                    }
                }
                None => {
                    storage.put_relayer_output_activation(&storage_key, activation.clone())?;
                    true
                }
            };
            CloudflareDurableObjectResponseV1::relayer_output_activate(
                CloudflareRelayerOutputActivationReceiptV1::new(
                    activation.lifecycle_id.clone(),
                    activation.relayer.relayer_id.clone(),
                    activation.transcript_digest,
                    activated,
                )?,
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
        CloudflareDurableObjectRequestV1::RouterLifecyclePutPublicState { state } => {
            worker_storage_put(storage, &storage_key, state.clone(), call.operation_kind()).await?;
            CloudflareDurableObjectResponseV1::router_lifecycle_put_public_state(
                CloudflareLifecyclePutReceiptV1::new(state.scope().lifecycle_id.clone(), true)?,
            )?
        }
        CloudflareDurableObjectRequestV1::RelayerOutputActivate { activation } => {
            let activated = match worker_storage_get::<RelayerActivationPayloadV1>(
                storage,
                &storage_key,
                call.operation_kind(),
            )
            .await?
            {
                Some(existing) => {
                    if existing == *activation {
                        false
                    } else {
                        return Err(RouterAbProtocolError::new(
                            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                            "relayer-output activation conflicts with existing activation",
                        ));
                    }
                }
                None => {
                    worker_storage_put(
                        storage,
                        &storage_key,
                        activation.clone(),
                        call.operation_kind(),
                    )
                    .await?;
                    true
                }
            };
            CloudflareDurableObjectResponseV1::relayer_output_activate(
                CloudflareRelayerOutputActivationReceiptV1::new(
                    activation.lifecycle_id.clone(),
                    activation.relayer.relayer_id.clone(),
                    activation.transcript_digest,
                    activated,
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
    state.scope().validate()?;
    match state {
        RouterAbLifecycleStateV1::Requested { .. }
        | RouterAbLifecycleStateV1::GateDeferred { .. }
        | RouterAbLifecycleStateV1::GateRejected { .. }
        | RouterAbLifecycleStateV1::AuthorityVerifiedFallback { .. } => Ok(()),
        RouterAbLifecycleStateV1::GateAccepted { request_id, .. } => {
            require_non_empty("request_id", request_id)
        }
        RouterAbLifecycleStateV1::GateReusingExisting {
            request_id,
            existing_lifecycle_id,
            ..
        } => {
            require_non_empty("request_id", request_id)?;
            require_non_empty("existing_lifecycle_id", existing_lifecycle_id)
        }
    }
}

#[cfg(feature = "workers-rs")]
fn worker_role_for_durable_object_scope(
    scope: CloudflareDurableObjectScopeV1,
) -> RouterAbProtocolResult<CloudflareWorkerRoleV1> {
    scope.validate()?;
    match scope {
        CloudflareDurableObjectScopeV1::RouterReplay
        | CloudflareDurableObjectScopeV1::RouterLifecycle => Ok(CloudflareWorkerRoleV1::Router),
        CloudflareDurableObjectScopeV1::SignerRootShare {
            role: Role::SignerA,
        }
        | CloudflareDurableObjectScopeV1::RelayerOutput {
            owner_role: Role::SignerA,
        } => Ok(CloudflareWorkerRoleV1::SignerARelayer),
        CloudflareDurableObjectScopeV1::SignerRootShare {
            role: Role::SignerB,
        } => Ok(CloudflareWorkerRoleV1::SignerB),
        CloudflareDurableObjectScopeV1::SignerRootShare { role }
        | CloudflareDurableObjectScopeV1::RelayerOutput { owner_role: role } => {
            Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidRole,
                format!(
                    "no Router A/B Worker role can own Durable Object scope for {}",
                    role.as_str()
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
