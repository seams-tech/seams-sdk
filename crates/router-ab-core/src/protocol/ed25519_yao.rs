use serde::{de::Error as _, Deserialize, Deserializer, Serialize};

use crate::derivation::RootShareEpoch;
use crate::protocol::error::{
    RouterAbProtocolError, RouterAbProtocolErrorCode, RouterAbProtocolResult,
};
use crate::protocol::gate::ExpensiveWorkKindV1;
use crate::protocol::lifecycle::LifecycleScopeV1;

/// Public SDK Router path for Ed25519 Yao registration admission.
pub const ROUTER_AB_ED25519_YAO_REGISTRATION_ADMISSION_PATH_V1: &str =
    "/router-ab/ed25519/yao/registration/admit";
/// Public SDK Router path for executing an admitted Ed25519 Yao registration.
pub const ROUTER_AB_ED25519_YAO_REGISTRATION_EXECUTE_PATH_V1: &str =
    "/router-ab/ed25519/yao/registration/execute";
/// Public SDK Router path for Ed25519 Yao exact-seed export admission.
pub const ROUTER_AB_ED25519_YAO_EXPORT_ADMISSION_PATH_V1: &str =
    "/router-ab/ed25519/yao/export/admit";
/// Public SDK Router path for executing an admitted Ed25519 Yao exact-seed export.
pub const ROUTER_AB_ED25519_YAO_EXPORT_EXECUTE_PATH_V1: &str =
    "/router-ab/ed25519/yao/export/execute";
/// Maximum ciphertext size accepted by compact Ed25519 Yao control envelopes.
pub const ED25519_YAO_CONTROL_CIPHERTEXT_MAX_BYTES_V1: usize = 64 * 1024;

/// Fixed Ed25519 Yao circuit family selected by a lifecycle operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ed25519YaoCircuitFamilyV1 {
    /// Produces disjoint Client and SigningWorker scalar shares.
    Activation,
    /// Produces Client-recipient seed shares for explicit export.
    Export,
}

/// Product lifecycle operation admitted to the fixed Yao circuit families.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ed25519YaoOperationV1 {
    /// Initial registration and activation.
    Registration,
    /// Recovery into fresh recipient shares.
    Recovery,
    /// Refresh into the next share epoch.
    Refresh,
    /// Explicitly authorized seed export.
    Export,
}

impl Ed25519YaoOperationV1 {
    /// Returns the only circuit family valid for this operation.
    pub const fn circuit_family(self) -> Ed25519YaoCircuitFamilyV1 {
        match self {
            Self::Registration | Self::Recovery | Self::Refresh => {
                Ed25519YaoCircuitFamilyV1::Activation
            }
            Self::Export => Ed25519YaoCircuitFamilyV1::Export,
        }
    }

    const fn work_kind(self) -> ExpensiveWorkKindV1 {
        match self {
            Self::Registration => ExpensiveWorkKindV1::RegistrationPrepare,
            Self::Recovery => ExpensiveWorkKindV1::Recovery,
            Self::Refresh => ExpensiveWorkKindV1::ServerShareRefresh,
            Self::Export => ExpensiveWorkKindV1::KeyExport,
        }
    }
}

/// Nonzero transcript session identifier derived at the Router admission boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct Ed25519YaoSessionIdV1([u8; 32]);

impl Ed25519YaoSessionIdV1 {
    /// Parses a nonzero fixed-width session identifier.
    pub fn new(bytes: [u8; 32]) -> RouterAbProtocolResult<Self> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLifecycleState,
                "Ed25519 Yao session id must be nonzero",
            ));
        }
        Ok(Self(bytes))
    }

    /// Returns the fixed transcript session bytes.
    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl<'de> Deserialize<'de> for Ed25519YaoSessionIdV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(<[u8; 32]>::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

/// Digest binding the canonical application facts and participant identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Ed25519YaoStableKeyContextBindingV1([u8; 32]);

impl Ed25519YaoStableKeyContextBindingV1 {
    /// Creates the fixed-width stable-context binding.
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the stable-context binding bytes.
    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// Monotonic role-local state epoch for Ed25519 Yao refresh.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct Ed25519YaoStateEpochV1(u64);

impl Ed25519YaoStateEpochV1 {
    /// Creates a nonzero state epoch.
    pub fn new(value: u64) -> RouterAbProtocolResult<Self> {
        if value == 0 {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLifecycleState,
                "Ed25519 Yao state epoch must be nonzero",
            ));
        }
        Ok(Self(value))
    }

    /// Returns the numeric epoch.
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl<'de> Deserialize<'de> for Ed25519YaoStateEpochV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(u64::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

/// Strict one-step epoch advancement for one refresh participant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Ed25519YaoEpochTransitionV1 {
    /// Currently active epoch.
    current: Ed25519YaoStateEpochV1,
    /// Proposed immediately following epoch.
    next: Ed25519YaoStateEpochV1,
}

impl Ed25519YaoEpochTransitionV1 {
    /// Creates an exact current-to-next transition.
    pub fn new(
        current: Ed25519YaoStateEpochV1,
        next: Ed25519YaoStateEpochV1,
    ) -> RouterAbProtocolResult<Self> {
        if next <= current {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLifecycleState,
                "Ed25519 Yao refresh epoch must strictly advance",
            ));
        }
        Ok(Self { current, next })
    }

    /// Returns the active epoch expected by the transition.
    pub const fn current(self) -> Ed25519YaoStateEpochV1 {
        self.current
    }

    /// Returns the strictly newer proposed epoch.
    pub const fn next(self) -> Ed25519YaoStateEpochV1 {
        self.next
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEd25519YaoEpochTransitionV1 {
    current: Ed25519YaoStateEpochV1,
    next: Ed25519YaoStateEpochV1,
}

impl<'de> Deserialize<'de> for Ed25519YaoEpochTransitionV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawEd25519YaoEpochTransitionV1::deserialize(deserializer)?;
        Self::new(raw.current, raw.next).map_err(D::Error::custom)
    }
}

/// Role-specific epochs bound into one admitted refresh.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ed25519YaoRefreshEpochsV1 {
    /// Deriver A input-state transition.
    pub deriver_a: Ed25519YaoEpochTransitionV1,
    /// Deriver B input-state transition.
    pub deriver_b: Ed25519YaoEpochTransitionV1,
    /// SigningWorker activation-state transition.
    pub signing_worker: Ed25519YaoEpochTransitionV1,
}

/// Refresh-only public binding layered over the shared ceremony binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Ed25519YaoRefreshBindingV1 {
    /// Shared Router-admitted ceremony binding.
    ceremony: Ed25519YaoCeremonyBindingV1,
    /// Existing public identity that refresh must preserve.
    registered_public_key: [u8; 32],
    /// Exact role-local epoch transitions.
    epochs: Ed25519YaoRefreshEpochsV1,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEd25519YaoRefreshBindingV1 {
    ceremony: Ed25519YaoCeremonyBindingV1,
    registered_public_key: [u8; 32],
    epochs: Ed25519YaoRefreshEpochsV1,
}

impl<'de> Deserialize<'de> for Ed25519YaoRefreshBindingV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawEd25519YaoRefreshBindingV1::deserialize(deserializer)?;
        Self::new(raw.ceremony, raw.registered_public_key, raw.epochs).map_err(D::Error::custom)
    }
}

impl Ed25519YaoRefreshBindingV1 {
    /// Creates a refresh-only binding with a nonzero registered identity.
    pub fn new(
        ceremony: Ed25519YaoCeremonyBindingV1,
        registered_public_key: [u8; 32],
        epochs: Ed25519YaoRefreshEpochsV1,
    ) -> RouterAbProtocolResult<Self> {
        ceremony.validate()?;
        if ceremony.operation != Ed25519YaoOperationV1::Refresh {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLifecycleState,
                "Ed25519 Yao refresh binding requires the refresh operation",
            ));
        }
        if registered_public_key.iter().all(|byte| *byte == 0) {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLifecycleState,
                "Ed25519 Yao refresh registered public key must be nonzero",
            ));
        }
        Ok(Self {
            ceremony,
            registered_public_key,
            epochs,
        })
    }

    /// Returns the shared refresh ceremony binding.
    pub const fn ceremony(&self) -> &Ed25519YaoCeremonyBindingV1 {
        &self.ceremony
    }

    /// Returns the public identity refresh must preserve.
    pub const fn registered_public_key(&self) -> &[u8; 32] {
        &self.registered_public_key
    }

    /// Returns the exact role-local epoch transitions.
    pub const fn epochs(&self) -> &Ed25519YaoRefreshEpochsV1 {
        &self.epochs
    }
}

/// Public Router-admitted binding shared by both Derivers for one ceremony.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ed25519YaoCeremonyBindingV1 {
    /// Product lifecycle and authenticated application scope.
    pub lifecycle: LifecycleScopeV1,
    /// Lifecycle operation selecting one fixed circuit family.
    pub operation: Ed25519YaoOperationV1,
    /// Transcript session id derived from the admitted request.
    pub session_id: Ed25519YaoSessionIdV1,
    /// Canonical stable KDF-context binding admitted by the Router.
    pub stable_key_context_binding: Ed25519YaoStableKeyContextBindingV1,
}

impl Ed25519YaoCeremonyBindingV1 {
    /// Creates a binding whose lifecycle work class matches the operation.
    pub fn new(
        lifecycle: LifecycleScopeV1,
        operation: Ed25519YaoOperationV1,
        session_id: Ed25519YaoSessionIdV1,
        stable_key_context_binding: Ed25519YaoStableKeyContextBindingV1,
    ) -> RouterAbProtocolResult<Self> {
        let binding = Self {
            lifecycle,
            operation,
            session_id,
            stable_key_context_binding,
        };
        binding.validate()?;
        Ok(binding)
    }

    /// Revalidates a binding received from an untrusted serialization boundary.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.lifecycle.validate()?;
        if self.lifecycle.work_kind != self.operation.work_kind() {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLifecycleState,
                "Ed25519 Yao operation does not match the admitted lifecycle work kind",
            ));
        }
        Ok(())
    }

    /// Returns the fixed circuit family selected by the operation.
    pub const fn circuit_family(&self) -> Ed25519YaoCircuitFamilyV1 {
        self.operation.circuit_family()
    }
}

/// Canonical application facts bound into one Ed25519 Yao stable key identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RouterAbEd25519YaoApplicationBindingFactsV1 {
    wallet_id: String,
    near_ed25519_signing_key_id: String,
    signing_root_id: String,
    key_creation_signer_slot: u32,
}

impl RouterAbEd25519YaoApplicationBindingFactsV1 {
    /// Creates validated visible-ASCII application binding facts.
    pub fn new(
        wallet_id: impl Into<String>,
        near_ed25519_signing_key_id: impl Into<String>,
        signing_root_id: impl Into<String>,
        key_creation_signer_slot: u32,
    ) -> RouterAbProtocolResult<Self> {
        let facts = Self {
            wallet_id: wallet_id.into(),
            near_ed25519_signing_key_id: near_ed25519_signing_key_id.into(),
            signing_root_id: signing_root_id.into(),
            key_creation_signer_slot,
        };
        validate_visible_identifier("wallet_id", &facts.wallet_id)?;
        validate_visible_identifier(
            "near_ed25519_signing_key_id",
            &facts.near_ed25519_signing_key_id,
        )?;
        validate_visible_identifier("signing_root_id", &facts.signing_root_id)?;
        if facts.key_creation_signer_slot == 0 {
            return Err(invalid_yao_wire(
                "Ed25519 Yao key_creation_signer_slot must be positive",
            ));
        }
        Ok(facts)
    }

    /// Returns the wallet identity.
    pub fn wallet_id(&self) -> &str {
        &self.wallet_id
    }

    /// Returns the NEAR Ed25519 signing-key identity.
    pub fn near_ed25519_signing_key_id(&self) -> &str {
        &self.near_ed25519_signing_key_id
    }

    /// Returns the signing-root identity.
    pub fn signing_root_id(&self) -> &str {
        &self.signing_root_id
    }

    /// Returns the positive key-creation signer slot.
    pub const fn key_creation_signer_slot(&self) -> u32 {
        self.key_creation_signer_slot
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRouterAbEd25519YaoApplicationBindingFactsV1 {
    wallet_id: String,
    near_ed25519_signing_key_id: String,
    signing_root_id: String,
    key_creation_signer_slot: u32,
}

impl<'de> Deserialize<'de> for RouterAbEd25519YaoApplicationBindingFactsV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawRouterAbEd25519YaoApplicationBindingFactsV1::deserialize(deserializer)?;
        Self::new(
            raw.wallet_id,
            raw.near_ed25519_signing_key_id,
            raw.signing_root_id,
            raw.key_creation_signer_slot,
        )
        .map_err(D::Error::custom)
    }
}

/// Public lifecycle facts accepted by an Ed25519 Yao Router admission route.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RouterAbEd25519YaoLifecycleScopeV1 {
    lifecycle_id: String,
    root_share_epoch: RootShareEpoch,
    account_id: String,
    wallet_session_id: String,
    signer_set_id: String,
    signing_worker_id: String,
}

impl RouterAbEd25519YaoLifecycleScopeV1 {
    /// Creates a validated public lifecycle scope.
    pub fn new(
        lifecycle_id: impl Into<String>,
        root_share_epoch: RootShareEpoch,
        account_id: impl Into<String>,
        wallet_session_id: impl Into<String>,
        signer_set_id: impl Into<String>,
        signing_worker_id: impl Into<String>,
    ) -> RouterAbProtocolResult<Self> {
        let scope = Self {
            lifecycle_id: lifecycle_id.into(),
            root_share_epoch,
            account_id: account_id.into(),
            wallet_session_id: wallet_session_id.into(),
            signer_set_id: signer_set_id.into(),
            signing_worker_id: signing_worker_id.into(),
        };
        validate_visible_identifier("lifecycle_id", &scope.lifecycle_id)?;
        validate_visible_identifier("account_id", &scope.account_id)?;
        validate_visible_identifier("wallet_session_id", &scope.wallet_session_id)?;
        validate_visible_identifier("signer_set_id", &scope.signer_set_id)?;
        validate_visible_identifier("signing_worker_id", &scope.signing_worker_id)?;
        Ok(scope)
    }

    /// Converts the public facts into the internal lifecycle for one fixed operation.
    pub fn into_lifecycle(
        self,
        operation: Ed25519YaoOperationV1,
    ) -> RouterAbProtocolResult<LifecycleScopeV1> {
        LifecycleScopeV1::new(
            self.lifecycle_id,
            operation.work_kind(),
            self.root_share_epoch,
            self.account_id,
            self.wallet_session_id,
            self.signer_set_id,
            self.signing_worker_id,
        )
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRouterAbEd25519YaoLifecycleScopeV1 {
    lifecycle_id: String,
    root_share_epoch: RootShareEpoch,
    account_id: String,
    wallet_session_id: String,
    signer_set_id: String,
    signing_worker_id: String,
}

impl<'de> Deserialize<'de> for RouterAbEd25519YaoLifecycleScopeV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawRouterAbEd25519YaoLifecycleScopeV1::deserialize(deserializer)?;
        Self::new(
            raw.lifecycle_id,
            raw.root_share_epoch,
            raw.account_id,
            raw.wallet_session_id,
            raw.signer_set_id,
            raw.signing_worker_id,
        )
        .map_err(D::Error::custom)
    }
}

/// Public registration admission request accepted by the SDK Router.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RouterAbEd25519YaoRegistrationAdmissionRequestV1 {
    scope: RouterAbEd25519YaoLifecycleScopeV1,
    application_binding: RouterAbEd25519YaoApplicationBindingFactsV1,
    participant_ids: [u16; 2],
}

impl RouterAbEd25519YaoRegistrationAdmissionRequestV1 {
    /// Creates a registration request with canonical ascending participant identifiers.
    pub fn new(
        scope: RouterAbEd25519YaoLifecycleScopeV1,
        application_binding: RouterAbEd25519YaoApplicationBindingFactsV1,
        participant_ids: [u16; 2],
    ) -> RouterAbProtocolResult<Self> {
        validate_participant_ids(participant_ids)?;
        Ok(Self {
            scope,
            application_binding,
            participant_ids,
        })
    }

    /// Consumes the boundary request into validated admission facts.
    pub fn into_parts(
        self,
    ) -> (
        RouterAbEd25519YaoLifecycleScopeV1,
        RouterAbEd25519YaoApplicationBindingFactsV1,
        [u16; 2],
    ) {
        (self.scope, self.application_binding, self.participant_ids)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRouterAbEd25519YaoRegistrationAdmissionRequestV1 {
    scope: RouterAbEd25519YaoLifecycleScopeV1,
    application_binding: RouterAbEd25519YaoApplicationBindingFactsV1,
    participant_ids: [u16; 2],
}

impl<'de> Deserialize<'de> for RouterAbEd25519YaoRegistrationAdmissionRequestV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawRouterAbEd25519YaoRegistrationAdmissionRequestV1::deserialize(deserializer)?;
        Self::new(raw.scope, raw.application_binding, raw.participant_ids).map_err(D::Error::custom)
    }
}

/// Fresh, explicit Client authorization bound to one exact-seed export admission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RouterAbEd25519YaoExportAuthorizationV1 {
    confirmation_digest: [u8; 32],
    authorization_digest: [u8; 32],
    nonce: [u8; 32],
    issued_at_ms: u64,
    expires_at_ms: u64,
}

impl RouterAbEd25519YaoExportAuthorizationV1 {
    /// Creates a short-lived, nonzero export authorization.
    pub fn new(
        confirmation_digest: [u8; 32],
        authorization_digest: [u8; 32],
        nonce: [u8; 32],
        issued_at_ms: u64,
        expires_at_ms: u64,
    ) -> RouterAbProtocolResult<Self> {
        if [confirmation_digest, authorization_digest, nonce]
            .iter()
            .any(|value| value.iter().all(|byte| *byte == 0))
        {
            return Err(invalid_yao_wire(
                "Ed25519 Yao export authorization contains a zero binding",
            ));
        }
        if issued_at_ms == 0 || expires_at_ms <= issued_at_ms {
            return Err(invalid_yao_wire(
                "Ed25519 Yao export authorization lifetime is invalid",
            ));
        }
        Ok(Self {
            confirmation_digest,
            authorization_digest,
            nonce,
            issued_at_ms,
            expires_at_ms,
        })
    }

    /// Returns the user-confirmation digest.
    pub const fn confirmation_digest(&self) -> [u8; 32] {
        self.confirmation_digest
    }

    /// Returns the exact export-authorization digest.
    pub const fn authorization_digest(&self) -> [u8; 32] {
        self.authorization_digest
    }

    /// Returns the one-use replay nonce.
    pub const fn nonce(&self) -> [u8; 32] {
        self.nonce
    }

    /// Returns the authorization issue time.
    pub const fn issued_at_ms(&self) -> u64 {
        self.issued_at_ms
    }

    /// Returns the authorization expiry time.
    pub const fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRouterAbEd25519YaoExportAuthorizationV1 {
    confirmation_digest: [u8; 32],
    authorization_digest: [u8; 32],
    nonce: [u8; 32],
    issued_at_ms: u64,
    expires_at_ms: u64,
}

impl<'de> Deserialize<'de> for RouterAbEd25519YaoExportAuthorizationV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawRouterAbEd25519YaoExportAuthorizationV1::deserialize(deserializer)?;
        Self::new(
            raw.confirmation_digest,
            raw.authorization_digest,
            raw.nonce,
            raw.issued_at_ms,
            raw.expires_at_ms,
        )
        .map_err(D::Error::custom)
    }
}

/// Public Ed25519 Yao export admission bound to one active wallet identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RouterAbEd25519YaoExportAdmissionRequestV1 {
    scope: RouterAbEd25519YaoLifecycleScopeV1,
    application_binding: RouterAbEd25519YaoApplicationBindingFactsV1,
    participant_ids: [u16; 2],
    registered_public_key: [u8; 32],
    state_epoch: Ed25519YaoStateEpochV1,
    runtime_policy_binding: [u8; 32],
    authorization: RouterAbEd25519YaoExportAuthorizationV1,
}

impl RouterAbEd25519YaoExportAdmissionRequestV1 {
    /// Creates an exact active-identity export admission request.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: RouterAbEd25519YaoLifecycleScopeV1,
        application_binding: RouterAbEd25519YaoApplicationBindingFactsV1,
        participant_ids: [u16; 2],
        registered_public_key: [u8; 32],
        state_epoch: Ed25519YaoStateEpochV1,
        runtime_policy_binding: [u8; 32],
        authorization: RouterAbEd25519YaoExportAuthorizationV1,
    ) -> RouterAbProtocolResult<Self> {
        validate_participant_ids(participant_ids)?;
        if registered_public_key.iter().all(|byte| *byte == 0)
            || runtime_policy_binding.iter().all(|byte| *byte == 0)
        {
            return Err(invalid_yao_wire(
                "Ed25519 Yao export admission contains a zero identity binding",
            ));
        }
        Ok(Self {
            scope,
            application_binding,
            participant_ids,
            registered_public_key,
            state_epoch,
            runtime_policy_binding,
            authorization,
        })
    }

    /// Consumes the boundary request into validated admission facts.
    #[allow(clippy::type_complexity)]
    pub fn into_parts(
        self,
    ) -> (
        RouterAbEd25519YaoLifecycleScopeV1,
        RouterAbEd25519YaoApplicationBindingFactsV1,
        [u16; 2],
        [u8; 32],
        Ed25519YaoStateEpochV1,
        [u8; 32],
        RouterAbEd25519YaoExportAuthorizationV1,
    ) {
        (
            self.scope,
            self.application_binding,
            self.participant_ids,
            self.registered_public_key,
            self.state_epoch,
            self.runtime_policy_binding,
            self.authorization,
        )
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRouterAbEd25519YaoExportAdmissionRequestV1 {
    scope: RouterAbEd25519YaoLifecycleScopeV1,
    application_binding: RouterAbEd25519YaoApplicationBindingFactsV1,
    participant_ids: [u16; 2],
    registered_public_key: [u8; 32],
    state_epoch: Ed25519YaoStateEpochV1,
    runtime_policy_binding: [u8; 32],
    authorization: RouterAbEd25519YaoExportAuthorizationV1,
}

impl<'de> Deserialize<'de> for RouterAbEd25519YaoExportAdmissionRequestV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawRouterAbEd25519YaoExportAdmissionRequestV1::deserialize(deserializer)?;
        Self::new(
            raw.scope,
            raw.application_binding,
            raw.participant_ids,
            raw.registered_public_key,
            raw.state_epoch,
            raw.runtime_policy_binding,
            raw.authorization,
        )
        .map_err(D::Error::custom)
    }
}

/// Fixed public HPKE keys returned by activation-family admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RouterAbEd25519YaoActivationKeysetV1 {
    deriver_a_input_public_key: [u8; 32],
    deriver_b_input_public_key: [u8; 32],
    signing_worker_recipient_public_key: [u8; 32],
}

impl RouterAbEd25519YaoActivationKeysetV1 {
    /// Creates three distinct nonzero X25519 public keys.
    pub fn new(
        deriver_a_input_public_key: [u8; 32],
        deriver_b_input_public_key: [u8; 32],
        signing_worker_recipient_public_key: [u8; 32],
    ) -> RouterAbProtocolResult<Self> {
        let keys = [
            deriver_a_input_public_key,
            deriver_b_input_public_key,
            signing_worker_recipient_public_key,
        ];
        if keys.iter().any(|key| key.iter().all(|byte| *byte == 0)) {
            return Err(invalid_yao_wire(
                "Ed25519 Yao activation keyset contains a zero public key",
            ));
        }
        if keys[0] == keys[1] || keys[0] == keys[2] || keys[1] == keys[2] {
            return Err(invalid_yao_wire(
                "Ed25519 Yao activation keyset public keys must be distinct",
            ));
        }
        Ok(Self {
            deriver_a_input_public_key,
            deriver_b_input_public_key,
            signing_worker_recipient_public_key,
        })
    }

    /// Returns the Deriver A input public key.
    pub const fn deriver_a_input_public_key(&self) -> [u8; 32] {
        self.deriver_a_input_public_key
    }

    /// Returns the Deriver B input public key.
    pub const fn deriver_b_input_public_key(&self) -> [u8; 32] {
        self.deriver_b_input_public_key
    }

    /// Returns the SigningWorker recipient public key.
    pub const fn signing_worker_recipient_public_key(&self) -> [u8; 32] {
        self.signing_worker_recipient_public_key
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRouterAbEd25519YaoActivationKeysetV1 {
    deriver_a_input_public_key: [u8; 32],
    deriver_b_input_public_key: [u8; 32],
    signing_worker_recipient_public_key: [u8; 32],
}

impl<'de> Deserialize<'de> for RouterAbEd25519YaoActivationKeysetV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawRouterAbEd25519YaoActivationKeysetV1::deserialize(deserializer)?;
        Self::new(
            raw.deriver_a_input_public_key,
            raw.deriver_b_input_public_key,
            raw.signing_worker_recipient_public_key,
        )
        .map_err(D::Error::custom)
    }
}

/// Public receipt returned after Router activation-family admission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RouterAbEd25519YaoActivationAdmissionReceiptV1 {
    binding: Ed25519YaoCeremonyBindingV1,
    keyset: RouterAbEd25519YaoActivationKeysetV1,
}

impl RouterAbEd25519YaoActivationAdmissionReceiptV1 {
    /// Creates a receipt for one registration or recovery binding and its exact public keyset.
    pub fn new(
        binding: Ed25519YaoCeremonyBindingV1,
        keyset: RouterAbEd25519YaoActivationKeysetV1,
    ) -> RouterAbProtocolResult<Self> {
        binding.validate()?;
        if !matches!(
            binding.operation,
            Ed25519YaoOperationV1::Registration | Ed25519YaoOperationV1::Recovery
        ) {
            return Err(invalid_yao_wire(
                "Ed25519 Yao activation admission receipt has the wrong operation",
            ));
        }
        Ok(Self { binding, keyset })
    }

    /// Returns the admitted activation-family binding.
    pub const fn binding(&self) -> &Ed25519YaoCeremonyBindingV1 {
        &self.binding
    }

    /// Returns the exact public HPKE keyset.
    pub const fn keyset(&self) -> &RouterAbEd25519YaoActivationKeysetV1 {
        &self.keyset
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRouterAbEd25519YaoActivationAdmissionReceiptV1 {
    binding: Ed25519YaoCeremonyBindingV1,
    keyset: RouterAbEd25519YaoActivationKeysetV1,
}

impl<'de> Deserialize<'de> for RouterAbEd25519YaoActivationAdmissionReceiptV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawRouterAbEd25519YaoActivationAdmissionReceiptV1::deserialize(deserializer)?;
        Self::new(raw.binding, raw.keyset).map_err(D::Error::custom)
    }
}

/// Immutable public identity and authorization bound through one export ceremony.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RouterAbEd25519YaoExportBindingV1 {
    ceremony: Ed25519YaoCeremonyBindingV1,
    registered_public_key: [u8; 32],
    state_epoch: Ed25519YaoStateEpochV1,
    runtime_policy_binding: [u8; 32],
    authorization_digest: [u8; 32],
}

impl RouterAbEd25519YaoExportBindingV1 {
    /// Creates an export-only binding for one exact active key state.
    pub fn new(
        ceremony: Ed25519YaoCeremonyBindingV1,
        registered_public_key: [u8; 32],
        state_epoch: Ed25519YaoStateEpochV1,
        runtime_policy_binding: [u8; 32],
        authorization_digest: [u8; 32],
    ) -> RouterAbProtocolResult<Self> {
        ceremony.validate()?;
        if ceremony.operation != Ed25519YaoOperationV1::Export {
            return Err(invalid_yao_wire(
                "Ed25519 Yao export binding requires the export operation",
            ));
        }
        if [
            registered_public_key,
            runtime_policy_binding,
            authorization_digest,
        ]
        .iter()
        .any(|value| value.iter().all(|byte| *byte == 0))
        {
            return Err(invalid_yao_wire(
                "Ed25519 Yao export binding contains a zero field",
            ));
        }
        Ok(Self {
            ceremony,
            registered_public_key,
            state_epoch,
            runtime_policy_binding,
            authorization_digest,
        })
    }

    /// Returns the shared ceremony binding.
    pub const fn ceremony(&self) -> &Ed25519YaoCeremonyBindingV1 {
        &self.ceremony
    }

    /// Returns the registered public identity that the exported seed must reproduce.
    pub const fn registered_public_key(&self) -> [u8; 32] {
        self.registered_public_key
    }

    /// Returns the exact active state epoch.
    pub const fn state_epoch(&self) -> Ed25519YaoStateEpochV1 {
        self.state_epoch
    }

    /// Returns the exact runtime-policy binding.
    pub const fn runtime_policy_binding(&self) -> [u8; 32] {
        self.runtime_policy_binding
    }

    /// Returns the fresh explicit authorization digest.
    pub const fn authorization_digest(&self) -> [u8; 32] {
        self.authorization_digest
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRouterAbEd25519YaoExportBindingV1 {
    ceremony: Ed25519YaoCeremonyBindingV1,
    registered_public_key: [u8; 32],
    state_epoch: Ed25519YaoStateEpochV1,
    runtime_policy_binding: [u8; 32],
    authorization_digest: [u8; 32],
}

impl<'de> Deserialize<'de> for RouterAbEd25519YaoExportBindingV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawRouterAbEd25519YaoExportBindingV1::deserialize(deserializer)?;
        Self::new(
            raw.ceremony,
            raw.registered_public_key,
            raw.state_epoch,
            raw.runtime_policy_binding,
            raw.authorization_digest,
        )
        .map_err(D::Error::custom)
    }
}

/// Public receipt returned after exact-seed export admission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RouterAbEd25519YaoExportAdmissionReceiptV1 {
    binding: RouterAbEd25519YaoExportBindingV1,
    keyset: RouterAbEd25519YaoActivationKeysetV1,
}

impl RouterAbEd25519YaoExportAdmissionReceiptV1 {
    /// Creates an admitted export binding and exact recipient keyset.
    pub fn new(
        binding: RouterAbEd25519YaoExportBindingV1,
        keyset: RouterAbEd25519YaoActivationKeysetV1,
    ) -> RouterAbProtocolResult<Self> {
        binding.ceremony.validate()?;
        Ok(Self { binding, keyset })
    }

    /// Returns the exact export binding.
    pub const fn binding(&self) -> &RouterAbEd25519YaoExportBindingV1 {
        &self.binding
    }

    /// Returns the exact public HPKE keyset.
    pub const fn keyset(&self) -> &RouterAbEd25519YaoActivationKeysetV1 {
        &self.keyset
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRouterAbEd25519YaoExportAdmissionReceiptV1 {
    binding: RouterAbEd25519YaoExportBindingV1,
    keyset: RouterAbEd25519YaoActivationKeysetV1,
}

impl<'de> Deserialize<'de> for RouterAbEd25519YaoExportAdmissionReceiptV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawRouterAbEd25519YaoExportAdmissionReceiptV1::deserialize(deserializer)?;
        Self::new(raw.binding, raw.keyset).map_err(D::Error::custom)
    }
}

/// Deriver role bound into an opaque Yao envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ed25519YaoDeriverRoleV1 {
    /// Fixed garbler role.
    DeriverA,
    /// Fixed evaluator role.
    DeriverB,
}

impl Ed25519YaoDeriverRoleV1 {
    /// Returns the canonical byte tag used by HPKE associated data.
    pub const fn wire_tag(self) -> u8 {
        match self {
            Self::DeriverA => 1,
            Self::DeriverB => 2,
        }
    }
}

/// Fixed circuit family carried by one encrypted Deriver input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ed25519YaoInputKindV1 {
    /// Activation-family input.
    Activation,
    /// Explicit-export input.
    Export,
}

impl Ed25519YaoInputKindV1 {
    /// Returns the canonical byte tag used by HPKE associated data.
    pub const fn wire_tag(self) -> u8 {
        match self {
            Self::Activation => 1,
            Self::Export => 2,
        }
    }
}

/// Opaque HPKE envelope forwarded by Router to exactly one Deriver.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Ed25519YaoEncryptedInputV1 {
    kind: Ed25519YaoInputKindV1,
    deriver: Ed25519YaoDeriverRoleV1,
    operation: Ed25519YaoOperationV1,
    session: [u8; 32],
    stable_context_binding: [u8; 32],
    encapsulated_key: [u8; 32],
    ciphertext: Vec<u8>,
}

impl Ed25519YaoEncryptedInputV1 {
    /// Creates a bounded opaque input whose operation matches its fixed family.
    pub fn new(
        kind: Ed25519YaoInputKindV1,
        deriver: Ed25519YaoDeriverRoleV1,
        operation: Ed25519YaoOperationV1,
        session: [u8; 32],
        stable_context_binding: [u8; 32],
        encapsulated_key: [u8; 32],
        ciphertext: Vec<u8>,
    ) -> RouterAbProtocolResult<Self> {
        let envelope = Self {
            kind,
            deriver,
            operation,
            session,
            stable_context_binding,
            encapsulated_key,
            ciphertext,
        };
        envelope.validate()?;
        Ok(envelope)
    }

    /// Validates public metadata and ciphertext bounds.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        if self.session.iter().all(|byte| *byte == 0)
            || self.stable_context_binding.iter().all(|byte| *byte == 0)
            || self.encapsulated_key.iter().all(|byte| *byte == 0)
        {
            return Err(invalid_yao_wire(
                "Ed25519 Yao encrypted input contains a zero binding",
            ));
        }
        if !(16..=ED25519_YAO_CONTROL_CIPHERTEXT_MAX_BYTES_V1).contains(&self.ciphertext.len()) {
            return Err(invalid_yao_wire(
                "Ed25519 Yao encrypted input ciphertext length is invalid",
            ));
        }
        if self.operation.circuit_family()
            != match self.kind {
                Ed25519YaoInputKindV1::Activation => Ed25519YaoCircuitFamilyV1::Activation,
                Ed25519YaoInputKindV1::Export => Ed25519YaoCircuitFamilyV1::Export,
            }
        {
            return Err(invalid_yao_wire(
                "Ed25519 Yao encrypted input operation does not match its family",
            ));
        }
        Ok(())
    }

    /// Returns the fixed input kind.
    pub const fn kind(&self) -> Ed25519YaoInputKindV1 {
        self.kind
    }

    /// Returns the recipient Deriver.
    pub const fn deriver(&self) -> Ed25519YaoDeriverRoleV1 {
        self.deriver
    }

    /// Returns the admitted lifecycle operation.
    pub const fn operation(&self) -> Ed25519YaoOperationV1 {
        self.operation
    }

    /// Returns the transcript session bytes.
    pub const fn session(&self) -> [u8; 32] {
        self.session
    }

    /// Returns the stable-context binding bytes.
    pub const fn stable_context_binding(&self) -> [u8; 32] {
        self.stable_context_binding
    }

    /// Returns the HPKE encapsulated key.
    pub const fn encapsulated_key(&self) -> &[u8; 32] {
        &self.encapsulated_key
    }

    /// Returns the opaque ciphertext.
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEd25519YaoEncryptedInputV1 {
    kind: Ed25519YaoInputKindV1,
    deriver: Ed25519YaoDeriverRoleV1,
    operation: Ed25519YaoOperationV1,
    session: [u8; 32],
    stable_context_binding: [u8; 32],
    encapsulated_key: [u8; 32],
    ciphertext: Vec<u8>,
}

impl<'de> Deserialize<'de> for Ed25519YaoEncryptedInputV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawEd25519YaoEncryptedInputV1::deserialize(deserializer)?;
        Self::new(
            raw.kind,
            raw.deriver,
            raw.operation,
            raw.session,
            raw.stable_context_binding,
            raw.encapsulated_key,
            raw.ciphertext,
        )
        .map_err(D::Error::custom)
    }
}

/// Opaque inputs submitted for one admitted activation-family execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RouterAbEd25519YaoActivationExecuteRequestV1 {
    binding: Ed25519YaoCeremonyBindingV1,
    deriver_a_input: Ed25519YaoEncryptedInputV1,
    deriver_b_input: Ed25519YaoEncryptedInputV1,
}

impl RouterAbEd25519YaoActivationExecuteRequestV1 {
    /// Creates an activation execution whose opaque A/B envelopes match admission.
    pub fn new(
        binding: Ed25519YaoCeremonyBindingV1,
        deriver_a_input: Ed25519YaoEncryptedInputV1,
        deriver_b_input: Ed25519YaoEncryptedInputV1,
    ) -> RouterAbProtocolResult<Self> {
        binding.validate()?;
        if !matches!(
            binding.operation,
            Ed25519YaoOperationV1::Registration | Ed25519YaoOperationV1::Recovery
        ) {
            return Err(invalid_yao_wire(
                "Ed25519 Yao activation execution has the wrong operation",
            ));
        }
        validate_activation_input(
            &binding,
            &deriver_a_input,
            Ed25519YaoDeriverRoleV1::DeriverA,
        )?;
        validate_activation_input(
            &binding,
            &deriver_b_input,
            Ed25519YaoDeriverRoleV1::DeriverB,
        )?;
        Ok(Self {
            binding,
            deriver_a_input,
            deriver_b_input,
        })
    }

    /// Returns the admitted binding.
    pub const fn binding(&self) -> &Ed25519YaoCeremonyBindingV1 {
        &self.binding
    }

    /// Returns the opaque Deriver A input.
    pub const fn deriver_a_input(&self) -> &Ed25519YaoEncryptedInputV1 {
        &self.deriver_a_input
    }

    /// Returns the opaque Deriver B input.
    pub const fn deriver_b_input(&self) -> &Ed25519YaoEncryptedInputV1 {
        &self.deriver_b_input
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRouterAbEd25519YaoActivationExecuteRequestV1 {
    binding: Ed25519YaoCeremonyBindingV1,
    deriver_a_input: Ed25519YaoEncryptedInputV1,
    deriver_b_input: Ed25519YaoEncryptedInputV1,
}

impl<'de> Deserialize<'de> for RouterAbEd25519YaoActivationExecuteRequestV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawRouterAbEd25519YaoActivationExecuteRequestV1::deserialize(deserializer)?;
        Self::new(raw.binding, raw.deriver_a_input, raw.deriver_b_input).map_err(D::Error::custom)
    }
}

/// Opaque A/B inputs submitted for one admitted exact-seed export.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RouterAbEd25519YaoExportExecuteRequestV1 {
    binding: RouterAbEd25519YaoExportBindingV1,
    deriver_a_input: Ed25519YaoEncryptedInputV1,
    deriver_b_input: Ed25519YaoEncryptedInputV1,
}

impl RouterAbEd25519YaoExportExecuteRequestV1 {
    /// Creates an export execution whose opaque inputs match admission.
    pub fn new(
        binding: RouterAbEd25519YaoExportBindingV1,
        deriver_a_input: Ed25519YaoEncryptedInputV1,
        deriver_b_input: Ed25519YaoEncryptedInputV1,
    ) -> RouterAbProtocolResult<Self> {
        validate_export_input(
            binding.ceremony(),
            &deriver_a_input,
            Ed25519YaoDeriverRoleV1::DeriverA,
        )?;
        validate_export_input(
            binding.ceremony(),
            &deriver_b_input,
            Ed25519YaoDeriverRoleV1::DeriverB,
        )?;
        Ok(Self {
            binding,
            deriver_a_input,
            deriver_b_input,
        })
    }

    /// Returns the exact admitted export binding.
    pub const fn binding(&self) -> &RouterAbEd25519YaoExportBindingV1 {
        &self.binding
    }

    /// Returns the Deriver A opaque input.
    pub const fn deriver_a_input(&self) -> &Ed25519YaoEncryptedInputV1 {
        &self.deriver_a_input
    }

    /// Returns the Deriver B opaque input.
    pub const fn deriver_b_input(&self) -> &Ed25519YaoEncryptedInputV1 {
        &self.deriver_b_input
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRouterAbEd25519YaoExportExecuteRequestV1 {
    binding: RouterAbEd25519YaoExportBindingV1,
    deriver_a_input: Ed25519YaoEncryptedInputV1,
    deriver_b_input: Ed25519YaoEncryptedInputV1,
}

impl<'de> Deserialize<'de> for RouterAbEd25519YaoExportExecuteRequestV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawRouterAbEd25519YaoExportExecuteRequestV1::deserialize(deserializer)?;
        Self::new(raw.binding, raw.deriver_a_input, raw.deriver_b_input).map_err(D::Error::custom)
    }
}

/// Recipient package kind produced by a fixed Ed25519 Yao circuit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ed25519YaoPackageKindV1 {
    /// Activation share encrypted to Client.
    ActivationClient,
    /// Activation share encrypted to SigningWorker.
    ActivationSigningWorker,
    /// Export seed share encrypted to Client.
    ExportClient,
}

impl Ed25519YaoPackageKindV1 {
    /// Returns the canonical byte tag used by HPKE associated data.
    pub const fn wire_tag(self) -> u8 {
        match self {
            Self::ActivationClient => 1,
            Self::ActivationSigningWorker => 2,
            Self::ExportClient => 3,
        }
    }

    /// Reports whether Client owns this package kind.
    pub const fn is_client(self) -> bool {
        matches!(self, Self::ActivationClient | Self::ExportClient)
    }
}

/// Recipient-encrypted role output forwarded without opening by Router.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Ed25519YaoEncryptedPackageV1 {
    kind: Ed25519YaoPackageKindV1,
    deriver: Ed25519YaoDeriverRoleV1,
    session: [u8; 32],
    transcript: [u8; 32],
    encapsulated_key: [u8; 32],
    ciphertext: Vec<u8>,
}

impl Ed25519YaoEncryptedPackageV1 {
    /// Creates a bounded recipient-encrypted package.
    pub fn new(
        kind: Ed25519YaoPackageKindV1,
        deriver: Ed25519YaoDeriverRoleV1,
        session: [u8; 32],
        transcript: [u8; 32],
        encapsulated_key: [u8; 32],
        ciphertext: Vec<u8>,
    ) -> RouterAbProtocolResult<Self> {
        let package = Self {
            kind,
            deriver,
            session,
            transcript,
            encapsulated_key,
            ciphertext,
        };
        package.validate()?;
        Ok(package)
    }

    /// Validates public metadata and ciphertext bounds.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        if self.session.iter().all(|byte| *byte == 0)
            || self.transcript.iter().all(|byte| *byte == 0)
            || self.encapsulated_key.iter().all(|byte| *byte == 0)
        {
            return Err(invalid_yao_wire(
                "Ed25519 Yao encrypted package contains a zero binding",
            ));
        }
        if !(16..=ED25519_YAO_CONTROL_CIPHERTEXT_MAX_BYTES_V1).contains(&self.ciphertext.len()) {
            return Err(invalid_yao_wire(
                "Ed25519 Yao encrypted package ciphertext length is invalid",
            ));
        }
        Ok(())
    }

    /// Returns the package kind.
    pub const fn kind(&self) -> Ed25519YaoPackageKindV1 {
        self.kind
    }

    /// Returns the producing Deriver.
    pub const fn deriver(&self) -> Ed25519YaoDeriverRoleV1 {
        self.deriver
    }

    /// Returns the ceremony session.
    pub const fn session(&self) -> [u8; 32] {
        self.session
    }

    /// Returns the final transcript.
    pub const fn transcript(&self) -> [u8; 32] {
        self.transcript
    }

    /// Returns the HPKE encapsulated key.
    pub const fn encapsulated_key(&self) -> &[u8; 32] {
        &self.encapsulated_key
    }

    /// Returns the opaque ciphertext.
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEd25519YaoEncryptedPackageV1 {
    kind: Ed25519YaoPackageKindV1,
    deriver: Ed25519YaoDeriverRoleV1,
    session: [u8; 32],
    transcript: [u8; 32],
    encapsulated_key: [u8; 32],
    ciphertext: Vec<u8>,
}

impl<'de> Deserialize<'de> for Ed25519YaoEncryptedPackageV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawEd25519YaoEncryptedPackageV1::deserialize(deserializer)?;
        Self::new(
            raw.kind,
            raw.deriver,
            raw.session,
            raw.transcript,
            raw.encapsulated_key,
            raw.ciphertext,
        )
        .map_err(D::Error::custom)
    }
}

/// Terminal Router result carrying only Client-recipient export packages.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RouterAbEd25519YaoExportResultV1 {
    binding: RouterAbEd25519YaoExportBindingV1,
    transcript: [u8; 32],
    deriver_a_client_package: Ed25519YaoEncryptedPackageV1,
    deriver_b_client_package: Ed25519YaoEncryptedPackageV1,
}

impl RouterAbEd25519YaoExportResultV1 {
    /// Creates a terminal export result from two Client-only packages.
    pub fn new(
        binding: RouterAbEd25519YaoExportBindingV1,
        transcript: [u8; 32],
        deriver_a_client_package: Ed25519YaoEncryptedPackageV1,
        deriver_b_client_package: Ed25519YaoEncryptedPackageV1,
    ) -> RouterAbProtocolResult<Self> {
        if transcript.iter().all(|byte| *byte == 0) {
            return Err(invalid_yao_wire(
                "Ed25519 Yao export result transcript must be nonzero",
            ));
        }
        validate_export_client_package(
            binding.ceremony(),
            transcript,
            &deriver_a_client_package,
            Ed25519YaoDeriverRoleV1::DeriverA,
        )?;
        validate_export_client_package(
            binding.ceremony(),
            transcript,
            &deriver_b_client_package,
            Ed25519YaoDeriverRoleV1::DeriverB,
        )?;
        Ok(Self {
            binding,
            transcript,
            deriver_a_client_package,
            deriver_b_client_package,
        })
    }

    /// Returns the exact admitted export binding.
    pub const fn binding(&self) -> &RouterAbEd25519YaoExportBindingV1 {
        &self.binding
    }

    /// Returns the final A/B transcript.
    pub const fn transcript(&self) -> [u8; 32] {
        self.transcript
    }

    /// Returns the Deriver A Client package.
    pub const fn deriver_a_client_package(&self) -> &Ed25519YaoEncryptedPackageV1 {
        &self.deriver_a_client_package
    }

    /// Returns the Deriver B Client package.
    pub const fn deriver_b_client_package(&self) -> &Ed25519YaoEncryptedPackageV1 {
        &self.deriver_b_client_package
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRouterAbEd25519YaoExportResultV1 {
    binding: RouterAbEd25519YaoExportBindingV1,
    transcript: [u8; 32],
    deriver_a_client_package: Ed25519YaoEncryptedPackageV1,
    deriver_b_client_package: Ed25519YaoEncryptedPackageV1,
}

impl<'de> Deserialize<'de> for RouterAbEd25519YaoExportResultV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawRouterAbEd25519YaoExportResultV1::deserialize(deserializer)?;
        Self::new(
            raw.binding,
            raw.transcript,
            raw.deriver_a_client_package,
            raw.deriver_b_client_package,
        )
        .map_err(D::Error::custom)
    }
}

/// Public activation evidence returned by successful registration or recovery execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RouterAbEd25519YaoActivationPublicReceiptV1 {
    transcript: [u8; 32],
    registered_public_key: [u8; 32],
    joined_client_commitment: [u8; 32],
    joined_signing_worker_commitment: [u8; 32],
    signing_worker_verifying_share: [u8; 32],
    state_epoch: Ed25519YaoStateEpochV1,
}

impl RouterAbEd25519YaoActivationPublicReceiptV1 {
    /// Creates nonzero public activation evidence.
    pub fn new(
        transcript: [u8; 32],
        registered_public_key: [u8; 32],
        joined_client_commitment: [u8; 32],
        joined_signing_worker_commitment: [u8; 32],
        signing_worker_verifying_share: [u8; 32],
        state_epoch: Ed25519YaoStateEpochV1,
    ) -> RouterAbProtocolResult<Self> {
        if [
            transcript,
            registered_public_key,
            joined_client_commitment,
            joined_signing_worker_commitment,
            signing_worker_verifying_share,
        ]
        .iter()
        .any(|value| value.iter().all(|byte| *byte == 0))
        {
            return Err(invalid_yao_wire(
                "Ed25519 Yao activation public receipt contains a zero field",
            ));
        }
        Ok(Self {
            transcript,
            registered_public_key,
            joined_client_commitment,
            joined_signing_worker_commitment,
            signing_worker_verifying_share,
            state_epoch,
        })
    }

    /// Returns the final ceremony transcript.
    pub const fn transcript(&self) -> [u8; 32] {
        self.transcript
    }

    /// Returns the registered Ed25519 public key.
    pub const fn registered_public_key(&self) -> [u8; 32] {
        self.registered_public_key
    }

    /// Returns the public commitment to the joined Client scalar share.
    pub const fn joined_client_commitment(&self) -> [u8; 32] {
        self.joined_client_commitment
    }

    /// Returns the public commitment to the joined SigningWorker scalar share.
    pub const fn joined_signing_worker_commitment(&self) -> [u8; 32] {
        self.joined_signing_worker_commitment
    }

    /// Returns the active SigningWorker verifying share.
    pub const fn signing_worker_verifying_share(&self) -> [u8; 32] {
        self.signing_worker_verifying_share
    }

    /// Returns the active SigningWorker state epoch.
    pub const fn state_epoch(&self) -> Ed25519YaoStateEpochV1 {
        self.state_epoch
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRouterAbEd25519YaoActivationPublicReceiptV1 {
    transcript: [u8; 32],
    registered_public_key: [u8; 32],
    joined_client_commitment: [u8; 32],
    joined_signing_worker_commitment: [u8; 32],
    signing_worker_verifying_share: [u8; 32],
    state_epoch: Ed25519YaoStateEpochV1,
}

impl<'de> Deserialize<'de> for RouterAbEd25519YaoActivationPublicReceiptV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawRouterAbEd25519YaoActivationPublicReceiptV1::deserialize(deserializer)?;
        Self::new(
            raw.transcript,
            raw.registered_public_key,
            raw.joined_client_commitment,
            raw.joined_signing_worker_commitment,
            raw.signing_worker_verifying_share,
            raw.state_epoch,
        )
        .map_err(D::Error::custom)
    }
}

/// Public activation result returned only after SigningWorker activation succeeds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RouterAbEd25519YaoActivationResultV1 {
    binding: Ed25519YaoCeremonyBindingV1,
    deriver_a_client_package: Ed25519YaoEncryptedPackageV1,
    deriver_b_client_package: Ed25519YaoEncryptedPackageV1,
    public_receipt: RouterAbEd25519YaoActivationPublicReceiptV1,
}

impl RouterAbEd25519YaoActivationResultV1 {
    /// Creates a terminal result from two role-specific Client packages.
    pub fn new(
        binding: Ed25519YaoCeremonyBindingV1,
        deriver_a_client_package: Ed25519YaoEncryptedPackageV1,
        deriver_b_client_package: Ed25519YaoEncryptedPackageV1,
        public_receipt: RouterAbEd25519YaoActivationPublicReceiptV1,
    ) -> RouterAbProtocolResult<Self> {
        binding.validate()?;
        if !matches!(
            binding.operation,
            Ed25519YaoOperationV1::Registration | Ed25519YaoOperationV1::Recovery
        ) {
            return Err(invalid_yao_wire(
                "Ed25519 Yao activation result has the wrong operation",
            ));
        }
        validate_activation_client_package(
            &binding,
            &public_receipt,
            &deriver_a_client_package,
            Ed25519YaoDeriverRoleV1::DeriverA,
        )?;
        validate_activation_client_package(
            &binding,
            &public_receipt,
            &deriver_b_client_package,
            Ed25519YaoDeriverRoleV1::DeriverB,
        )?;
        Ok(Self {
            binding,
            deriver_a_client_package,
            deriver_b_client_package,
            public_receipt,
        })
    }

    /// Returns the admitted binding.
    pub const fn binding(&self) -> &Ed25519YaoCeremonyBindingV1 {
        &self.binding
    }

    /// Returns the Deriver A Client package.
    pub const fn deriver_a_client_package(&self) -> &Ed25519YaoEncryptedPackageV1 {
        &self.deriver_a_client_package
    }

    /// Returns the Deriver B Client package.
    pub const fn deriver_b_client_package(&self) -> &Ed25519YaoEncryptedPackageV1 {
        &self.deriver_b_client_package
    }

    /// Returns public activation evidence.
    pub const fn public_receipt(&self) -> &RouterAbEd25519YaoActivationPublicReceiptV1 {
        &self.public_receipt
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRouterAbEd25519YaoActivationResultV1 {
    binding: Ed25519YaoCeremonyBindingV1,
    deriver_a_client_package: Ed25519YaoEncryptedPackageV1,
    deriver_b_client_package: Ed25519YaoEncryptedPackageV1,
    public_receipt: RouterAbEd25519YaoActivationPublicReceiptV1,
}

impl<'de> Deserialize<'de> for RouterAbEd25519YaoActivationResultV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawRouterAbEd25519YaoActivationResultV1::deserialize(deserializer)?;
        Self::new(
            raw.binding,
            raw.deriver_a_client_package,
            raw.deriver_b_client_package,
            raw.public_receipt,
        )
        .map_err(D::Error::custom)
    }
}

fn validate_activation_input(
    binding: &Ed25519YaoCeremonyBindingV1,
    input: &Ed25519YaoEncryptedInputV1,
    expected_deriver: Ed25519YaoDeriverRoleV1,
) -> RouterAbProtocolResult<()> {
    input.validate()?;
    if input.kind != Ed25519YaoInputKindV1::Activation
        || input.deriver != expected_deriver
        || input.operation != binding.operation
        || input.session != binding.session_id.into_bytes()
        || input.stable_context_binding != binding.stable_key_context_binding.into_bytes()
    {
        return Err(invalid_yao_wire(
            "Ed25519 Yao activation input does not match admission",
        ));
    }
    Ok(())
}

fn validate_export_input(
    binding: &Ed25519YaoCeremonyBindingV1,
    input: &Ed25519YaoEncryptedInputV1,
    expected_deriver: Ed25519YaoDeriverRoleV1,
) -> RouterAbProtocolResult<()> {
    input.validate()?;
    if binding.operation != Ed25519YaoOperationV1::Export
        || input.kind != Ed25519YaoInputKindV1::Export
        || input.deriver != expected_deriver
        || input.operation != Ed25519YaoOperationV1::Export
        || input.session != binding.session_id.into_bytes()
        || input.stable_context_binding != binding.stable_key_context_binding.into_bytes()
    {
        return Err(invalid_yao_wire(
            "Ed25519 Yao export input does not match admission",
        ));
    }
    Ok(())
}

fn validate_export_client_package(
    binding: &Ed25519YaoCeremonyBindingV1,
    transcript: [u8; 32],
    package: &Ed25519YaoEncryptedPackageV1,
    expected_deriver: Ed25519YaoDeriverRoleV1,
) -> RouterAbProtocolResult<()> {
    package.validate()?;
    if package.kind != Ed25519YaoPackageKindV1::ExportClient
        || package.deriver != expected_deriver
        || package.session != binding.session_id.into_bytes()
        || package.transcript != transcript
    {
        return Err(invalid_yao_wire(
            "Ed25519 Yao export Client package does not match terminal result",
        ));
    }
    Ok(())
}

fn validate_activation_client_package(
    binding: &Ed25519YaoCeremonyBindingV1,
    receipt: &RouterAbEd25519YaoActivationPublicReceiptV1,
    package: &Ed25519YaoEncryptedPackageV1,
    expected_deriver: Ed25519YaoDeriverRoleV1,
) -> RouterAbProtocolResult<()> {
    package.validate()?;
    if package.kind != Ed25519YaoPackageKindV1::ActivationClient
        || package.deriver != expected_deriver
        || package.session != binding.session_id.into_bytes()
        || package.transcript != receipt.transcript
    {
        return Err(invalid_yao_wire(
            "Ed25519 Yao activation Client package does not match terminal receipt",
        ));
    }
    Ok(())
}

fn validate_visible_identifier(field: &str, value: &str) -> RouterAbProtocolResult<()> {
    if value.is_empty() || !value.bytes().all(|byte| (0x21..=0x7e).contains(&byte)) {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("Ed25519 Yao {field} must contain visible ASCII bytes"),
        ));
    }
    if u32::try_from(value.len()).is_err() {
        return Err(invalid_yao_wire(
            "Ed25519 Yao identifier exceeds its length-delimited encoding",
        ));
    }
    Ok(())
}

fn validate_participant_ids(participant_ids: [u16; 2]) -> RouterAbProtocolResult<()> {
    if participant_ids[0] == 0
        || participant_ids[1] == 0
        || participant_ids[0] >= participant_ids[1]
    {
        return Err(invalid_yao_wire(
            "Ed25519 Yao participant ids must be distinct, nonzero, and ascending",
        ));
    }
    Ok(())
}

fn invalid_yao_wire(message: &'static str) -> RouterAbProtocolError {
    RouterAbProtocolError::new(RouterAbProtocolErrorCode::MalformedWirePayload, message)
}

#[cfg(test)]
mod tests {
    use crate::derivation::RootShareEpoch;

    use super::*;

    fn lifecycle(work_kind: ExpensiveWorkKindV1) -> LifecycleScopeV1 {
        LifecycleScopeV1::new(
            "lifecycle-1",
            work_kind,
            RootShareEpoch::new("epoch-1").expect("epoch"),
            "account-1",
            "wallet-session-1",
            "signer-set-1",
            "signing-worker-1",
        )
        .expect("lifecycle")
    }

    fn registration_binding() -> Ed25519YaoCeremonyBindingV1 {
        Ed25519YaoCeremonyBindingV1::new(
            lifecycle(ExpensiveWorkKindV1::RegistrationPrepare),
            Ed25519YaoOperationV1::Registration,
            Ed25519YaoSessionIdV1::new([7; 32]).expect("session"),
            Ed25519YaoStableKeyContextBindingV1::new([8; 32]),
        )
        .expect("registration binding")
    }

    fn encrypted_input_for(
        binding: &Ed25519YaoCeremonyBindingV1,
        deriver: Ed25519YaoDeriverRoleV1,
    ) -> Ed25519YaoEncryptedInputV1 {
        Ed25519YaoEncryptedInputV1::new(
            Ed25519YaoInputKindV1::Activation,
            deriver,
            binding.operation,
            binding.session_id.into_bytes(),
            binding.stable_key_context_binding.into_bytes(),
            [9; 32],
            vec![10; 32],
        )
        .expect("encrypted input")
    }

    fn public_receipt() -> RouterAbEd25519YaoActivationPublicReceiptV1 {
        RouterAbEd25519YaoActivationPublicReceiptV1::new(
            [11; 32],
            [12; 32],
            [13; 32],
            [14; 32],
            [15; 32],
            Ed25519YaoStateEpochV1::new(1).expect("state epoch"),
        )
        .expect("public receipt")
    }

    fn client_package(
        deriver: Ed25519YaoDeriverRoleV1,
        transcript: [u8; 32],
    ) -> Ed25519YaoEncryptedPackageV1 {
        Ed25519YaoEncryptedPackageV1::new(
            Ed25519YaoPackageKindV1::ActivationClient,
            deriver,
            [7; 32],
            transcript,
            [16; 32],
            vec![17; 32],
        )
        .expect("client package")
    }

    #[test]
    fn operation_selects_one_family_and_matching_work_kind() {
        let session = Ed25519YaoSessionIdV1::new([7; 32]).expect("session");
        let registration = Ed25519YaoCeremonyBindingV1::new(
            lifecycle(ExpensiveWorkKindV1::RegistrationPrepare),
            Ed25519YaoOperationV1::Registration,
            session,
            Ed25519YaoStableKeyContextBindingV1::new([8; 32]),
        )
        .expect("registration");
        assert_eq!(
            registration.circuit_family(),
            Ed25519YaoCircuitFamilyV1::Activation
        );

        let mismatch = Ed25519YaoCeremonyBindingV1::new(
            lifecycle(ExpensiveWorkKindV1::KeyExport),
            Ed25519YaoOperationV1::Recovery,
            session,
            Ed25519YaoStableKeyContextBindingV1::new([8; 32]),
        );
        assert!(mismatch.is_err());
    }

    #[test]
    fn zero_session_is_rejected() {
        assert!(Ed25519YaoSessionIdV1::new([0; 32]).is_err());
    }

    #[test]
    fn refresh_binding_requires_strictly_advancing_epochs() {
        let current = Ed25519YaoStateEpochV1::new(4).expect("current");
        let next = Ed25519YaoStateEpochV1::new(5).expect("next");
        let transition = Ed25519YaoEpochTransitionV1::new(current, next).expect("transition");
        assert!(Ed25519YaoEpochTransitionV1::new(current, current).is_err());
        let ceremony = Ed25519YaoCeremonyBindingV1::new(
            lifecycle(ExpensiveWorkKindV1::ServerShareRefresh),
            Ed25519YaoOperationV1::Refresh,
            Ed25519YaoSessionIdV1::new([9; 32]).expect("session"),
            Ed25519YaoStableKeyContextBindingV1::new([8; 32]),
        )
        .expect("refresh ceremony");
        let binding = Ed25519YaoRefreshBindingV1::new(
            ceremony,
            [7; 32],
            Ed25519YaoRefreshEpochsV1 {
                deriver_a: transition,
                deriver_b: transition,
                signing_worker: transition,
            },
        )
        .expect("refresh binding");
        assert_eq!(binding.epochs().deriver_a.next().get(), 5);
    }

    #[test]
    fn refresh_wire_types_reject_constructor_bypasses() {
        assert!(serde_json::from_str::<Ed25519YaoStateEpochV1>("0").is_err());
        assert!(
            serde_json::from_str::<Ed25519YaoEpochTransitionV1>(r#"{"current":1,"next":1}"#,)
                .is_err()
        );
        assert!(
            serde_json::from_str::<Ed25519YaoEpochTransitionV1>(r#"{"current":1,"next":3}"#,)
                .is_ok()
        );

        let transition = Ed25519YaoEpochTransitionV1::new(
            Ed25519YaoStateEpochV1::new(1).expect("current"),
            Ed25519YaoStateEpochV1::new(2).expect("next"),
        )
        .expect("transition");
        let ceremony = Ed25519YaoCeremonyBindingV1::new(
            lifecycle(ExpensiveWorkKindV1::ServerShareRefresh),
            Ed25519YaoOperationV1::Refresh,
            Ed25519YaoSessionIdV1::new([9; 32]).expect("session"),
            Ed25519YaoStableKeyContextBindingV1::new([8; 32]),
        )
        .expect("ceremony");
        let binding = Ed25519YaoRefreshBindingV1::new(
            ceremony,
            [7; 32],
            Ed25519YaoRefreshEpochsV1 {
                deriver_a: transition,
                deriver_b: transition,
                signing_worker: transition,
            },
        )
        .expect("binding");
        let mut value = serde_json::to_value(binding).expect("serialize");
        value["registered_public_key"] = serde_json::to_value([0_u8; 32]).expect("zero key");
        assert!(serde_json::from_value::<Ed25519YaoRefreshBindingV1>(value).is_err());
    }

    #[test]
    fn registration_admission_wire_types_reject_invalid_identity_and_participants() {
        let scope = RouterAbEd25519YaoLifecycleScopeV1::new(
            "registration-1",
            RootShareEpoch::new("epoch-1").expect("epoch"),
            "account-1",
            "wallet-session-1",
            "signer-set-1",
            "signing-worker-1",
        )
        .expect("scope");
        let application = RouterAbEd25519YaoApplicationBindingFactsV1::new(
            "wallet-1",
            "ed25519ks_1",
            "project:local",
            1,
        )
        .expect("application");
        let request =
            RouterAbEd25519YaoRegistrationAdmissionRequestV1::new(scope, application, [1, 2])
                .expect("request");

        let mut duplicate_participants = serde_json::to_value(&request).expect("request JSON");
        duplicate_participants["participant_ids"] = serde_json::json!([1, 1]);
        assert!(
            serde_json::from_value::<RouterAbEd25519YaoRegistrationAdmissionRequestV1>(
                duplicate_participants
            )
            .is_err()
        );

        let mut descending_participants = serde_json::to_value(&request).expect("request JSON");
        descending_participants["participant_ids"] = serde_json::json!([2, 1]);
        assert!(
            serde_json::from_value::<RouterAbEd25519YaoRegistrationAdmissionRequestV1>(
                descending_participants
            )
            .is_err()
        );

        let mut empty_identity = serde_json::to_value(request).expect("request JSON");
        empty_identity["application_binding"]["wallet_id"] = serde_json::json!("");
        assert!(
            serde_json::from_value::<RouterAbEd25519YaoRegistrationAdmissionRequestV1>(
                empty_identity
            )
            .is_err()
        );
    }

    #[test]
    fn activation_keyset_rejects_zero_and_duplicate_recipient_keys() {
        assert!(RouterAbEd25519YaoActivationKeysetV1::new([0; 32], [2; 32], [3; 32]).is_err());
        assert!(RouterAbEd25519YaoActivationKeysetV1::new([1; 32], [1; 32], [3; 32]).is_err());
        assert!(RouterAbEd25519YaoActivationKeysetV1::new([1; 32], [2; 32], [3; 32]).is_ok());
    }

    #[test]
    fn registration_execution_rejects_mixed_roles_sessions_and_unbounded_ciphertext() {
        let binding = registration_binding();
        let input_a = encrypted_input_for(&binding, Ed25519YaoDeriverRoleV1::DeriverA);
        let input_b = encrypted_input_for(&binding, Ed25519YaoDeriverRoleV1::DeriverB);
        assert!(RouterAbEd25519YaoActivationExecuteRequestV1::new(
            binding.clone(),
            input_a.clone(),
            input_b.clone(),
        )
        .is_ok());
        assert!(RouterAbEd25519YaoActivationExecuteRequestV1::new(
            binding.clone(),
            input_b.clone(),
            input_a,
        )
        .is_err());

        let mixed_session = Ed25519YaoEncryptedInputV1::new(
            input_b.kind(),
            input_b.deriver(),
            input_b.operation(),
            [18; 32],
            input_b.stable_context_binding(),
            *input_b.encapsulated_key(),
            input_b.ciphertext().to_vec(),
        )
        .expect("mixed-session input");
        assert!(RouterAbEd25519YaoActivationExecuteRequestV1::new(
            binding,
            encrypted_input_for(&registration_binding(), Ed25519YaoDeriverRoleV1::DeriverA),
            mixed_session,
        )
        .is_err());

        assert!(Ed25519YaoEncryptedInputV1::new(
            Ed25519YaoInputKindV1::Activation,
            Ed25519YaoDeriverRoleV1::DeriverA,
            Ed25519YaoOperationV1::Registration,
            [7; 32],
            [8; 32],
            [9; 32],
            vec![10; ED25519_YAO_CONTROL_CIPHERTEXT_MAX_BYTES_V1 + 1],
        )
        .is_err());
    }

    #[test]
    fn registration_result_rejects_wrong_role_and_transcript_packages() {
        let binding = registration_binding();
        let receipt = public_receipt();
        let package_a = client_package(Ed25519YaoDeriverRoleV1::DeriverA, receipt.transcript());
        let package_b = client_package(Ed25519YaoDeriverRoleV1::DeriverB, receipt.transcript());
        assert!(RouterAbEd25519YaoActivationResultV1::new(
            binding.clone(),
            package_a.clone(),
            package_b.clone(),
            receipt.clone(),
        )
        .is_ok());
        assert!(RouterAbEd25519YaoActivationResultV1::new(
            binding.clone(),
            package_b,
            package_a,
            receipt.clone(),
        )
        .is_err());
        assert!(RouterAbEd25519YaoActivationResultV1::new(
            binding,
            client_package(Ed25519YaoDeriverRoleV1::DeriverA, [19; 32]),
            client_package(Ed25519YaoDeriverRoleV1::DeriverB, receipt.transcript()),
            receipt,
        )
        .is_err());
    }

    #[test]
    fn recovery_uses_the_same_activation_wire_types() {
        let binding = Ed25519YaoCeremonyBindingV1::new(
            lifecycle(ExpensiveWorkKindV1::Recovery),
            Ed25519YaoOperationV1::Recovery,
            Ed25519YaoSessionIdV1::new([7; 32]).expect("session"),
            Ed25519YaoStableKeyContextBindingV1::new([8; 32]),
        )
        .expect("recovery binding");
        let request = RouterAbEd25519YaoActivationExecuteRequestV1::new(
            binding.clone(),
            encrypted_input_for(&binding, Ed25519YaoDeriverRoleV1::DeriverA),
            encrypted_input_for(&binding, Ed25519YaoDeriverRoleV1::DeriverB),
        )
        .expect("recovery request");
        assert_eq!(request.binding().operation, Ed25519YaoOperationV1::Recovery);

        let receipt = public_receipt();
        RouterAbEd25519YaoActivationResultV1::new(
            binding,
            client_package(Ed25519YaoDeriverRoleV1::DeriverA, receipt.transcript()),
            client_package(Ed25519YaoDeriverRoleV1::DeriverB, receipt.transcript()),
            receipt,
        )
        .expect("recovery result");
    }
}
