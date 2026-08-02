use crate::derivation::{RequestKind, RootShareEpoch};
use serde::{Deserialize, Serialize};

use crate::protocol::error::{
    RouterAbProtocolError, RouterAbProtocolErrorCode, RouterAbProtocolResult,
};
use crate::protocol::gate::{
    ExpensiveWorkGateDecisionV1, ExpensiveWorkKindV1, GateDeferReasonV1, GateRejectReasonV1,
};

/// Public scope shared by Router lifecycle states.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "typescript-bindings", derive(ts_rs::TS))]
#[cfg_attr(
    feature = "typescript-bindings",
    ts(rename = "RouterAbEd25519YaoAdmittedLifecycleV1")
)]
pub struct LifecycleScopeV1 {
    /// Router-assigned lifecycle id.
    pub lifecycle_id: String,
    /// Product-level protected work kind.
    pub work_kind: ExpensiveWorkKindV1,
    /// Primitive derivation request kind.
    pub primitive_request_kind: RequestKind,
    /// Public signing-root share epoch used by this ceremony.
    pub root_share_epoch: RootShareEpoch,
    /// Canonical account or wallet id.
    pub account_id: String,
    /// Canonical session id.
    pub session_id: String,
    /// Signer set id bound into the transcript.
    pub signer_set_id: String,
    /// Selected server identity.
    pub selected_server_id: String,
}

impl LifecycleScopeV1 {
    /// Creates a validated lifecycle scope.
    pub fn new(
        lifecycle_id: impl Into<String>,
        work_kind: ExpensiveWorkKindV1,
        root_share_epoch: RootShareEpoch,
        account_id: impl Into<String>,
        session_id: impl Into<String>,
        signer_set_id: impl Into<String>,
        selected_server_id: impl Into<String>,
    ) -> RouterAbProtocolResult<Self> {
        let scope = Self {
            lifecycle_id: lifecycle_id.into(),
            work_kind,
            primitive_request_kind: work_kind.primitive_request_kind(),
            root_share_epoch,
            account_id: account_id.into(),
            session_id: session_id.into(),
            signer_set_id: signer_set_id.into(),
            selected_server_id: selected_server_id.into(),
        };
        scope.validate()?;
        Ok(scope)
    }

    /// Validates required lifecycle identity fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("lifecycle_id", &self.lifecycle_id)?;
        require_non_empty("root_share_epoch", self.root_share_epoch.as_str())?;
        require_non_empty("account_id", &self.account_id)?;
        require_non_empty("session_id", &self.session_id)?;
        require_non_empty("signer_set_id", &self.signer_set_id)?;
        require_non_empty("selected_server_id", &self.selected_server_id)?;
        if self.primitive_request_kind != self.work_kind.primitive_request_kind() {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLifecycleState,
                "lifecycle primitive request kind does not match product work kind",
            ));
        }
        Ok(())
    }
}

/// Operation authority for one normal-signing request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum NormalSigningAuthorizationV1 {
    /// Reusable Wallet Session authority. The Gateway derives the exact operation grant.
    ReusableWalletSession { wallet_session_id: String },
    /// Single-operation step-up authority.
    OperationStepUp { grant_id: String },
}

impl NormalSigningAuthorizationV1 {
    /// Creates validated reusable Wallet Session authority.
    pub fn reusable_wallet_session(
        wallet_session_id: impl Into<String>,
    ) -> RouterAbProtocolResult<Self> {
        let authorization = Self::ReusableWalletSession {
            wallet_session_id: wallet_session_id.into(),
        };
        authorization.validate()?;
        Ok(authorization)
    }

    /// Creates validated single-operation step-up authority.
    pub fn operation_step_up(grant_id: impl Into<String>) -> RouterAbProtocolResult<Self> {
        let authorization = Self::OperationStepUp {
            grant_id: grant_id.into(),
        };
        authorization.validate()?;
        Ok(authorization)
    }

    /// Validates the exact authorization identity.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        match self {
            Self::ReusableWalletSession { wallet_session_id } => {
                require_non_empty("authorization.wallet_session_id", wallet_session_id)
            }
            Self::OperationStepUp { grant_id } => {
                require_non_empty("authorization.grant_id", grant_id)
            }
        }
    }

    /// Returns the canonical wire label of the authorization branch.
    pub fn kind_label(&self) -> &'static str {
        match self {
            Self::ReusableWalletSession { .. } => "reusable_wallet_session",
            Self::OperationStepUp { .. } => "operation_step_up",
        }
    }

    /// Returns the exact identifier carried by the authorization branch.
    pub fn authorization_id(&self) -> &str {
        match self {
            Self::ReusableWalletSession { wallet_session_id } => wallet_session_id,
            Self::OperationStepUp { grant_id } => grant_id,
        }
    }

    /// Returns the exact reusable Wallet Session id or fails closed for step-up authority.
    pub fn reusable_wallet_session_id(&self) -> RouterAbProtocolResult<&str> {
        self.validate()?;
        match self {
            Self::ReusableWalletSession {
                wallet_session_id, ..
            } => Ok(wallet_session_id),
            Self::OperationStepUp { .. } => Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "operation step-up authority has no reusable Wallet Session id",
            )),
        }
    }

    /// Returns the pre-issued capability grant id for operation step-up authority.
    pub fn operation_step_up_grant_id(&self) -> RouterAbProtocolResult<&str> {
        self.validate()?;
        match self {
            Self::OperationStepUp { grant_id } => Ok(grant_id),
            Self::ReusableWalletSession { .. } => Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "reusable Wallet Session authority has no pre-issued operation grant",
            )),
        }
    }
}

/// Exact activated MPC material used by one normal-signing request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "typescript-bindings", derive(ts_rs::TS))]
#[cfg_attr(
    feature = "typescript-bindings",
    ts(
        rename = "RouterAbMpcMaterialActivationRefKindV1",
        rename_all = "snake_case"
    )
)]
pub enum MpcMaterialActivationRefKindV1 {
    /// Exact MPC material-activation reference.
    MpcMaterialActivationRef,
}

/// Exact activated MPC material used by one normal-signing request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "typescript-bindings", derive(ts_rs::TS))]
#[cfg_attr(
    feature = "typescript-bindings",
    ts(rename = "RouterAbMpcMaterialActivationRefV1")
)]
pub struct MpcMaterialActivationRefV1 {
    /// Wire discriminant.
    pub kind: MpcMaterialActivationRefKindV1,
    /// Opaque activation id.
    pub activation_id: String,
    /// Activated capability instance.
    pub capability: String,
    /// Owner of the activated material.
    pub material_owner: String,
    /// Public-key binding.
    pub key_binding: String,
    /// Lifecycle binding.
    pub lifecycle_binding: String,
    /// SigningWorker that owns the live material.
    pub signing_worker: String,
}

impl MpcMaterialActivationRefV1 {
    /// Creates a validated material-activation reference.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        activation_id: impl Into<String>,
        capability: impl Into<String>,
        material_owner: impl Into<String>,
        key_binding: impl Into<String>,
        lifecycle_binding: impl Into<String>,
        signing_worker: impl Into<String>,
    ) -> RouterAbProtocolResult<Self> {
        let activation = Self {
            kind: MpcMaterialActivationRefKindV1::MpcMaterialActivationRef,
            activation_id: activation_id.into(),
            capability: capability.into(),
            material_owner: material_owner.into(),
            key_binding: key_binding.into(),
            lifecycle_binding: lifecycle_binding.into(),
            signing_worker: signing_worker.into(),
        };
        activation.validate()?;
        Ok(activation)
    }

    /// Validates every material-activation binding.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("material_activation.activation_id", &self.activation_id)?;
        require_non_empty("material_activation.capability", &self.capability)?;
        require_non_empty("material_activation.material_owner", &self.material_owner)?;
        require_non_empty("material_activation.key_binding", &self.key_binding)?;
        require_non_empty(
            "material_activation.lifecycle_binding",
            &self.lifecycle_binding,
        )?;
        require_non_empty("material_activation.signing_worker", &self.signing_worker)
    }
}

/// Normal signing scope that bypasses A/B derivation setup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormalSigningScopeV1 {
    /// Router-assigned signing request id.
    pub request_id: String,
    /// Canonical account or wallet id.
    pub account_id: String,
    /// Exact operation authority, independent from material identity.
    pub authorization: NormalSigningAuthorizationV1,
    /// Exact activated MPC material.
    pub material_activation: MpcMaterialActivationRefV1,
    /// Active SigningWorker identity.
    pub signing_worker_id: String,
}

impl NormalSigningScopeV1 {
    /// Creates a validated normal-signing scope.
    pub fn new(
        request_id: impl Into<String>,
        account_id: impl Into<String>,
        authorization: NormalSigningAuthorizationV1,
        material_activation: MpcMaterialActivationRefV1,
        signing_worker_id: impl Into<String>,
    ) -> RouterAbProtocolResult<Self> {
        let scope = Self {
            request_id: request_id.into(),
            account_id: account_id.into(),
            authorization,
            material_activation,
            signing_worker_id: signing_worker_id.into(),
        };
        scope.validate()?;
        Ok(scope)
    }

    /// Validates normal-signing identity fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("request_id", &self.request_id)?;
        require_non_empty("account_id", &self.account_id)?;
        self.authorization.validate()?;
        self.material_activation.validate()?;
        require_non_empty("signing_worker_id", &self.signing_worker_id)?;
        if self.material_activation.signing_worker != self.signing_worker_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLifecycleState,
                "material activation SigningWorker does not match normal signing scope",
            ));
        }
        Ok(())
    }
}

/// Reason a setup lifecycle should use the slower authority-verified path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityVerifiedFallbackReasonV1 {
    /// Early prepare is disabled by deployment, org, project, or incident policy.
    EarlyPrepareDisabled,
    /// Short-window expensive-work gate is saturated.
    ShortWindowSaturated,
    /// Signer queue expensive-work gate is saturated.
    SignerQueueSaturated,
}

impl From<GateDeferReasonV1> for AuthorityVerifiedFallbackReasonV1 {
    fn from(reason: GateDeferReasonV1) -> Self {
        match reason {
            GateDeferReasonV1::ShortWindowSaturated => Self::ShortWindowSaturated,
            GateDeferReasonV1::SignerQueueSaturated => Self::SignerQueueSaturated,
        }
    }
}

/// Router lifecycle state around admission and signer dispatch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum RouterAbLifecycleStateV1 {
    /// Router has normalized scope and has not yet admitted expensive work.
    Requested {
        /// Lifecycle scope.
        scope: LifecycleScopeV1,
    },
    /// Gate accepted new expensive work.
    GateAccepted {
        /// Lifecycle scope.
        scope: LifecycleScopeV1,
        /// Router-assigned request id.
        request_id: String,
    },
    /// Gate selected an existing active lifecycle.
    GateReusingExisting {
        /// Lifecycle scope.
        scope: LifecycleScopeV1,
        /// Router-assigned request id.
        request_id: String,
        /// Existing lifecycle id.
        existing_lifecycle_id: String,
    },
    /// Gate deferred work so caller can use fallback or retry.
    GateDeferred {
        /// Lifecycle scope.
        scope: LifecycleScopeV1,
        /// Deferral reason.
        reason: GateDeferReasonV1,
    },
    /// Gate rejected work before signer/cryptographic capacity was allocated.
    GateRejected {
        /// Lifecycle scope.
        scope: LifecycleScopeV1,
        /// Rejection reason.
        reason: GateRejectReasonV1,
        /// Retry-after duration in milliseconds.
        retry_after_ms: u64,
    },
    /// Expensive early prepare is bypassed and the slower authority-verified path remains available.
    AuthorityVerifiedFallback {
        /// Lifecycle scope.
        scope: LifecycleScopeV1,
        /// Fallback reason.
        reason: AuthorityVerifiedFallbackReasonV1,
    },
}

impl RouterAbLifecycleStateV1 {
    /// Creates the initial requested state.
    pub fn requested(scope: LifecycleScopeV1) -> RouterAbProtocolResult<Self> {
        scope.validate()?;
        Ok(Self::Requested { scope })
    }

    /// Applies a gate decision to a requested lifecycle.
    pub fn apply_gate_decision(
        scope: LifecycleScopeV1,
        decision: ExpensiveWorkGateDecisionV1,
    ) -> RouterAbProtocolResult<Self> {
        scope.validate()?;
        decision.validate()?;
        match decision {
            ExpensiveWorkGateDecisionV1::Accepted { request_id } => {
                Ok(Self::GateAccepted { scope, request_id })
            }
            ExpensiveWorkGateDecisionV1::ReuseExisting {
                request_id,
                existing_lifecycle_id,
            } => Ok(Self::GateReusingExisting {
                scope,
                request_id,
                existing_lifecycle_id,
            }),
            ExpensiveWorkGateDecisionV1::Defer { reason } => {
                Ok(Self::GateDeferred { scope, reason })
            }
            ExpensiveWorkGateDecisionV1::Rejected {
                reason,
                retry_after_ms,
            } => Ok(Self::GateRejected {
                scope,
                reason,
                retry_after_ms,
            }),
        }
    }

    /// Creates a fallback state for the slower authority-verified path.
    pub fn authority_verified_fallback(
        scope: LifecycleScopeV1,
        reason: AuthorityVerifiedFallbackReasonV1,
    ) -> RouterAbProtocolResult<Self> {
        scope.validate()?;
        Ok(Self::AuthorityVerifiedFallback { scope, reason })
    }

    /// Returns lifecycle scope for every branch.
    pub fn scope(&self) -> &LifecycleScopeV1 {
        match self {
            Self::Requested { scope }
            | Self::GateAccepted { scope, .. }
            | Self::GateReusingExisting { scope, .. }
            | Self::GateDeferred { scope, .. }
            | Self::GateRejected { scope, .. }
            | Self::AuthorityVerifiedFallback { scope, .. } => scope,
        }
    }

    /// Validates required state fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.scope().validate()?;
        match self {
            Self::Requested { .. }
            | Self::GateDeferred { .. }
            | Self::GateRejected { .. }
            | Self::AuthorityVerifiedFallback { .. } => Ok(()),
            Self::GateAccepted { request_id, .. } => require_non_empty("request_id", request_id),
            Self::GateReusingExisting {
                request_id,
                existing_lifecycle_id,
                ..
            } => {
                require_non_empty("request_id", request_id)?;
                require_non_empty("existing_lifecycle_id", existing_lifecycle_id)
            }
        }
    }

    /// Validates the Router admission lifecycle transition before persistence.
    pub fn validate_transition_from(
        previous: Option<&Self>,
        next: &Self,
    ) -> RouterAbProtocolResult<()> {
        next.validate()?;
        let Some(previous) = previous else {
            return match next {
                Self::Requested { .. } => Ok(()),
                _ => Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidLifecycleState,
                    "router lifecycle must start in requested state",
                )),
            };
        };
        previous.validate()?;
        if previous == next {
            return Ok(());
        }
        if previous.scope() != next.scope() {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLifecycleState,
                "router lifecycle transition changed scope",
            ));
        }
        match (previous, next) {
            (
                Self::Requested { .. },
                Self::GateAccepted { .. }
                | Self::GateReusingExisting { .. }
                | Self::GateDeferred { .. }
                | Self::GateRejected { .. }
                | Self::AuthorityVerifiedFallback { .. },
            ) => Ok(()),
            _ => Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLifecycleState,
                "invalid router lifecycle transition",
            )),
        }
    }
}

fn require_non_empty(field: &'static str, value: &str) -> RouterAbProtocolResult<()> {
    if value.is_empty() {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::EmptyField,
            format!("{field} is required"),
        ));
    }
    Ok(())
}
