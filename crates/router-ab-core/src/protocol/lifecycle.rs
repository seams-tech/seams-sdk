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
    /// Selected relayer identity.
    pub selected_relayer_id: String,
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
        selected_relayer_id: impl Into<String>,
    ) -> RouterAbProtocolResult<Self> {
        let scope = Self {
            lifecycle_id: lifecycle_id.into(),
            work_kind,
            primitive_request_kind: work_kind.primitive_request_kind(),
            root_share_epoch,
            account_id: account_id.into(),
            session_id: session_id.into(),
            signer_set_id: signer_set_id.into(),
            selected_relayer_id: selected_relayer_id.into(),
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
        require_non_empty("selected_relayer_id", &self.selected_relayer_id)?;
        if self.primitive_request_kind != self.work_kind.primitive_request_kind() {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLifecycleState,
                "lifecycle primitive request kind does not match product work kind",
            ));
        }
        Ok(())
    }
}

/// Normal signing scope that bypasses A/B derivation setup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalSigningScopeV1 {
    /// Router-assigned signing request id.
    pub request_id: String,
    /// Canonical account or wallet id.
    pub account_id: String,
    /// Canonical session id.
    pub session_id: String,
    /// Active relayer identity.
    pub relayer_id: String,
}

impl NormalSigningScopeV1 {
    /// Creates a validated normal-signing scope.
    pub fn new(
        request_id: impl Into<String>,
        account_id: impl Into<String>,
        session_id: impl Into<String>,
        relayer_id: impl Into<String>,
    ) -> RouterAbProtocolResult<Self> {
        let scope = Self {
            request_id: request_id.into(),
            account_id: account_id.into(),
            session_id: session_id.into(),
            relayer_id: relayer_id.into(),
        };
        scope.validate()?;
        Ok(scope)
    }

    /// Validates normal-signing identity fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("request_id", &self.request_id)?;
        require_non_empty("account_id", &self.account_id)?;
        require_non_empty("session_id", &self.session_id)?;
        require_non_empty("relayer_id", &self.relayer_id)
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
    /// Gate rejected work before signer/HSS capacity was allocated.
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
