use crate::derivation::{PublicDigest32, RequestKind};
use serde::{Deserialize, Serialize};

use crate::protocol::error::{
    RouterAbProtocolError, RouterAbProtocolErrorCode, RouterAbProtocolResult,
};

/// Expensive-work class protected by Router admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpensiveWorkKindV1 {
    /// Early registration preparation before expensive signer/HSS work.
    RegistrationPrepare,
    /// Key export setup ceremony.
    KeyExport,
    /// Recovery setup ceremony.
    Recovery,
    /// Relayer-share refresh ceremony.
    RelayerShareRefresh,
}

impl ExpensiveWorkKindV1 {
    /// Returns the canonical work-kind label.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RegistrationPrepare => "registration_prepare",
            Self::KeyExport => "key_export",
            Self::Recovery => "recovery",
            Self::RelayerShareRefresh => "relayer_share_refresh",
        }
    }

    /// Returns the primitive derivation request kind associated with this gate.
    pub fn primitive_request_kind(self) -> RequestKind {
        match self {
            Self::RegistrationPrepare => RequestKind::Registration,
            Self::KeyExport | Self::Recovery => RequestKind::Export,
            Self::RelayerShareRefresh => RequestKind::Refresh,
        }
    }
}

/// Principal shape used to derive an admission key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GatePrincipalV1 {
    /// Fully authenticated user/session.
    AuthenticatedSession {
        /// Canonical user or subject id.
        subject_id: String,
        /// Canonical session id.
        session_id: String,
    },
    /// Pre-auth browser or device session scoped to registration preparation.
    PreAuthSession {
        /// Coarse server-derived session id.
        pre_auth_session_id: String,
    },
}

impl GatePrincipalV1 {
    /// Creates an authenticated-session principal.
    pub fn authenticated_session(
        subject_id: impl Into<String>,
        session_id: impl Into<String>,
    ) -> RouterAbProtocolResult<Self> {
        let principal = Self::AuthenticatedSession {
            subject_id: subject_id.into(),
            session_id: session_id.into(),
        };
        principal.validate()?;
        Ok(principal)
    }

    /// Creates a pre-auth session principal.
    pub fn pre_auth_session(
        pre_auth_session_id: impl Into<String>,
    ) -> RouterAbProtocolResult<Self> {
        let principal = Self::PreAuthSession {
            pre_auth_session_id: pre_auth_session_id.into(),
        };
        principal.validate()?;
        Ok(principal)
    }

    /// Validates branch-specific identity fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        match self {
            Self::AuthenticatedSession {
                subject_id,
                session_id,
            } => {
                require_non_empty("subject_id", subject_id)?;
                require_non_empty("session_id", session_id)
            }
            Self::PreAuthSession {
                pre_auth_session_id,
            } => require_non_empty("pre_auth_session_id", pre_auth_session_id),
        }
    }
}

/// Router-owned context for an expensive-work admission decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpensiveWorkGateContextV1 {
    /// Protected work class.
    pub work_kind: ExpensiveWorkKindV1,
    /// Canonical organization id.
    pub org_id: String,
    /// Canonical project id.
    pub project_id: String,
    /// Deployment environment label.
    pub environment: String,
    /// Account, wallet, or root resource id.
    pub resource_id: String,
    /// Server-derived principal.
    pub principal: GatePrincipalV1,
    /// Digest of trusted source metadata, such as IP or edge client address.
    pub trusted_source_digest: PublicDigest32,
}

impl ExpensiveWorkGateContextV1 {
    /// Creates a validated gate context.
    pub fn new(
        work_kind: ExpensiveWorkKindV1,
        org_id: impl Into<String>,
        project_id: impl Into<String>,
        environment: impl Into<String>,
        resource_id: impl Into<String>,
        principal: GatePrincipalV1,
        trusted_source_digest: PublicDigest32,
    ) -> RouterAbProtocolResult<Self> {
        let context = Self {
            work_kind,
            org_id: org_id.into(),
            project_id: project_id.into(),
            environment: environment.into(),
            resource_id: resource_id.into(),
            principal,
            trusted_source_digest,
        };
        context.validate()?;
        Ok(context)
    }

    /// Validates public gate context fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("org_id", &self.org_id)?;
        require_non_empty("project_id", &self.project_id)?;
        require_non_empty("environment", &self.environment)?;
        require_non_empty("resource_id", &self.resource_id)?;
        self.principal.validate()
    }
}

/// Reason a request is deferred without consuming expensive signer capacity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateDeferReasonV1 {
    /// Short-window gate is saturated for this admission key.
    ShortWindowSaturated,
    /// Signer queue is saturated and the caller should retry or use fallback.
    SignerQueueSaturated,
}

/// Reason a request is rejected before signer work.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateRejectReasonV1 {
    /// Request exceeded policy rate limits.
    RateLimited,
    /// Abuse policy rejected the request.
    AbusePolicy,
}

/// Router admission result for expensive setup, export, recovery, and refresh.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ExpensiveWorkGateDecisionV1 {
    /// Request may allocate signer/HSS capacity.
    Accepted {
        /// Router-assigned request id.
        request_id: String,
    },
    /// Existing active lifecycle should be reused.
    ReuseExisting {
        /// Router-assigned request id.
        request_id: String,
        /// Existing lifecycle id.
        existing_lifecycle_id: String,
    },
    /// Request should use fallback or retry later.
    Defer {
        /// Deferral reason.
        reason: GateDeferReasonV1,
    },
    /// Request is rejected before signer/HSS work.
    Rejected {
        /// Rejection reason.
        reason: GateRejectReasonV1,
        /// Retry-after duration in milliseconds.
        retry_after_ms: u64,
    },
}

impl ExpensiveWorkGateDecisionV1 {
    /// Creates an accepted gate decision.
    pub fn accepted(request_id: impl Into<String>) -> RouterAbProtocolResult<Self> {
        let decision = Self::Accepted {
            request_id: request_id.into(),
        };
        decision.validate()?;
        Ok(decision)
    }

    /// Creates a reuse-existing gate decision.
    pub fn reuse_existing(
        request_id: impl Into<String>,
        existing_lifecycle_id: impl Into<String>,
    ) -> RouterAbProtocolResult<Self> {
        let decision = Self::ReuseExisting {
            request_id: request_id.into(),
            existing_lifecycle_id: existing_lifecycle_id.into(),
        };
        decision.validate()?;
        Ok(decision)
    }

    /// Creates a deferral gate decision.
    pub fn defer(reason: GateDeferReasonV1) -> Self {
        Self::Defer { reason }
    }

    /// Creates a rejection gate decision.
    pub fn rejected(
        reason: GateRejectReasonV1,
        retry_after_ms: u64,
    ) -> RouterAbProtocolResult<Self> {
        let decision = Self::Rejected {
            reason,
            retry_after_ms,
        };
        decision.validate()?;
        Ok(decision)
    }

    /// Validates branch-specific decision fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        match self {
            Self::Accepted { request_id } => require_non_empty("request_id", request_id),
            Self::ReuseExisting {
                request_id,
                existing_lifecycle_id,
            } => {
                require_non_empty("request_id", request_id)?;
                require_non_empty("existing_lifecycle_id", existing_lifecycle_id)
            }
            Self::Defer { .. } => Ok(()),
            Self::Rejected { retry_after_ms, .. } => {
                if *retry_after_ms == 0 {
                    return Err(RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::InvalidGateDecision,
                        "rejected gate decision requires retry_after_ms greater than zero",
                    ));
                }
                Ok(())
            }
        }
    }
}

/// Single-use registration prepare handle scoped before expensive HSS work.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistrationPrepareHandleV1 {
    /// Router-assigned handle id.
    pub handle_id: String,
    /// Auth method, such as email_otp or passkey.
    pub auth_method: String,
    /// Account or wallet id.
    pub account_id: String,
    /// WebAuthn relying party id or equivalent origin scope.
    pub rp_id: String,
    /// Signer mode requested by the registration path.
    pub signer_mode: String,
    /// Digest of the normalized registration intent.
    pub intent_digest: PublicDigest32,
    /// Digest of the Router/A/B protocol context.
    pub protocol_context_digest: PublicDigest32,
    /// Digest used to enforce single-use replay behavior.
    pub single_use_nonce_digest: PublicDigest32,
    /// Server-issued timestamp in milliseconds.
    pub issued_at_ms: u64,
    /// Expiry timestamp in milliseconds.
    pub expires_at_ms: u64,
}

impl RegistrationPrepareHandleV1 {
    /// Creates a validated registration prepare handle.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        handle_id: impl Into<String>,
        auth_method: impl Into<String>,
        account_id: impl Into<String>,
        rp_id: impl Into<String>,
        signer_mode: impl Into<String>,
        intent_digest: PublicDigest32,
        protocol_context_digest: PublicDigest32,
        single_use_nonce_digest: PublicDigest32,
        issued_at_ms: u64,
        expires_at_ms: u64,
    ) -> RouterAbProtocolResult<Self> {
        let handle = Self {
            handle_id: handle_id.into(),
            auth_method: auth_method.into(),
            account_id: account_id.into(),
            rp_id: rp_id.into(),
            signer_mode: signer_mode.into(),
            intent_digest,
            protocol_context_digest,
            single_use_nonce_digest,
            issued_at_ms,
            expires_at_ms,
        };
        handle.validate()?;
        Ok(handle)
    }

    /// Validates scope and expiry fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("handle_id", &self.handle_id)?;
        require_non_empty("auth_method", &self.auth_method)?;
        require_non_empty("account_id", &self.account_id)?;
        require_non_empty("rp_id", &self.rp_id)?;
        require_non_empty("signer_mode", &self.signer_mode)?;
        if self.expires_at_ms <= self.issued_at_ms {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidTimeRange,
                "registration prepare handle expires_at_ms must be greater than issued_at_ms",
            ));
        }
        Ok(())
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
