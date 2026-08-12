use crate::*;

/// Auth context already verified by the Router boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "auth", rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum CloudflareRouterAuthContextV1 {
    /// Fully authenticated user/session.
    AuthenticatedSession {
        /// Canonical subject id from verified auth.
        subject_id: String,
        /// Canonical session id from verified auth.
        session_id: String,
    },
    /// Authenticated app session carrying a claimed single-operation authorization.
    OperationStepUpSession {
        /// Canonical subject id from verified auth.
        subject_id: String,
        /// Canonical Seams authorization-session id.
        authorization_session_id: String,
    },
    /// Pre-auth session allowed only for registration prepare.
    PreAuthSession {
        /// Router-derived pre-auth session id.
        pre_auth_session_id: String,
    },
}

impl CloudflareRouterAuthContextV1 {
    /// Creates a validated authenticated-session context.
    pub fn authenticated_session(
        subject_id: impl Into<String>,
        session_id: impl Into<String>,
    ) -> RouterAbProtocolResult<Self> {
        let context = Self::AuthenticatedSession {
            subject_id: subject_id.into(),
            session_id: session_id.into(),
        };
        context.validate()?;
        Ok(context)
    }

    /// Creates a validated pre-auth session context.
    pub fn pre_auth_session(
        pre_auth_session_id: impl Into<String>,
    ) -> RouterAbProtocolResult<Self> {
        let context = Self::PreAuthSession {
            pre_auth_session_id: pre_auth_session_id.into(),
        };
        context.validate()?;
        Ok(context)
    }

    /// Creates a validated operation-step-up session context.
    pub fn operation_step_up_session(
        subject_id: impl Into<String>,
        authorization_session_id: impl Into<String>,
    ) -> RouterAbProtocolResult<Self> {
        let context = Self::OperationStepUpSession {
            subject_id: subject_id.into(),
            authorization_session_id: authorization_session_id.into(),
        };
        context.validate()?;
        Ok(context)
    }

    /// Validates auth branch identity fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        match self {
            Self::AuthenticatedSession {
                subject_id,
                session_id,
            } => {
                require_non_empty("subject_id", subject_id)?;
                require_non_empty("session_id", session_id)
            }
            Self::OperationStepUpSession {
                subject_id,
                authorization_session_id,
            } => {
                require_non_empty("subject_id", subject_id)?;
                require_non_empty("authorization_session_id", authorization_session_id)
            }
            Self::PreAuthSession {
                pre_auth_session_id,
            } => require_non_empty("pre_auth_session_id", pre_auth_session_id),
        }
    }

    /// Converts trusted Router auth context into a core gate principal.
    pub fn to_gate_principal(&self) -> RouterAbProtocolResult<GatePrincipalV1> {
        self.validate()?;
        match self {
            Self::AuthenticatedSession {
                subject_id,
                session_id,
            } => GatePrincipalV1::authenticated_session(subject_id.clone(), session_id.clone()),
            Self::OperationStepUpSession {
                subject_id,
                authorization_session_id,
            } => GatePrincipalV1::authenticated_session(
                subject_id.clone(),
                authorization_session_id.clone(),
            ),
            Self::PreAuthSession {
                pre_auth_session_id,
            } => GatePrincipalV1::pre_auth_session(pre_auth_session_id.clone()),
        }
    }

    pub(crate) fn session_id(&self) -> &str {
        match self {
            Self::AuthenticatedSession { session_id, .. } => session_id,
            Self::OperationStepUpSession {
                authorization_session_id,
                ..
            } => authorization_session_id,
            Self::PreAuthSession {
                pre_auth_session_id,
            } => pre_auth_session_id,
        }
    }
}

/// Router-owned request metadata used to derive gate context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareRouterTrustedRequestMetadataV1 {
    /// Protected work class from verified Router routing.
    pub work_kind: ExpensiveWorkKindV1,
    /// Canonical organization id.
    pub org_id: String,
    /// Canonical project id.
    pub project_id: String,
    /// Deployment environment label.
    pub environment: String,
    /// Account, wallet, or root resource id.
    pub account_id: String,
    /// Router-owned auth context.
    pub auth: CloudflareRouterAuthContextV1,
    /// Digest of trusted source metadata, such as edge client address.
    pub trusted_source_digest: PublicDigest32,
}

impl CloudflareRouterTrustedRequestMetadataV1 {
    /// Creates validated trusted request metadata.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        work_kind: ExpensiveWorkKindV1,
        org_id: impl Into<String>,
        project_id: impl Into<String>,
        environment: impl Into<String>,
        account_id: impl Into<String>,
        auth: CloudflareRouterAuthContextV1,
        trusted_source_digest: PublicDigest32,
    ) -> RouterAbProtocolResult<Self> {
        let metadata = Self {
            work_kind,
            org_id: org_id.into(),
            project_id: project_id.into(),
            environment: environment.into(),
            account_id: account_id.into(),
            auth,
            trusted_source_digest,
        };
        metadata.validate()?;
        Ok(metadata)
    }

    /// Validates trusted request metadata fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("org_id", &self.org_id)?;
        require_non_empty("project_id", &self.project_id)?;
        require_non_empty("environment", &self.environment)?;
        require_non_empty("account_id", &self.account_id)?;
        self.auth.validate()
    }

    /// Validates trusted metadata matches the normalized public request.
    pub fn validate_for_request(
        &self,
        request: &EcdsaThresholdPrfRequestV1,
    ) -> RouterAbProtocolResult<()> {
        self.validate()?;
        request.validate()?;
        if self.work_kind != request.lifecycle.work_kind {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "trusted Router metadata work kind does not match public request lifecycle",
            ));
        }
        if self.account_id != request.lifecycle.account_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "trusted Router metadata account id does not match public request lifecycle",
            ));
        }
        if self.auth.session_id() != request.lifecycle.session_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "trusted Router metadata session id does not match public request lifecycle",
            ));
        }
        if matches!(
            self.auth,
            CloudflareRouterAuthContextV1::PreAuthSession { .. }
        ) && self.work_kind != ExpensiveWorkKindV1::RegistrationPrepare
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "pre-auth Router metadata is allowed only for registration prepare",
            ));
        }
        if matches!(
            self.auth,
            CloudflareRouterAuthContextV1::OperationStepUpSession { .. }
        ) {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "operation step-up Router metadata is allowed only for normal signing",
            ));
        }
        Ok(())
    }

    /// Builds the core gate context from trusted Router metadata.
    pub fn to_gate_context(&self) -> RouterAbProtocolResult<ExpensiveWorkGateContextV1> {
        self.validate()?;
        ExpensiveWorkGateContextV1::new(
            self.work_kind,
            self.org_id.clone(),
            self.project_id.clone(),
            self.environment.clone(),
            self.account_id.clone(),
            self.auth.to_gate_principal()?,
            self.trusted_source_digest,
        )
    }
}

/// Router-owned metadata for normal-signing admission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareRouterNormalSigningTrustedMetadataV1 {
    /// Canonical organization id.
    pub org_id: String,
    /// Canonical project id.
    pub project_id: String,
    /// Deployment environment label.
    pub environment: String,
    /// Account, wallet, or root resource id.
    pub account_id: String,
    /// Router-owned authenticated-session context.
    pub auth: CloudflareRouterAuthContextV1,
    /// Digest of trusted source metadata, such as edge client address.
    pub trusted_source_digest: PublicDigest32,
    /// Digest of the canonical user intent authorized by policy.
    pub intent_digest: PublicDigest32,
}

impl CloudflareRouterNormalSigningTrustedMetadataV1 {
    /// Creates validated normal-signing metadata.
    pub fn new(
        org_id: impl Into<String>,
        project_id: impl Into<String>,
        environment: impl Into<String>,
        account_id: impl Into<String>,
        auth: CloudflareRouterAuthContextV1,
        trusted_source_digest: PublicDigest32,
        intent_digest: PublicDigest32,
    ) -> RouterAbProtocolResult<Self> {
        let metadata = Self {
            org_id: org_id.into(),
            project_id: project_id.into(),
            environment: environment.into(),
            account_id: account_id.into(),
            auth,
            trusted_source_digest,
            intent_digest,
        };
        metadata.validate()?;
        Ok(metadata)
    }

    /// Validates trusted normal-signing metadata fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("normal signing org_id", &self.org_id)?;
        require_non_empty("normal signing project_id", &self.project_id)?;
        require_non_empty("normal signing environment", &self.environment)?;
        require_non_empty("normal signing account_id", &self.account_id)?;
        self.auth.validate()?;
        if matches!(
            self.auth,
            CloudflareRouterAuthContextV1::PreAuthSession { .. }
        ) {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "normal signing requires authenticated Router metadata",
            ));
        }
        Ok(())
    }

    /// Validates metadata matches a typed v2 normal-signing finalize request.
    pub fn validate_for_finalize_request_v2(
        &self,
        request: &RouterAbEd25519NormalSigningFinalizeRequestV2,
    ) -> RouterAbProtocolResult<()> {
        self.validate()?;
        request.validate()?;
        if self.account_id != request.scope.account_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "trusted normal-signing account id does not match v2 finalize scope",
            ));
        }
        match (&self.auth, &request.scope.authorization) {
            (
                CloudflareRouterAuthContextV1::AuthenticatedSession { session_id, .. },
                NormalSigningAuthorizationV1::ReusableWalletSession {
                    wallet_session_id, ..
                },
            ) if session_id == wallet_session_id => {}
            (
                CloudflareRouterAuthContextV1::OperationStepUpSession { .. },
                NormalSigningAuthorizationV1::OperationStepUp,
            ) => {}
            _ => {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidGateDecision,
                    "trusted normal-signing authorization does not match v2 finalize scope",
                ));
            }
        }
        if self.intent_digest != request.intent_digest() {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "trusted normal-signing intent digest does not match v2 finalize intent",
            ));
        }
        Ok(())
    }
}

/// Project policy outcome produced by Router-owned policy checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "policy", rename_all = "snake_case")]
pub enum CloudflareRouterProjectPolicyV1 {
    /// Project policy allows this work kind.
    Allowed,
    /// Project policy rejects this work kind before signer capacity is used.
    Rejected {
        /// Retry-after duration in milliseconds.
        retry_after_ms: u64,
    },
}

impl CloudflareRouterProjectPolicyV1 {
    /// Validates project policy branch fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        match self {
            Self::Allowed => Ok(()),
            Self::Rejected { retry_after_ms } => {
                require_positive_ms("project policy retry_after_ms", *retry_after_ms)
            }
        }
    }
}

/// Abuse-control outcome produced by Router-owned abuse checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "abuse", rename_all = "snake_case")]
pub enum CloudflareRouterAbuseCheckV1 {
    /// Abuse checks allow the request.
    Allowed,
    /// Request is rate-limited before signer capacity is used.
    RateLimited {
        /// Retry-after duration in milliseconds.
        retry_after_ms: u64,
    },
    /// Abuse policy rejects the request before signer capacity is used.
    Rejected {
        /// Retry-after duration in milliseconds.
        retry_after_ms: u64,
    },
}

impl CloudflareRouterAbuseCheckV1 {
    /// Validates abuse-check branch fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        match self {
            Self::Allowed => Ok(()),
            Self::RateLimited { retry_after_ms } => {
                require_positive_ms("abuse rate-limit retry_after_ms", *retry_after_ms)
            }
            Self::Rejected { retry_after_ms } => {
                require_positive_ms("abuse rejection retry_after_ms", *retry_after_ms)
            }
        }
    }
}

/// Quota and queue outcome produced by Router-owned gate checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "quota", rename_all = "snake_case")]
pub enum CloudflareRouterQuotaCheckV1 {
    /// New expensive work is allowed.
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
    /// Short-window quota is saturated.
    ShortWindowSaturated,
    /// Signer queue is saturated.
    SignerQueueSaturated,
}

impl CloudflareRouterQuotaCheckV1 {
    /// Validates quota branch fields.
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
            Self::ShortWindowSaturated | Self::SignerQueueSaturated => Ok(()),
        }
    }
}

/// Trusted Router admission check results.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareRouterAdmissionChecksV1 {
    /// Project policy result.
    pub project_policy: CloudflareRouterProjectPolicyV1,
    /// Abuse-control result.
    pub abuse: CloudflareRouterAbuseCheckV1,
    /// Quota/queue result.
    pub quota: CloudflareRouterQuotaCheckV1,
}

impl CloudflareRouterAdmissionChecksV1 {
    /// Creates validated admission checks.
    pub fn new(
        project_policy: CloudflareRouterProjectPolicyV1,
        abuse: CloudflareRouterAbuseCheckV1,
        quota: CloudflareRouterQuotaCheckV1,
    ) -> RouterAbProtocolResult<Self> {
        let checks = Self {
            project_policy,
            abuse,
            quota,
        };
        checks.validate()?;
        Ok(checks)
    }

    /// Validates all trusted check results.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.project_policy.validate()?;
        self.abuse.validate()?;
        self.quota.validate()
    }

    /// Converts check results into the core expensive-work gate decision.
    pub fn to_gate_decision(&self) -> RouterAbProtocolResult<ExpensiveWorkGateDecisionV1> {
        self.validate()?;
        match &self.project_policy {
            CloudflareRouterProjectPolicyV1::Rejected { retry_after_ms } => {
                return ExpensiveWorkGateDecisionV1::rejected(
                    GateRejectReasonV1::AbusePolicy,
                    *retry_after_ms,
                );
            }
            CloudflareRouterProjectPolicyV1::Allowed => {}
        }
        match &self.abuse {
            CloudflareRouterAbuseCheckV1::RateLimited { retry_after_ms } => {
                return ExpensiveWorkGateDecisionV1::rejected(
                    GateRejectReasonV1::RateLimited,
                    *retry_after_ms,
                );
            }
            CloudflareRouterAbuseCheckV1::Rejected { retry_after_ms } => {
                return ExpensiveWorkGateDecisionV1::rejected(
                    GateRejectReasonV1::AbusePolicy,
                    *retry_after_ms,
                );
            }
            CloudflareRouterAbuseCheckV1::Allowed => {}
        }
        match &self.quota {
            CloudflareRouterQuotaCheckV1::Accepted { request_id } => {
                ExpensiveWorkGateDecisionV1::accepted(request_id.clone())
            }
            CloudflareRouterQuotaCheckV1::ReuseExisting {
                request_id,
                existing_lifecycle_id,
            } => ExpensiveWorkGateDecisionV1::reuse_existing(
                request_id.clone(),
                existing_lifecycle_id.clone(),
            ),
            CloudflareRouterQuotaCheckV1::ShortWindowSaturated => Ok(
                ExpensiveWorkGateDecisionV1::defer(GateDeferReasonV1::ShortWindowSaturated),
            ),
            CloudflareRouterQuotaCheckV1::SignerQueueSaturated => Ok(
                ExpensiveWorkGateDecisionV1::defer(GateDeferReasonV1::SignerQueueSaturated),
            ),
        }
    }
}

/// Typed output from Router-owned auth, policy, abuse, and quota providers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareRouterAdmissionProviderOutputV1 {
    /// Trusted request metadata derived from auth/session context.
    pub metadata: CloudflareRouterTrustedRequestMetadataV1,
    /// Trusted policy, abuse, and quota results.
    pub checks: CloudflareRouterAdmissionChecksV1,
}

impl CloudflareRouterAdmissionProviderOutputV1 {
    /// Creates validated admission-provider output.
    pub fn new(
        metadata: CloudflareRouterTrustedRequestMetadataV1,
        checks: CloudflareRouterAdmissionChecksV1,
    ) -> RouterAbProtocolResult<Self> {
        let output = Self { metadata, checks };
        output.validate()?;
        Ok(output)
    }

    /// Validates provider output independent of a public request.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.metadata.validate()?;
        self.checks.validate()
    }

    /// Validates provider output against the normalized public request.
    pub fn validate_for_request(
        &self,
        request: &EcdsaThresholdPrfRequestV1,
    ) -> RouterAbProtocolResult<()> {
        self.metadata.validate_for_request(request)?;
        self.checks.validate()
    }
}

/// Router-owned boundary for auth, session, policy, abuse, and quota checks.
pub trait CloudflareRouterAdmissionProviderV1 {
    /// Evaluates all server-owned admission checks for a normalized public request.
    fn evaluate_public_request_admission(
        &mut self,
        request: &EcdsaThresholdPrfRequestV1,
    ) -> RouterAbProtocolResult<CloudflareRouterAdmissionProviderOutputV1>;
}

/// Already verified JWT/session claims at the Router auth boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareRouterVerifiedJwtClaimsV1 {
    /// Canonical subject id from verified auth.
    pub subject_id: String,
    /// Canonical session id from verified auth.
    pub session_id: String,
    /// Canonical organization id authorized by the session.
    pub org_id: String,
    /// Canonical project id authorized by the session.
    pub project_id: String,
    /// Deployment environment label authorized by the session.
    pub environment: String,
    /// Account, wallet, or root resource id authorized by the session.
    pub account_id: String,
    /// Digest of trusted source metadata, such as edge client address.
    pub trusted_source_digest: PublicDigest32,
}

impl CloudflareRouterVerifiedJwtClaimsV1 {
    /// Creates validated claims from an already verified JWT/session boundary.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        subject_id: impl Into<String>,
        session_id: impl Into<String>,
        org_id: impl Into<String>,
        project_id: impl Into<String>,
        environment: impl Into<String>,
        account_id: impl Into<String>,
        trusted_source_digest: PublicDigest32,
    ) -> RouterAbProtocolResult<Self> {
        let claims = Self {
            subject_id: subject_id.into(),
            session_id: session_id.into(),
            org_id: org_id.into(),
            project_id: project_id.into(),
            environment: environment.into(),
            account_id: account_id.into(),
            trusted_source_digest,
        };
        claims.validate()?;
        Ok(claims)
    }

    /// Validates branch identity and policy-scope fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("subject_id", &self.subject_id)?;
        require_non_empty("session_id", &self.session_id)?;
        require_non_empty("org_id", &self.org_id)?;
        require_non_empty("project_id", &self.project_id)?;
        require_non_empty("environment", &self.environment)?;
        require_non_empty("account_id", &self.account_id)
    }

    /// Converts verified claims into trusted Router metadata for this request.
    pub fn to_trusted_metadata(
        &self,
        request: &EcdsaThresholdPrfRequestV1,
    ) -> RouterAbProtocolResult<CloudflareRouterTrustedRequestMetadataV1> {
        self.validate()?;
        request.validate()?;
        CloudflareRouterTrustedRequestMetadataV1::new(
            request.lifecycle.work_kind,
            self.org_id.clone(),
            self.project_id.clone(),
            self.environment.clone(),
            self.account_id.clone(),
            CloudflareRouterAuthContextV1::authenticated_session(
                self.subject_id.clone(),
                self.session_id.clone(),
            )?,
            self.trusted_source_digest,
        )
    }
}

/// Wallet Session credential accepted at the Router auth boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CloudflareRouterWalletSessionCredentialV1 {
    /// Bearer token supplied by the public normal-signing caller.
    Bearer {
        /// Parsed bearer authorization.
        authorization: CloudflareRouterBearerAuthorizationV1,
    },
}

impl CloudflareRouterWalletSessionCredentialV1 {
    /// Creates a bearer Wallet Session credential.
    pub fn bearer(
        authorization: CloudflareRouterBearerAuthorizationV1,
    ) -> RouterAbProtocolResult<Self> {
        let credential = Self::Bearer { authorization };
        credential.validate()?;
        Ok(credential)
    }

    /// Parses an HTTP Authorization header into a bearer Wallet Session credential.
    pub fn from_bearer_authorization_header(header: &str) -> RouterAbProtocolResult<Self> {
        Self::bearer(CloudflareRouterBearerAuthorizationV1::from_authorization_header(header)?)
    }

    /// Validates credential branch fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        match self {
            Self::Bearer { authorization } => authorization.validate(),
        }
    }
}

/// Already verified Wallet Session at the Router auth boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareRouterVerifiedWalletSessionV1 {
    /// Canonical subject id from verified wallet auth.
    pub subject_id: String,
    /// Account, wallet, or root resource id authorized by the session.
    pub account_id: String,
    /// Exact Seams authorization-session id carried by the verified credential.
    pub authorization_session_id: String,
    /// Exact durable Wallet Session authorization id.
    pub authorization_id: String,
    /// Exact reusable Wallet Session id.
    pub wallet_session_id: String,
    /// Exact reusable Wallet Session quota id paired with the Wallet Session.
    pub quota_id: String,
    /// Threshold/MPC session id authorized by the Wallet Session.
    pub threshold_session_id: String,
    /// Canonical organization id authorized by the session.
    pub org_id: String,
    /// Canonical project id authorized by the session.
    pub project_id: String,
    /// Deployment environment label authorized by the session.
    pub environment: String,
    /// Wallet authorization level selected by Router policy.
    pub authorization_level: String,
    /// Active SigningWorker id authorized for this session.
    pub signing_worker_id: String,
    /// Digest of trusted source metadata, such as edge client address.
    pub trusted_source_digest: PublicDigest32,
    /// Session expiry in Unix milliseconds.
    pub expires_at_ms: u64,
}

impl CloudflareRouterVerifiedWalletSessionV1 {
    /// Creates a validated Wallet Session boundary object.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        subject_id: impl Into<String>,
        account_id: impl Into<String>,
        authorization_session_id: impl Into<String>,
        authorization_id: impl Into<String>,
        wallet_session_id: impl Into<String>,
        quota_id: impl Into<String>,
        threshold_session_id: impl Into<String>,
        org_id: impl Into<String>,
        project_id: impl Into<String>,
        environment: impl Into<String>,
        authorization_level: impl Into<String>,
        signing_worker_id: impl Into<String>,
        trusted_source_digest: PublicDigest32,
        expires_at_ms: u64,
    ) -> RouterAbProtocolResult<Self> {
        let session = Self {
            subject_id: subject_id.into(),
            account_id: account_id.into(),
            authorization_session_id: authorization_session_id.into(),
            authorization_id: authorization_id.into(),
            wallet_session_id: wallet_session_id.into(),
            quota_id: quota_id.into(),
            threshold_session_id: threshold_session_id.into(),
            org_id: org_id.into(),
            project_id: project_id.into(),
            environment: environment.into(),
            authorization_level: authorization_level.into(),
            signing_worker_id: signing_worker_id.into(),
            trusted_source_digest,
            expires_at_ms,
        };
        session.validate()?;
        Ok(session)
    }

    /// Validates required Wallet Session fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("wallet session subject_id", &self.subject_id)?;
        require_non_empty("wallet session account_id", &self.account_id)?;
        require_non_empty(
            "wallet session authorization_session_id",
            &self.authorization_session_id,
        )?;
        require_non_empty("wallet session authorization_id", &self.authorization_id)?;
        require_non_empty("wallet session wallet_session_id", &self.wallet_session_id)?;
        require_non_empty("wallet session quota_id", &self.quota_id)?;
        if self.authorization_id == self.wallet_session_id
            || self.authorization_id == self.quota_id
            || self.wallet_session_id == self.quota_id
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "wallet session authorization, Wallet Session, and quota ids must be pairwise distinct",
            ));
        }
        require_non_empty(
            "wallet session threshold_session_id",
            &self.threshold_session_id,
        )?;
        require_non_empty("wallet session org_id", &self.org_id)?;
        require_non_empty("wallet session project_id", &self.project_id)?;
        require_non_empty("wallet session environment", &self.environment)?;
        require_non_empty(
            "wallet session authorization_level",
            &self.authorization_level,
        )?;
        require_non_empty("wallet session signing_worker_id", &self.signing_worker_id)?;
        require_positive_ms("wallet session expires_at_ms", self.expires_at_ms)
    }

    /// Validates the Wallet Session against Router time.
    pub fn validate_at(&self, now_unix_ms: u64) -> RouterAbProtocolResult<()> {
        self.validate()?;
        require_positive_ms("wallet session now_unix_ms", now_unix_ms)?;
        if now_unix_ms >= self.expires_at_ms {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ExpiredLocalRequest,
                "Wallet Session expired",
            ));
        }
        Ok(())
    }

    /// Validates that the Wallet Session authorizes a typed normal-signing prepare request.
    pub fn validate_for_normal_signing_prepare_request_v2(
        &self,
        request: &RouterAbEd25519NormalSigningPrepareRequestV2,
        now_unix_ms: u64,
    ) -> RouterAbProtocolResult<()> {
        self.validate_at(now_unix_ms)?;
        request.validate_at(now_unix_ms)?;
        if self.authorization_level != "near-ed25519" {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "Wallet Session does not authorize Ed25519 normal signing",
            ));
        }
        if self.expires_at_ms < request.expires_at_ms {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidTimeRange,
                "Wallet Session expires before normal-signing request",
            ));
        }
        if self.account_id != request.scope.account_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "Wallet Session account_id does not match normal-signing scope",
            ));
        }
        match &request.scope.authorization {
            NormalSigningAuthorizationV1::ReusableWalletSession { wallet_session_id } => {
                if self.wallet_session_id != *wallet_session_id {
                    return Err(RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::InvalidGateDecision,
                        "Wallet Session id does not match normal-signing scope",
                    ));
                }
            }
            NormalSigningAuthorizationV1::OperationStepUp => {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidGateDecision,
                    "Wallet Session bearer cannot authorize operation-step-up signing",
                ));
            }
        }
        if self.signing_worker_id != request.scope.signing_worker_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "Wallet Session signing_worker_id does not match normal-signing scope",
            ));
        }
        Ok(())
    }

    /// Validates that the Wallet Session authorizes a typed normal-signing finalize request.
    pub fn validate_for_normal_signing_finalize_request_v2(
        &self,
        request: &RouterAbEd25519NormalSigningFinalizeRequestV2,
        now_unix_ms: u64,
    ) -> RouterAbProtocolResult<()> {
        self.validate_at(now_unix_ms)?;
        request.validate_at(now_unix_ms)?;
        if self.authorization_level != "near-ed25519" {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "Wallet Session does not authorize Ed25519 normal-signing finalize",
            ));
        }
        if self.expires_at_ms < request.expires_at_ms {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidTimeRange,
                "Wallet Session expires before normal-signing finalize request",
            ));
        }
        if self.account_id != request.scope.account_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "Wallet Session account_id does not match normal-signing finalize scope",
            ));
        }
        match &request.scope.authorization {
            NormalSigningAuthorizationV1::ReusableWalletSession { wallet_session_id } => {
                if self.wallet_session_id != *wallet_session_id {
                    return Err(RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::InvalidGateDecision,
                        "Wallet Session id does not match normal-signing finalize scope",
                    ));
                }
            }
            NormalSigningAuthorizationV1::OperationStepUp => {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidGateDecision,
                    "Wallet Session bearer cannot authorize operation-step-up signing",
                ));
            }
        }
        if self.signing_worker_id != request.scope.signing_worker_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "Wallet Session signing_worker_id does not match normal-signing finalize scope",
            ));
        }
        Ok(())
    }

    /// Validates that the Wallet Session authorizes a Router A/B ECDSA derivation digest-signing prepare request.
    pub fn validate_for_router_ab_ecdsa_derivation_evm_digest_signing_request_v1(
        &self,
        request: &RouterAbEcdsaDerivationEvmDigestSigningRequestV1,
        now_unix_ms: u64,
    ) -> RouterAbProtocolResult<()> {
        self.validate_at(now_unix_ms)?;
        request.validate_at(now_unix_ms)?;
        if self.authorization_level != "evm-family" {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "Wallet Session does not authorize ECDSA normal signing",
            ));
        }
        if self.expires_at_ms < request.expires_at_ms {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidTimeRange,
                "Wallet Session expires before Router A/B ECDSA derivation signing request",
            ));
        }
        if self.account_id != request.scope.wallet_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "Wallet Session account_id does not match Router A/B ECDSA derivation signing scope",
            ));
        }
        match &request.authorization {
            NormalSigningAuthorizationV1::ReusableWalletSession { wallet_session_id } => {
                if self.wallet_session_id != *wallet_session_id {
                    return Err(RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::InvalidGateDecision,
                        "Wallet Session id does not match Router A/B ECDSA derivation signing scope",
                    ));
                }
            }
            NormalSigningAuthorizationV1::OperationStepUp => {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidGateDecision,
                    "Wallet Session bearer cannot authorize operation-step-up signing",
                ));
            }
        }
        if self.signing_worker_id != request.scope.signing_worker.server_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "Wallet Session signing_worker_id does not match Router A/B ECDSA derivation signing scope",
            ));
        }
        Ok(())
    }

    /// Validates that the Wallet Session authorizes a Router A/B ECDSA derivation finalize request.
    pub fn validate_for_router_ab_ecdsa_derivation_evm_digest_finalize_request_v1(
        &self,
        request: &RouterAbEcdsaDerivationEvmDigestSigningFinalizeRequestV1,
        now_unix_ms: u64,
    ) -> RouterAbProtocolResult<()> {
        self.validate_at(now_unix_ms)?;
        request.validate_at(now_unix_ms)?;
        if self.authorization_level != "evm-family" {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "Wallet Session does not authorize ECDSA normal-signing finalize",
            ));
        }
        if self.expires_at_ms < request.expires_at_ms {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidTimeRange,
                "Wallet Session expires before Router A/B ECDSA derivation finalize request",
            ));
        }
        if self.account_id != request.scope.wallet_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "Wallet Session account_id does not match Router A/B ECDSA derivation finalize scope",
            ));
        }
        match &request.authorization {
            NormalSigningAuthorizationV1::ReusableWalletSession { wallet_session_id } => {
                if self.wallet_session_id != *wallet_session_id {
                    return Err(RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::InvalidGateDecision,
                        "Wallet Session id does not match Router A/B ECDSA derivation finalize scope",
                    ));
                }
            }
            NormalSigningAuthorizationV1::OperationStepUp => {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidGateDecision,
                    "Wallet Session bearer cannot authorize operation-step-up signing",
                ));
            }
        }
        if self.signing_worker_id != request.scope.signing_worker.server_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "Wallet Session signing_worker_id does not match Router A/B ECDSA derivation finalize scope",
            ));
        }
        Ok(())
    }

    /// Converts a verified Wallet Session and typed request into a prepare admission candidate.
    pub fn to_normal_signing_prepare_admission_candidate_v2(
        &self,
        request: &RouterAbEd25519NormalSigningPrepareRequestV2,
        now_unix_ms: u64,
    ) -> RouterAbProtocolResult<CloudflareRouterNormalSigningPrepareAdmissionCandidateV2> {
        CloudflareRouterNormalSigningPrepareAdmissionCandidateV2::from_prepare_request(
            self,
            request,
            now_unix_ms,
        )
    }
}

/// Wallet Session verifier boundary used by normal-signing v2 admission.
pub trait CloudflareRouterWalletSessionVerifierV1 {
    /// Verifies a Wallet Session credential and returns normalized session data.
    fn verify_wallet_session(
        &mut self,
        verifier: &CloudflareRouterJwtVerifierBindingV1,
        credential: &CloudflareRouterWalletSessionCredentialV1,
        trusted_source_digest: PublicDigest32,
        now_unix_ms: u64,
    ) -> RouterAbProtocolResult<CloudflareRouterVerifiedWalletSessionV1>;
}

/// Already verified pre-auth session at the Router auth boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareRouterVerifiedPreAuthSessionV1 {
    /// Router-derived pre-auth session id.
    pub pre_auth_session_id: String,
    /// Canonical organization id assigned by Router policy.
    pub org_id: String,
    /// Canonical project id assigned by Router policy.
    pub project_id: String,
    /// Deployment environment label assigned by Router policy.
    pub environment: String,
    /// Account, wallet, or root resource id assigned by Router policy.
    pub account_id: String,
    /// Digest of trusted source metadata, such as edge client address.
    pub trusted_source_digest: PublicDigest32,
}

impl CloudflareRouterVerifiedPreAuthSessionV1 {
    /// Creates a validated pre-auth session boundary.
    pub fn new(
        pre_auth_session_id: impl Into<String>,
        org_id: impl Into<String>,
        project_id: impl Into<String>,
        environment: impl Into<String>,
        account_id: impl Into<String>,
        trusted_source_digest: PublicDigest32,
    ) -> RouterAbProtocolResult<Self> {
        let session = Self {
            pre_auth_session_id: pre_auth_session_id.into(),
            org_id: org_id.into(),
            project_id: project_id.into(),
            environment: environment.into(),
            account_id: account_id.into(),
            trusted_source_digest,
        };
        session.validate()?;
        Ok(session)
    }

    /// Validates pre-auth identity and policy-scope fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("pre_auth_session_id", &self.pre_auth_session_id)?;
        require_non_empty("org_id", &self.org_id)?;
        require_non_empty("project_id", &self.project_id)?;
        require_non_empty("environment", &self.environment)?;
        require_non_empty("account_id", &self.account_id)
    }

    /// Converts verified pre-auth session data into trusted Router metadata.
    pub fn to_trusted_metadata(
        &self,
        request: &EcdsaThresholdPrfRequestV1,
    ) -> RouterAbProtocolResult<CloudflareRouterTrustedRequestMetadataV1> {
        self.validate()?;
        request.validate()?;
        CloudflareRouterTrustedRequestMetadataV1::new(
            request.lifecycle.work_kind,
            self.org_id.clone(),
            self.project_id.clone(),
            self.environment.clone(),
            self.account_id.clone(),
            CloudflareRouterAuthContextV1::pre_auth_session(self.pre_auth_session_id.clone())?,
            self.trusted_source_digest,
        )
    }
}

/// Verified session variants accepted by the Router admission chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CloudflareRouterVerifiedSessionV1 {
    /// Claims from a verified JWT/auth session.
    Jwt {
        /// Verified JWT/session claims.
        claims: CloudflareRouterVerifiedJwtClaimsV1,
    },
    /// Router-verified pre-auth session for registration prepare.
    PreAuth {
        /// Verified pre-auth session data.
        session: CloudflareRouterVerifiedPreAuthSessionV1,
    },
}

impl CloudflareRouterVerifiedSessionV1 {
    /// Creates a verified JWT session variant.
    pub fn jwt(claims: CloudflareRouterVerifiedJwtClaimsV1) -> RouterAbProtocolResult<Self> {
        let session = Self::Jwt { claims };
        session.validate()?;
        Ok(session)
    }

    /// Creates a verified pre-auth session variant.
    pub fn pre_auth(
        session: CloudflareRouterVerifiedPreAuthSessionV1,
    ) -> RouterAbProtocolResult<Self> {
        let verified = Self::PreAuth { session };
        verified.validate()?;
        Ok(verified)
    }

    /// Validates the verified session branch.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        match self {
            Self::Jwt { claims } => claims.validate(),
            Self::PreAuth { session } => session.validate(),
        }
    }

    /// Converts the verified session branch into trusted Router metadata.
    pub fn to_trusted_metadata(
        &self,
        request: &EcdsaThresholdPrfRequestV1,
    ) -> RouterAbProtocolResult<CloudflareRouterTrustedRequestMetadataV1> {
        self.validate()?;
        match self {
            Self::Jwt { claims } => claims.to_trusted_metadata(request),
            Self::PreAuth { session } => session.to_trusted_metadata(request),
        }
    }
}

/// Router auth/session provider used by the admission chain.
pub trait CloudflareRouterSessionProviderV1 {
    /// Verifies auth/session state and derives trusted Router metadata.
    fn verify_public_request_session(
        &mut self,
        request: &EcdsaThresholdPrfRequestV1,
    ) -> RouterAbProtocolResult<CloudflareRouterTrustedRequestMetadataV1>;
}

/// Session provider for claims already verified at the request boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudflareRouterVerifiedSessionProviderV1 {
    session: CloudflareRouterVerifiedSessionV1,
}

impl CloudflareRouterVerifiedSessionProviderV1 {
    /// Creates a provider from already verified session data.
    pub fn new(session: CloudflareRouterVerifiedSessionV1) -> RouterAbProtocolResult<Self> {
        session.validate()?;
        Ok(Self { session })
    }
}

impl CloudflareRouterSessionProviderV1 for CloudflareRouterVerifiedSessionProviderV1 {
    fn verify_public_request_session(
        &mut self,
        request: &EcdsaThresholdPrfRequestV1,
    ) -> RouterAbProtocolResult<CloudflareRouterTrustedRequestMetadataV1> {
        self.session.to_trusted_metadata(request)
    }
}

/// Parsed `Authorization: Bearer ...` token at the Router boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareRouterBearerAuthorizationV1 {
    /// Compact bearer token.
    pub token: String,
}

impl CloudflareRouterBearerAuthorizationV1 {
    /// Creates a validated bearer token.
    pub fn new(token: impl Into<String>) -> RouterAbProtocolResult<Self> {
        let authorization = Self {
            token: token.into(),
        };
        authorization.validate()?;
        Ok(authorization)
    }

    /// Parses an HTTP Authorization header value.
    pub fn from_authorization_header(header: &str) -> RouterAbProtocolResult<Self> {
        let value = header.trim();
        let token = value.strip_prefix("Bearer ").ok_or_else(|| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "Router authorization header must use Bearer scheme",
            )
        })?;
        Self::new(token.to_owned())
    }

    /// Validates token shape before verifier-specific parsing.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("authorization bearer token", &self.token)?;
        require_no_ascii_whitespace("authorization bearer token", &self.token)
    }
}

/// One Ed25519 public JWT verification key parsed from JWKS.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareRouterEd25519JwkV1 {
    /// JWK key id.
    pub key_id: String,
    /// Ed25519 public key bytes.
    pub public_key: [u8; 32],
}

impl CloudflareRouterEd25519JwkV1 {
    /// Creates a validated Ed25519 JWK descriptor.
    pub fn new(key_id: impl Into<String>, public_key: [u8; 32]) -> RouterAbProtocolResult<Self> {
        let key = Self {
            key_id: key_id.into(),
            public_key,
        };
        key.validate()?;
        Ok(key)
    }

    /// Validates the key id.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("ed25519 jwk kid", &self.key_id)?;
        require_no_ascii_whitespace("ed25519 jwk kid", &self.key_id)
    }
}

/// EdDSA/Ed25519-only JWT verifier backed by a parsed JWKS document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareRouterEd25519JwksJwtVerifierV1 {
    /// Parsed Ed25519 signing keys indexed by `kid`.
    pub keys: Vec<CloudflareRouterEd25519JwkV1>,
}

impl CloudflareRouterEd25519JwksJwtVerifierV1 {
    /// Parses a JWKS JSON document into an Ed25519-only verifier.
    pub fn from_jwks_json(jwks_json: &str) -> RouterAbProtocolResult<Self> {
        require_non_empty("router jwt jwks json", jwks_json)?;
        let raw: CloudflareRouterRawJwksV1 = serde_json::from_str(jwks_json).map_err(|err| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                format!("Router JWT JWKS JSON parse failed: {err}"),
            )
        })?;
        let mut keys = Vec::new();
        for raw_key in raw.keys {
            let Some(key) = raw_key.try_into_ed25519_key()? else {
                continue;
            };
            if keys
                .iter()
                .any(|existing: &CloudflareRouterEd25519JwkV1| existing.key_id == key.key_id)
            {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                    "Router JWT JWKS contains duplicate Ed25519 kid",
                ));
            }
            keys.push(key);
        }
        let verifier = Self { keys };
        verifier.validate()?;
        Ok(verifier)
    }

    /// Creates a verifier from already parsed Ed25519 JWKs.
    pub fn new(keys: Vec<CloudflareRouterEd25519JwkV1>) -> RouterAbProtocolResult<Self> {
        let verifier = Self { keys };
        verifier.validate()?;
        Ok(verifier)
    }

    /// Validates that the verifier has at least one unique key.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        if self.keys.is_empty() {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "Router JWT JWKS must contain at least one Ed25519 signing key",
            ));
        }
        for key in &self.keys {
            key.validate()?;
        }
        for (index, key) in self.keys.iter().enumerate() {
            if self
                .keys
                .iter()
                .skip(index + 1)
                .any(|other| other.key_id == key.key_id)
            {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                    "Router JWT verifier keys contain duplicate kid",
                ));
            }
        }
        Ok(())
    }

    fn key_for_id(&self, key_id: &str) -> RouterAbProtocolResult<&CloudflareRouterEd25519JwkV1> {
        require_non_empty("jwt kid", key_id)?;
        self.keys
            .iter()
            .find(|key| key.key_id == key_id)
            .ok_or_else(|| {
                RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::MalformedWirePayload,
                    "Router JWT kid is not present in the configured JWKS",
                )
            })
    }
}

impl CloudflareRouterJwtVerifierV1 for CloudflareRouterEd25519JwksJwtVerifierV1 {
    fn verify_public_request_jwt(
        &mut self,
        verifier: &CloudflareRouterJwtVerifierBindingV1,
        authorization: &CloudflareRouterBearerAuthorizationV1,
        request: &EcdsaThresholdPrfRequestV1,
        request_policy_digest: PublicDigest32,
        now_unix_ms: u64,
        trusted_source_digest: PublicDigest32,
    ) -> RouterAbProtocolResult<CloudflareRouterVerifiedJwtClaimsV1> {
        self.validate()?;
        verifier.validate()?;
        authorization.validate()?;
        request.validate_at(now_unix_ms)?;
        let jwt = CloudflareRouterCompactJwtV1::parse(&authorization.token)?;
        if jwt.header.alg != "EdDSA" {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "Router JWT alg must be EdDSA",
            ));
        }
        let key = self.key_for_id(&jwt.header.kid)?;
        verify_router_ed25519_jwt_signature_v1(&jwt.signing_input, &jwt.signature, key)?;
        jwt.claims.validate_for_router_request(
            verifier,
            request,
            request_policy_digest,
            now_unix_ms,
            trusted_source_digest,
        )
    }
}

impl CloudflareRouterWalletSessionVerifierV1 for CloudflareRouterEd25519JwksJwtVerifierV1 {
    fn verify_wallet_session(
        &mut self,
        verifier: &CloudflareRouterJwtVerifierBindingV1,
        credential: &CloudflareRouterWalletSessionCredentialV1,
        trusted_source_digest: PublicDigest32,
        now_unix_ms: u64,
    ) -> RouterAbProtocolResult<CloudflareRouterVerifiedWalletSessionV1> {
        self.validate()?;
        verifier.validate()?;
        credential.validate()?;
        require_positive_ms("wallet session now_unix_ms", now_unix_ms)?;
        let CloudflareRouterWalletSessionCredentialV1::Bearer { authorization } = credential;
        authorization.validate()?;
        let jwt = CloudflareRouterCompactJwtV1::parse(&authorization.token)?;
        if jwt.header.alg != "EdDSA" {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "Router Wallet Session JWT alg must be EdDSA",
            ));
        }
        let key = self.key_for_id(&jwt.header.kid)?;
        verify_router_ed25519_jwt_signature_v1(&jwt.signing_input, &jwt.signature, key)?;
        jwt.claims
            .validate_for_wallet_session(verifier, now_unix_ms, trusted_source_digest)
    }
}

#[derive(Debug, Deserialize)]
struct CloudflareRouterRawJwksV1 {
    keys: Vec<CloudflareRouterRawJwkV1>,
}

#[derive(Debug, Deserialize)]
struct CloudflareRouterRawJwkV1 {
    kty: String,
    crv: Option<String>,
    kid: Option<String>,
    alg: Option<String>,
    #[serde(rename = "use")]
    public_use: Option<String>,
    x: Option<String>,
}

impl CloudflareRouterRawJwkV1 {
    fn try_into_ed25519_key(self) -> RouterAbProtocolResult<Option<CloudflareRouterEd25519JwkV1>> {
        if self.kty != "OKP" || self.crv.as_deref() != Some("Ed25519") {
            return Ok(None);
        }
        if self.alg.as_deref().is_some_and(|alg| alg != "EdDSA") {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "Router JWT Ed25519 JWK alg must be EdDSA when present",
            ));
        }
        if self.public_use.as_deref().is_some_and(|use_| use_ != "sig") {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "Router JWT Ed25519 JWK use must be sig when present",
            ));
        }
        let kid = self.kid.ok_or_else(|| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "Router JWT Ed25519 JWK must include kid",
            )
        })?;
        let x = self.x.ok_or_else(|| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "Router JWT Ed25519 JWK must include x coordinate",
            )
        })?;
        let public_key = decode_base64url_fixed_32_v1("Router JWT Ed25519 JWK x", &x)?;
        CloudflareRouterEd25519JwkV1::new(kid, public_key).map(Some)
    }
}

#[derive(Debug, Deserialize)]
struct CloudflareRouterJwtHeaderV1 {
    alg: String,
    kid: String,
}

#[derive(Debug)]
struct CloudflareRouterCompactJwtV1 {
    signing_input: String,
    header: CloudflareRouterJwtHeaderV1,
    claims: CloudflareRouterJwtClaimsPayloadV1,
    signature: [u8; 64],
}

impl CloudflareRouterCompactJwtV1 {
    fn parse(token: &str) -> RouterAbProtocolResult<Self> {
        require_non_empty("router jwt token", token)?;
        require_no_ascii_whitespace("router jwt token", token)?;
        let mut parts = token.split('.');
        let header_segment = parts.next().ok_or_else(router_jwt_segment_error)?;
        let claims_segment = parts.next().ok_or_else(router_jwt_segment_error)?;
        let signature_segment = parts.next().ok_or_else(router_jwt_segment_error)?;
        if parts.next().is_some() {
            return Err(router_jwt_segment_error());
        }
        let header: CloudflareRouterJwtHeaderV1 =
            decode_base64url_json_v1("Router JWT header", header_segment)?;
        let claims: CloudflareRouterJwtClaimsPayloadV1 =
            decode_base64url_json_v1("Router JWT claims", claims_segment)?;
        let signature = decode_base64url_fixed_64_v1("Router JWT signature", signature_segment)?;
        Ok(Self {
            signing_input: format!("{header_segment}.{claims_segment}"),
            header,
            claims,
            signature,
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CloudflareRouterJwtClaimsPayloadV1 {
    kind: Option<String>,
    #[serde(rename = "authorizationKind", default)]
    authorization_kind: Option<String>,
    iss: String,
    sub: String,
    aud: CloudflareRouterJwtAudienceV1,
    exp: u64,
    nbf: Option<u64>,
    iat: Option<u64>,
    sid: String,
    #[serde(rename = "walletId", default)]
    wallet_id: Option<String>,
    #[serde(rename = "nearAccountId", default)]
    near_account_id: Option<String>,
    #[serde(rename = "nearEd25519SigningKeyId", default)]
    near_ed25519_signing_key_id: Option<String>,
    #[serde(rename = "relayerKeyId", default)]
    relayer_key_id: Option<String>,
    #[serde(rename = "authority", default)]
    authority: Option<serde_json::Value>,
    #[serde(rename = "authorityScope", default)]
    authority_scope: Option<serde_json::Value>,
    #[serde(rename = "authorizationId")]
    authorization_id: Option<String>,
    #[serde(rename = "authorizationSessionId", default)]
    authorization_session_id: Option<String>,
    #[serde(rename = "walletAuthAuthorityRef", default)]
    wallet_auth_authority_ref: Option<CloudflareRouterJwtWalletAuthAuthorityRefV1>,
    #[serde(rename = "authSource", default)]
    auth_source: Option<CloudflareRouterJwtWalletAuthSourceV1>,
    #[serde(rename = "walletSessionId")]
    wallet_session_id: Option<String>,
    #[serde(rename = "quotaId")]
    quota_id: Option<String>,
    #[serde(rename = "thresholdSessionId")]
    threshold_session_id: Option<String>,
    #[serde(rename = "keyScope", default)]
    key_scope: Option<String>,
    #[serde(rename = "keyHandle", default)]
    key_handle: Option<String>,
    #[serde(rename = "thresholdExpiresAtMs", default)]
    threshold_expires_at_ms: Option<u64>,
    #[serde(rename = "participantIds", default)]
    participant_ids: Option<Vec<u16>>,
    org_id: String,
    project_id: String,
    environment: String,
    account_id: String,
    #[serde(rename = "runtimePolicyScope", default)]
    runtime_policy_scope: Option<CloudflareRouterJwtRuntimePolicyScopeV1>,
    #[serde(rename = "routerAbRequestPolicy", default)]
    router_ab_request_policy: Option<RouterRequestPolicyClaimsV1>,
    #[serde(rename = "routerAbNormalSigning", default)]
    router_ab_normal_signing: Option<CloudflareRouterJwtNormalSigningWalletSessionClaimsV1>,
    #[serde(rename = "routerAbEcdsaDerivationNormalSigning", default)]
    router_ab_ecdsa_derivation_normal_signing:
        Option<CloudflareRouterJwtEcdsaDerivationNormalSigningClaimsV1>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CloudflareRouterJwtWalletAuthAuthorityRefV1 {
    kind: String,
    #[serde(rename = "walletId")]
    wallet_id: String,
    #[serde(rename = "authorityDigest")]
    authority_digest: String,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
enum CloudflareRouterJwtWalletAuthSourceV1 {
    #[serde(rename = "passkey")]
    Passkey {
        #[serde(rename = "credentialIdB64u")]
        credential_id_b64u: String,
    },
    #[serde(rename = "oidc_provider")]
    OidcProvider {
        #[serde(rename = "providerId")]
        provider_id: String,
        #[serde(rename = "providerSubject")]
        provider_subject: String,
    },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CloudflareRouterJwtRuntimePolicyScopeV1 {
    #[serde(rename = "orgId")]
    org_id: String,
    #[serde(rename = "projectId")]
    project_id: String,
    #[serde(rename = "envId")]
    env_id: String,
    #[serde(rename = "signingRootVersion")]
    signing_root_version: String,
}

impl CloudflareRouterJwtRuntimePolicyScopeV1 {
    fn validate_for_claims(
        &self,
        org_id: &str,
        project_id: &str,
        environment: &str,
    ) -> RouterAbProtocolResult<()> {
        require_non_empty("runtimePolicyScope.orgId", &self.org_id)?;
        require_non_empty("runtimePolicyScope.projectId", &self.project_id)?;
        require_non_empty("runtimePolicyScope.envId", &self.env_id)?;
        require_non_empty(
            "runtimePolicyScope.signingRootVersion",
            &self.signing_root_version,
        )?;
        if self.org_id != org_id || self.project_id != project_id || self.env_id != environment {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "Router Wallet Session runtime policy scope does not match its claims",
            ));
        }
        Ok(())
    }
}

fn validate_wallet_session_participant_ids(
    participant_ids: Option<&Vec<u16>>,
) -> RouterAbProtocolResult<()> {
    let participant_ids = participant_ids.ok_or_else(|| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "Router Wallet Session requires participantIds",
        )
    })?;
    if participant_ids.len() < 2
        || participant_ids
            .iter()
            .any(|participant_id| *participant_id == 0)
        || participant_ids.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "Router Wallet Session participantIds must be sorted, unique, and contain at least two positive ids",
        ));
    }
    Ok(())
}

fn require_wallet_session_authority(
    authority: Option<&serde_json::Value>,
    wallet_id: &str,
) -> RouterAbProtocolResult<()> {
    let authority = authority
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "Router Wallet Session requires authority",
            )
        })?;
    if authority
        .get("walletId")
        .and_then(serde_json::Value::as_str)
        != Some(wallet_id)
    {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "Router Wallet Session authority wallet id does not match walletId",
        ));
    }
    Ok(())
}

fn require_wallet_session_authority_scope(
    authority_scope: Option<&serde_json::Value>,
) -> RouterAbProtocolResult<()> {
    if authority_scope
        .and_then(serde_json::Value::as_object)
        .is_none()
    {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "Router Wallet Session requires authorityScope",
        ));
    }
    Ok(())
}

fn require_ecdsa_owner_wallet_session_claims(
    authorization_kind: Option<&str>,
    wallet_auth_authority_ref: Option<&CloudflareRouterJwtWalletAuthAuthorityRefV1>,
    auth_source: Option<&CloudflareRouterJwtWalletAuthSourceV1>,
    wallet_id: &str,
) -> RouterAbProtocolResult<()> {
    if authorization_kind != Some("owner_wallet_session") {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "Router Wallet Session authorizationKind must be owner_wallet_session",
        ));
    }
    let authority_ref = wallet_auth_authority_ref.ok_or_else(|| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "Router ECDSA Wallet Session requires walletAuthAuthorityRef",
        )
    })?;
    if authority_ref.kind != "wallet_auth_authority_ref" {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "Router ECDSA Wallet Session walletAuthAuthorityRef kind is unsupported",
        ));
    }
    require_non_empty(
        "Router ECDSA Wallet Session walletAuthAuthorityRef.walletId",
        &authority_ref.wallet_id,
    )?;
    require_no_ascii_whitespace(
        "Router ECDSA Wallet Session walletAuthAuthorityRef.walletId",
        &authority_ref.wallet_id,
    )?;
    if authority_ref.wallet_id != wallet_id {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "Router ECDSA Wallet Session walletAuthAuthorityRef wallet id does not match walletId",
        ));
    }
    decode_base64url_fixed_32_v1(
        "Router ECDSA Wallet Session walletAuthAuthorityRef.authorityDigest",
        &authority_ref.authority_digest,
    )?;

    let auth_source = auth_source.ok_or_else(|| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "Router ECDSA Wallet Session requires authSource",
        )
    })?;
    match auth_source {
        CloudflareRouterJwtWalletAuthSourceV1::Passkey { credential_id_b64u } => {
            require_non_empty(
                "Router ECDSA Wallet Session authSource.credentialIdB64u",
                credential_id_b64u,
            )?;
            require_no_ascii_whitespace(
                "Router ECDSA Wallet Session authSource.credentialIdB64u",
                credential_id_b64u,
            )?;
        }
        CloudflareRouterJwtWalletAuthSourceV1::OidcProvider {
            provider_id,
            provider_subject,
        } => {
            if provider_id != "google_oidc" && provider_id != "oidc" {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::MalformedWirePayload,
                    "Router ECDSA Wallet Session authSource providerId is unsupported",
                ));
            }
            require_non_empty(
                "Router ECDSA Wallet Session authSource.providerSubject",
                provider_subject,
            )?;
            require_no_ascii_whitespace(
                "Router ECDSA Wallet Session authSource.providerSubject",
                provider_subject,
            )?;
        }
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
struct CloudflareRouterJwtNormalSigningWalletSessionClaimsV1 {
    #[serde(rename = "signingWorkerId")]
    signing_worker_id: String,
}

impl CloudflareRouterJwtNormalSigningWalletSessionClaimsV1 {
    fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty(
            "routerAbNormalSigning.signingWorkerId",
            &self.signing_worker_id,
        )
    }
}

#[derive(Debug, Deserialize)]
struct CloudflareRouterJwtEcdsaDerivationNormalSigningClaimsV1 {
    scope: CloudflareRouterJwtEcdsaDerivationNormalSigningScopeV1,
}

#[derive(Debug, Deserialize)]
struct CloudflareRouterJwtEcdsaDerivationNormalSigningScopeV1 {
    wallet_id: String,
    signing_worker: CloudflareRouterJwtEcdsaDerivationSigningWorkerV1,
}

#[derive(Debug, Deserialize)]
struct CloudflareRouterJwtEcdsaDerivationSigningWorkerV1 {
    server_id: String,
}

impl CloudflareRouterJwtEcdsaDerivationNormalSigningClaimsV1 {
    fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty(
            "routerAbEcdsaDerivationNormalSigning.scope.wallet_id",
            &self.scope.wallet_id,
        )?;
        require_non_empty(
            "routerAbEcdsaDerivationNormalSigning.scope.signing_worker.server_id",
            &self.scope.signing_worker.server_id,
        )
    }
}

impl CloudflareRouterJwtClaimsPayloadV1 {
    fn validate_for_router_request(
        self,
        verifier: &CloudflareRouterJwtVerifierBindingV1,
        request: &EcdsaThresholdPrfRequestV1,
        request_policy_digest: PublicDigest32,
        now_unix_ms: u64,
        trusted_source_digest: PublicDigest32,
    ) -> RouterAbProtocolResult<CloudflareRouterVerifiedJwtClaimsV1> {
        verifier.validate()?;
        request.validate_at(now_unix_ms)?;
        let request_policy = self.router_ab_request_policy.as_ref().ok_or_else(|| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "Router JWT requires routerAbRequestPolicy",
            )
        })?;
        request_policy.validate()?;
        if request_policy.work_kind != request.lifecycle.work_kind {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "Router JWT request policy work kind does not match request",
            ));
        }
        if request_policy.request_digest != request_policy_digest {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "Router JWT request policy digest does not match request",
            ));
        }
        let claims = self.validate_common_for_request_expiry(
            verifier,
            request.expires_at_ms,
            now_unix_ms,
            trusted_source_digest,
        )?;
        claims
            .to_trusted_metadata(request)?
            .validate_for_request(request)?;
        Ok(claims)
    }

    fn validate_for_wallet_session(
        self,
        verifier: &CloudflareRouterJwtVerifierBindingV1,
        now_unix_ms: u64,
        trusted_source_digest: PublicDigest32,
    ) -> RouterAbProtocolResult<CloudflareRouterVerifiedWalletSessionV1> {
        verifier.validate()?;
        if self.iss != verifier.issuer {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "Router Wallet Session issuer does not match verifier config",
            ));
        }
        if !self.aud.contains(&verifier.audience) {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "Router Wallet Session audience does not match verifier config",
            ));
        }
        let exp_ms = unix_seconds_to_millis_v1("wallet session exp", self.exp)?;
        if exp_ms <= now_unix_ms {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ExpiredLocalRequest,
                "Router Wallet Session is expired",
            ));
        }
        if let Some(nbf) = self.nbf {
            let nbf_ms = unix_seconds_to_millis_v1("wallet session nbf", nbf)?;
            if nbf_ms > now_unix_ms {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidTimeRange,
                    "Router Wallet Session is not valid yet",
                ));
            }
        }
        if let Some(iat) = self.iat {
            let iat_ms = unix_seconds_to_millis_v1("wallet session iat", iat)?;
            if iat_ms > now_unix_ms {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidTimeRange,
                    "Router Wallet Session issued-at time is in the future",
                ));
            }
        }
        let kind = self.kind.as_deref().ok_or_else(|| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "Router Wallet Session requires kind",
            )
        })?;
        let wallet_id = self.wallet_id.as_deref().ok_or_else(|| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "Router Wallet Session requires walletId",
            )
        })?;
        require_non_empty("Router Wallet Session walletId", wallet_id)?;
        if wallet_id != self.sub {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "Router Wallet Session walletId must match sub",
            ));
        }
        validate_wallet_session_participant_ids(self.participant_ids.as_ref())?;
        let threshold_expires_at_ms = self.threshold_expires_at_ms.ok_or_else(|| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "Router Wallet Session requires thresholdExpiresAtMs",
            )
        })?;
        if threshold_expires_at_ms <= now_unix_ms {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ExpiredLocalRequest,
                "Router Wallet Session threshold expiry has passed",
            ));
        }
        let is_ed25519 = kind == "router_ab_ed25519_wallet_session_v1";
        let is_ecdsa = kind == "router_ab_ecdsa_derivation_wallet_session_v1";
        if !is_ed25519 && !is_ecdsa {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "Router Wallet Session kind is unsupported",
            ));
        }
        if is_ed25519 {
            if self.authorization_kind.as_deref() != Some("owner_wallet_session") {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::MalformedWirePayload,
                    "Router Wallet Session authorizationKind must be owner_wallet_session",
                ));
            }
            if self.authorization_session_id.is_some()
                || self.wallet_auth_authority_ref.is_some()
                || self.auth_source.is_some()
                || self.key_scope.is_some()
                || self.key_handle.is_some()
            {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::MalformedWirePayload,
                    "Router Ed25519 Wallet Session contains ECDSA-only claims",
                ));
            }
        }
        if let Some(runtime_policy_scope) = self.runtime_policy_scope.as_ref() {
            runtime_policy_scope.validate_for_claims(
                &self.org_id,
                &self.project_id,
                &self.environment,
            )?;
        } else {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "Router Wallet Session requires runtimePolicyScope",
            ));
        }
        if is_ed25519 {
            let near_account_id = self.near_account_id.as_deref().ok_or_else(|| {
                RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::MalformedWirePayload,
                    "Router Wallet Session requires nearAccountId",
                )
            })?;
            require_non_empty("Router Wallet Session nearAccountId", near_account_id)?;
            let near_signing_key_id =
                self.near_ed25519_signing_key_id.as_deref().ok_or_else(|| {
                    RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::MalformedWirePayload,
                        "Router Wallet Session requires nearEd25519SigningKeyId",
                    )
                })?;
            require_non_empty(
                "Router Wallet Session nearEd25519SigningKeyId",
                near_signing_key_id,
            )?;
            let relayer_key_id = self.relayer_key_id.as_deref().ok_or_else(|| {
                RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::MalformedWirePayload,
                    "Router Wallet Session requires relayerKeyId",
                )
            })?;
            require_non_empty("Router Wallet Session relayerKeyId", relayer_key_id)?;
            require_wallet_session_authority(self.authority.as_ref(), wallet_id)?;
            require_wallet_session_authority_scope(self.authority_scope.as_ref())?;
        }
        if is_ecdsa {
            require_ecdsa_owner_wallet_session_claims(
                self.authorization_kind.as_deref(),
                self.wallet_auth_authority_ref.as_ref(),
                self.auth_source.as_ref(),
                wallet_id,
            )?;
            if self.account_id != wallet_id {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::MalformedWirePayload,
                    "Router Wallet Session account_id must match walletId",
                ));
            }
            let authorization_session_id =
                self.authorization_session_id.as_deref().ok_or_else(|| {
                    RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::MalformedWirePayload,
                        "Router Wallet Session requires authorizationSessionId",
                    )
                })?;
            if authorization_session_id != self.sid {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::MalformedWirePayload,
                    "Router Wallet Session authorizationSessionId must match sid",
                ));
            }
            if self.key_scope.as_deref() != Some("evm-family") {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::MalformedWirePayload,
                    "Router Wallet Session keyScope must be evm-family",
                ));
            }
            let key_handle = self.key_handle.as_deref().ok_or_else(|| {
                RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::MalformedWirePayload,
                    "Router Wallet Session requires keyHandle",
                )
            })?;
            require_non_empty("Router Wallet Session keyHandle", key_handle)?;
            let relayer_key_id = self.relayer_key_id.as_deref().ok_or_else(|| {
                RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::MalformedWirePayload,
                    "Router Wallet Session requires relayerKeyId",
                )
            })?;
            require_non_empty("Router Wallet Session relayerKeyId", relayer_key_id)?;
        }
        let (authorization_level, signing_worker_id) = match (
            self.router_ab_normal_signing.as_ref(),
            self.router_ab_ecdsa_derivation_normal_signing.as_ref(),
        ) {
            (Some(normal_signing), None) => {
                normal_signing.validate()?;
                if !is_ed25519 {
                    return Err(RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::MalformedWirePayload,
                        "Router Wallet Session kind does not match Ed25519 normal signing",
                    ));
                }
                (
                    "near-ed25519".to_owned(),
                    normal_signing.signing_worker_id.clone(),
                )
            }
            (None, Some(normal_signing)) => {
                normal_signing.validate()?;
                if !is_ecdsa {
                    return Err(RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::MalformedWirePayload,
                        "Router Wallet Session kind does not match ECDSA normal signing",
                    ));
                }
                if normal_signing.scope.wallet_id != wallet_id {
                    return Err(RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::MalformedWirePayload,
                        "Router Wallet Session normal-signing wallet id does not match walletId",
                    ));
                }
                (
                    "evm-family".to_owned(),
                    normal_signing.scope.signing_worker.server_id.clone(),
                )
            }
            (None, None) => {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::MalformedWirePayload,
                    "Router Wallet Session requires one normal-signing binding",
                ));
            }
            (Some(_), Some(_)) => {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::MalformedWirePayload,
                    "Router Wallet Session contains conflicting normal-signing bindings",
                ));
            }
        };
        require_non_empty("jwt sid", &self.sid)?;
        let authorization_session_id = self.sid;
        let authorization_id = self.authorization_id.ok_or_else(|| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "Router Wallet Session requires authorizationId",
            )
        })?;
        let wallet_session_id = self.wallet_session_id.ok_or_else(|| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "Router Wallet Session requires walletSessionId",
            )
        })?;
        let quota_id = self.quota_id.ok_or_else(|| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "Router Wallet Session requires quotaId",
            )
        })?;
        let threshold_session_id = self.threshold_session_id.ok_or_else(|| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "Router Wallet Session requires thresholdSessionId",
            )
        })?;
        CloudflareRouterVerifiedWalletSessionV1::new(
            self.sub,
            self.account_id,
            authorization_session_id,
            authorization_id,
            wallet_session_id,
            quota_id,
            threshold_session_id,
            self.org_id,
            self.project_id,
            self.environment,
            authorization_level,
            signing_worker_id,
            trusted_source_digest,
            exp_ms,
        )
    }

    fn validate_common_for_request_expiry(
        self,
        verifier: &CloudflareRouterJwtVerifierBindingV1,
        request_expires_at_ms: u64,
        now_unix_ms: u64,
        trusted_source_digest: PublicDigest32,
    ) -> RouterAbProtocolResult<CloudflareRouterVerifiedJwtClaimsV1> {
        verifier.validate()?;
        if self.iss != verifier.issuer {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "Router JWT issuer does not match verifier config",
            ));
        }
        if !self.aud.contains(&verifier.audience) {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "Router JWT audience does not match verifier config",
            ));
        }
        let exp_ms = unix_seconds_to_millis_v1("jwt exp", self.exp)?;
        if exp_ms <= now_unix_ms {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ExpiredLocalRequest,
                "Router JWT is expired",
            ));
        }
        if exp_ms < request_expires_at_ms {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidTimeRange,
                "Router JWT expires before the request",
            ));
        }
        if let Some(nbf) = self.nbf {
            let nbf_ms = unix_seconds_to_millis_v1("jwt nbf", nbf)?;
            if nbf_ms > now_unix_ms {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidTimeRange,
                    "Router JWT is not valid yet",
                ));
            }
        }
        if let Some(iat) = self.iat {
            let iat_ms = unix_seconds_to_millis_v1("jwt iat", iat)?;
            if iat_ms > now_unix_ms {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidTimeRange,
                    "Router JWT issued-at time is in the future",
                ));
            }
        }
        require_non_empty("jwt sid", &self.sid)?;
        let session_id = self.sid;
        let claims = CloudflareRouterVerifiedJwtClaimsV1::new(
            self.sub,
            session_id,
            self.org_id,
            self.project_id,
            self.environment,
            self.account_id,
            trusted_source_digest,
        )?;
        Ok(claims)
    }
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum CloudflareRouterJwtAudienceV1 {
    Single(String),
    Many(Vec<String>),
}

impl CloudflareRouterJwtAudienceV1 {
    fn contains(&self, expected: &str) -> bool {
        match self {
            Self::Single(audience) => audience == expected,
            Self::Many(audiences) => audiences.iter().any(|audience| audience == expected),
        }
    }
}

/// JWT verifier boundary used by the Router session provider.
pub trait CloudflareRouterJwtVerifierV1 {
    /// Verifies a bearer token and returns normalized claims.
    fn verify_public_request_jwt(
        &mut self,
        verifier: &CloudflareRouterJwtVerifierBindingV1,
        authorization: &CloudflareRouterBearerAuthorizationV1,
        request: &EcdsaThresholdPrfRequestV1,
        request_policy_digest: PublicDigest32,
        now_unix_ms: u64,
        trusted_source_digest: PublicDigest32,
    ) -> RouterAbProtocolResult<CloudflareRouterVerifiedJwtClaimsV1>;
}

/// Session provider backed by a Router JWT verifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudflareRouterJwtSessionProviderV1<Verifier> {
    verifier_binding: CloudflareRouterJwtVerifierBindingV1,
    authorization: CloudflareRouterBearerAuthorizationV1,
    now_unix_ms: u64,
    trusted_source_digest: PublicDigest32,
    request_policy_digest: PublicDigest32,
    verifier: Verifier,
}

impl<Verifier> CloudflareRouterJwtSessionProviderV1<Verifier> {
    /// Creates a JWT-backed session provider from parsed boundary inputs.
    pub fn new(
        verifier_binding: CloudflareRouterJwtVerifierBindingV1,
        authorization: CloudflareRouterBearerAuthorizationV1,
        now_unix_ms: u64,
        trusted_source_digest: PublicDigest32,
        request_policy_digest: PublicDigest32,
        verifier: Verifier,
    ) -> RouterAbProtocolResult<Self> {
        let provider = Self {
            verifier_binding,
            authorization,
            now_unix_ms,
            trusted_source_digest,
            request_policy_digest,
            verifier,
        };
        provider.validate()?;
        Ok(provider)
    }

    /// Validates provider inputs before verifier execution.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.verifier_binding.validate()?;
        self.authorization.validate()?;
        require_positive_ms("jwt session now_unix_ms", self.now_unix_ms)
    }
}

impl<Verifier> CloudflareRouterSessionProviderV1 for CloudflareRouterJwtSessionProviderV1<Verifier>
where
    Verifier: CloudflareRouterJwtVerifierV1,
{
    fn verify_public_request_session(
        &mut self,
        request: &EcdsaThresholdPrfRequestV1,
    ) -> RouterAbProtocolResult<CloudflareRouterTrustedRequestMetadataV1> {
        request.validate()?;
        let claims = self.verifier.verify_public_request_jwt(
            &self.verifier_binding,
            &self.authorization,
            request,
            self.request_policy_digest,
            self.now_unix_ms,
            self.trusted_source_digest,
        )?;
        claims.to_trusted_metadata(request)
    }
}

/// Router project policy provider used by the admission chain.
pub trait CloudflareRouterProjectPolicyProviderV1 {
    /// Evaluates whether a project may run this work kind.
    fn evaluate_project_policy(
        &mut self,
        metadata: &CloudflareRouterTrustedRequestMetadataV1,
        request: &EcdsaThresholdPrfRequestV1,
    ) -> RouterAbProtocolResult<CloudflareRouterProjectPolicyV1>;
}

/// Project policy provider backed by an explicit allowed-work-kind set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudflareRouterAllowedWorkKindsProjectPolicyProviderV1 {
    allowed_work_kinds: Vec<ExpensiveWorkKindV1>,
    rejected_retry_after_ms: u64,
}

impl CloudflareRouterAllowedWorkKindsProjectPolicyProviderV1 {
    /// Creates a project policy provider from the allowed work-kind set.
    pub fn new(
        allowed_work_kinds: Vec<ExpensiveWorkKindV1>,
        rejected_retry_after_ms: u64,
    ) -> RouterAbProtocolResult<Self> {
        let provider = Self {
            allowed_work_kinds,
            rejected_retry_after_ms,
        };
        provider.validate()?;
        Ok(provider)
    }

    /// Validates provider configuration.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_work_kind_set("allowed_work_kinds", &self.allowed_work_kinds)?;
        require_positive_ms(
            "project policy rejected retry_after_ms",
            self.rejected_retry_after_ms,
        )
    }
}

impl CloudflareRouterProjectPolicyProviderV1
    for CloudflareRouterAllowedWorkKindsProjectPolicyProviderV1
{
    fn evaluate_project_policy(
        &mut self,
        metadata: &CloudflareRouterTrustedRequestMetadataV1,
        request: &EcdsaThresholdPrfRequestV1,
    ) -> RouterAbProtocolResult<CloudflareRouterProjectPolicyV1> {
        metadata.validate_for_request(request)?;
        if self.allowed_work_kinds.contains(&metadata.work_kind) {
            return Ok(CloudflareRouterProjectPolicyV1::Allowed);
        }
        Ok(CloudflareRouterProjectPolicyV1::Rejected {
            retry_after_ms: self.rejected_retry_after_ms,
        })
    }
}

/// Router abuse-control provider used by the admission chain.
pub trait CloudflareRouterAbuseProviderV1 {
    /// Evaluates source, principal, and request-level abuse controls.
    fn evaluate_abuse(
        &mut self,
        metadata: &CloudflareRouterTrustedRequestMetadataV1,
        request: &EcdsaThresholdPrfRequestV1,
    ) -> RouterAbProtocolResult<CloudflareRouterAbuseCheckV1>;
}

/// Abuse-control provider backed by a caller-supplied decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudflareRouterConfiguredAbuseProviderV1 {
    outcome: CloudflareRouterAbuseCheckV1,
}

impl CloudflareRouterConfiguredAbuseProviderV1 {
    /// Creates an abuse provider from a validated decision.
    pub fn new(outcome: CloudflareRouterAbuseCheckV1) -> RouterAbProtocolResult<Self> {
        outcome.validate()?;
        Ok(Self { outcome })
    }
}

impl CloudflareRouterAbuseProviderV1 for CloudflareRouterConfiguredAbuseProviderV1 {
    fn evaluate_abuse(
        &mut self,
        metadata: &CloudflareRouterTrustedRequestMetadataV1,
        request: &EcdsaThresholdPrfRequestV1,
    ) -> RouterAbProtocolResult<CloudflareRouterAbuseCheckV1> {
        metadata.validate_for_request(request)?;
        Ok(self.outcome.clone())
    }
}

/// Router quota provider used by the admission chain.
pub trait CloudflareRouterQuotaProviderV1 {
    /// Evaluates quota, idempotency reuse, and signer queue capacity.
    fn evaluate_quota(
        &mut self,
        metadata: &CloudflareRouterTrustedRequestMetadataV1,
        request: &EcdsaThresholdPrfRequestV1,
    ) -> RouterAbProtocolResult<CloudflareRouterQuotaCheckV1>;
}

/// Quota provider backed by a caller-supplied decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudflareRouterConfiguredQuotaProviderV1 {
    outcome: CloudflareRouterQuotaCheckV1,
}

impl CloudflareRouterConfiguredQuotaProviderV1 {
    /// Creates a quota provider from a validated decision.
    pub fn new(outcome: CloudflareRouterQuotaCheckV1) -> RouterAbProtocolResult<Self> {
        outcome.validate()?;
        Ok(Self { outcome })
    }
}

impl CloudflareRouterQuotaProviderV1 for CloudflareRouterConfiguredQuotaProviderV1 {
    fn evaluate_quota(
        &mut self,
        metadata: &CloudflareRouterTrustedRequestMetadataV1,
        request: &EcdsaThresholdPrfRequestV1,
    ) -> RouterAbProtocolResult<CloudflareRouterQuotaCheckV1> {
        metadata.validate_for_request(request)?;
        Ok(self.outcome.clone())
    }
}

/// Composite Router provider that wires session, policy, abuse, and quota checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudflareRouterCompositeAdmissionProviderV1<
    SessionProvider,
    ProjectPolicyProvider,
    AbuseProvider,
    QuotaProvider,
> {
    session: SessionProvider,
    project_policy: ProjectPolicyProvider,
    abuse: AbuseProvider,
    quota: QuotaProvider,
}

impl<SessionProvider, ProjectPolicyProvider, AbuseProvider, QuotaProvider>
    CloudflareRouterCompositeAdmissionProviderV1<
        SessionProvider,
        ProjectPolicyProvider,
        AbuseProvider,
        QuotaProvider,
    >
{
    /// Creates a composite Router admission provider.
    pub fn new(
        session: SessionProvider,
        project_policy: ProjectPolicyProvider,
        abuse: AbuseProvider,
        quota: QuotaProvider,
    ) -> Self {
        Self {
            session,
            project_policy,
            abuse,
            quota,
        }
    }
}

impl<SessionProvider, ProjectPolicyProvider, AbuseProvider, QuotaProvider>
    CloudflareRouterAdmissionProviderV1
    for CloudflareRouterCompositeAdmissionProviderV1<
        SessionProvider,
        ProjectPolicyProvider,
        AbuseProvider,
        QuotaProvider,
    >
where
    SessionProvider: CloudflareRouterSessionProviderV1,
    ProjectPolicyProvider: CloudflareRouterProjectPolicyProviderV1,
    AbuseProvider: CloudflareRouterAbuseProviderV1,
    QuotaProvider: CloudflareRouterQuotaProviderV1,
{
    fn evaluate_public_request_admission(
        &mut self,
        request: &EcdsaThresholdPrfRequestV1,
    ) -> RouterAbProtocolResult<CloudflareRouterAdmissionProviderOutputV1> {
        request.validate()?;
        let metadata = self.session.verify_public_request_session(request)?;
        metadata.validate_for_request(request)?;
        let project_policy = self
            .project_policy
            .evaluate_project_policy(&metadata, request)?;
        project_policy.validate()?;
        let abuse = self.abuse.evaluate_abuse(&metadata, request)?;
        abuse.validate()?;
        let quota = self.quota.evaluate_quota(&metadata, request)?;
        quota.validate()?;
        CloudflareRouterAdmissionProviderOutputV1::new(
            metadata,
            CloudflareRouterAdmissionChecksV1::new(project_policy, abuse, quota)?,
        )
    }
}

/// Derives trusted Router admission from a provider-owned admission boundary.
pub fn derive_cloudflare_router_trusted_admission_from_provider_v1(
    request: &EcdsaThresholdPrfRequestV1,
    provider: &mut impl CloudflareRouterAdmissionProviderV1,
) -> RouterAbProtocolResult<CloudflareRouterTrustedAdmissionV1> {
    request.validate()?;
    let output = provider.evaluate_public_request_admission(request)?;
    output.validate_for_request(request)?;
    derive_cloudflare_router_trusted_admission_v1(request, output.metadata, output.checks)
}

/// Derives trusted Router admission from server-owned metadata and checks.
pub fn derive_cloudflare_router_trusted_admission_v1(
    request: &EcdsaThresholdPrfRequestV1,
    metadata: CloudflareRouterTrustedRequestMetadataV1,
    checks: CloudflareRouterAdmissionChecksV1,
) -> RouterAbProtocolResult<CloudflareRouterTrustedAdmissionV1> {
    request.validate()?;
    metadata.validate_for_request(request)?;
    checks.validate()?;
    let admission = CloudflareRouterTrustedAdmissionV1::new(
        metadata.to_gate_context()?,
        checks.to_gate_decision()?,
    )?;
    admission.validate_for_request(request)?;
    Ok(admission)
}

/// Server-derived Router admission data for a public expensive-work request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareRouterTrustedAdmissionV1 {
    /// Trusted Router-owned gate context.
    pub context: ExpensiveWorkGateContextV1,
    /// Trusted Router-owned gate decision.
    pub decision: ExpensiveWorkGateDecisionV1,
}

impl CloudflareRouterTrustedAdmissionV1 {
    /// Creates a validated trusted admission wrapper.
    pub fn new(
        context: ExpensiveWorkGateContextV1,
        decision: ExpensiveWorkGateDecisionV1,
    ) -> RouterAbProtocolResult<Self> {
        let admission = Self { context, decision };
        admission.validate()?;
        Ok(admission)
    }

    /// Validates the admission wrapper itself.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.context.validate()?;
        self.decision.validate()
    }

    /// Validates server-derived admission data against the normalized request.
    pub fn validate_for_request(
        &self,
        request: &EcdsaThresholdPrfRequestV1,
    ) -> RouterAbProtocolResult<()> {
        self.validate()?;
        request.validate()?;
        if self.context.work_kind != request.lifecycle.work_kind {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "trusted admission work kind does not match public request lifecycle",
            ));
        }
        if self.context.resource_id != request.lifecycle.account_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "trusted admission resource id does not match public request account",
            ));
        }
        match &self.context.principal {
            GatePrincipalV1::AuthenticatedSession { session_id, .. } => {
                if session_id != &request.lifecycle.session_id {
                    return Err(RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::InvalidGateDecision,
                        "trusted authenticated session does not match public request lifecycle",
                    ));
                }
            }
            GatePrincipalV1::PreAuthSession {
                pre_auth_session_id,
            } => {
                if pre_auth_session_id != &request.lifecycle.session_id {
                    return Err(RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::InvalidGateDecision,
                        "trusted pre-auth session does not match public request lifecycle",
                    ));
                }
                if self.context.work_kind != ExpensiveWorkKindV1::RegistrationPrepare {
                    return Err(RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::InvalidGateDecision,
                        "pre-auth trusted admission is allowed only for registration prepare",
                    ));
                }
            }
        }
        Ok(())
    }

    /// Returns whether signer forwarding is allowed for this decision.
    pub fn allows_signer_forwarding(&self) -> RouterAbProtocolResult<bool> {
        self.validate()?;
        Ok(matches!(
            self.decision,
            ExpensiveWorkGateDecisionV1::Accepted { .. }
                | ExpensiveWorkGateDecisionV1::ReuseExisting { .. }
        ))
    }

    /// Returns the lifecycle state that the Router should persist.
    pub fn lifecycle_state_for_request(
        &self,
        request: &EcdsaThresholdPrfRequestV1,
    ) -> RouterAbProtocolResult<RouterAbLifecycleStateV1> {
        self.validate_for_request(request)?;
        RouterAbLifecycleStateV1::apply_gate_decision(
            request.lifecycle.clone(),
            self.decision.clone(),
        )
    }
}

/// Server-derived Router admission data for a normal-signing request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareRouterNormalSigningTrustedAdmissionV1 {
    /// Trusted Router-owned normal-signing metadata.
    pub metadata: CloudflareRouterNormalSigningTrustedMetadataV1,
    /// Trusted Router-owned gate decision.
    pub decision: ExpensiveWorkGateDecisionV1,
}

impl CloudflareRouterNormalSigningTrustedAdmissionV1 {
    /// Creates a validated normal-signing admission wrapper.
    pub fn new(
        metadata: CloudflareRouterNormalSigningTrustedMetadataV1,
        decision: ExpensiveWorkGateDecisionV1,
    ) -> RouterAbProtocolResult<Self> {
        let admission = Self { metadata, decision };
        admission.validate()?;
        Ok(admission)
    }

    /// Validates the normal-signing admission wrapper itself.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.metadata.validate()?;
        self.decision.validate()
    }

    /// Validates server-derived admission data against a typed v2 finalize request.
    pub fn validate_for_finalize_request_v2(
        &self,
        request: &RouterAbEd25519NormalSigningFinalizeRequestV2,
    ) -> RouterAbProtocolResult<()> {
        self.validate()?;
        self.metadata.validate_for_finalize_request_v2(request)
    }

    /// Returns whether SigningWorker forwarding is allowed for this decision.
    pub fn allows_signing_worker_forwarding(&self) -> RouterAbProtocolResult<bool> {
        self.validate()?;
        Ok(matches!(
            self.decision,
            ExpensiveWorkGateDecisionV1::Accepted { .. }
        ))
    }
}

/// Exact authorization branch admitted by the Router for normal signing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum CloudflareRouterNormalSigningAuthorizationV2 {
    /// Reusable Wallet Session authority.
    ReusableWalletSession {
        /// Exact durable Wallet Session authorization id.
        authorization_id: String,
        /// Exact reusable Wallet Session id.
        wallet_session_id: String,
    },
    /// Single-operation step-up authority.
    OperationStepUp {
        /// Exact Seams authorization-session id that verified the evidence.
        authorization_session_id: String,
        /// Digest of the verified evidence set. This field is server-private;
        /// the public normal-signing marker carries no evidence data.
        evidence_set_digest: String,
    },
}

impl CloudflareRouterNormalSigningAuthorizationV2 {
    pub fn kind_label(&self) -> &'static str {
        match self {
            Self::ReusableWalletSession { .. } => "reusable_wallet_session",
            Self::OperationStepUp { .. } => "operation_step_up",
        }
    }

    pub fn authorization_id(&self) -> RouterAbProtocolResult<&str> {
        match self {
            Self::ReusableWalletSession {
                authorization_id, ..
            } => Ok(authorization_id),
            Self::OperationStepUp { .. } => Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "operation step-up authority has no public authorization id",
            )),
        }
    }

    /// Creates reusable Wallet Session authority.
    pub fn reusable_wallet_session(
        authorization_id: impl Into<String>,
        wallet_session_id: impl Into<String>,
    ) -> RouterAbProtocolResult<Self> {
        let authorization = Self::ReusableWalletSession {
            authorization_id: authorization_id.into(),
            wallet_session_id: wallet_session_id.into(),
        };
        authorization.validate()?;
        Ok(authorization)
    }

    /// Creates single-operation step-up authority.
    pub fn operation_step_up(
        authorization_session_id: impl Into<String>,
        evidence_set_digest: impl Into<String>,
    ) -> RouterAbProtocolResult<Self> {
        let authorization = Self::OperationStepUp {
            authorization_session_id: authorization_session_id.into(),
            evidence_set_digest: evidence_set_digest.into(),
        };
        authorization.validate()?;
        Ok(authorization)
    }

    /// Validates exact branch identity.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        match self {
            Self::ReusableWalletSession {
                authorization_id,
                wallet_session_id,
            } => {
                require_non_empty(
                    "normal-signing authorization authorization_id",
                    authorization_id,
                )?;
                require_non_empty(
                    "normal-signing authorization wallet_session_id",
                    wallet_session_id,
                )?;
                if authorization_id == wallet_session_id {
                    return Err(RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::InvalidGateDecision,
                        "normal-signing authorization and Wallet Session ids must be pairwise distinct",
                    ));
                }
                Ok(())
            }
            Self::OperationStepUp {
                authorization_session_id,
                evidence_set_digest,
            } => {
                require_non_empty(
                    "normal-signing authorization authorization_session_id",
                    authorization_session_id,
                )?;
                require_non_empty(
                    "normal-signing authorization evidence_set_digest",
                    evidence_set_digest,
                )
            }
        }
    }

    /// Validates this trusted authorization against the public scope branch.
    pub fn validate_for_scope(
        &self,
        authorization: &NormalSigningAuthorizationV1,
    ) -> RouterAbProtocolResult<()> {
        self.validate()?;
        authorization.validate()?;
        let matches = match (self, authorization) {
            (
                Self::ReusableWalletSession {
                    authorization_id: _,
                    wallet_session_id,
                    ..
                },
                NormalSigningAuthorizationV1::ReusableWalletSession {
                    wallet_session_id: scope_session_id,
                },
            ) => wallet_session_id == scope_session_id,
            (Self::OperationStepUp { .. }, NormalSigningAuthorizationV1::OperationStepUp) => true,
            _ => false,
        };
        if matches {
            Ok(())
        } else {
            Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "normal-signing trusted authorization does not match request scope",
            ))
        }
    }

    fn to_auth_context(
        &self,
        subject_id: impl Into<String>,
    ) -> RouterAbProtocolResult<CloudflareRouterAuthContextV1> {
        let subject_id = subject_id.into();
        match self {
            Self::ReusableWalletSession {
                authorization_id: _,
                wallet_session_id,
                ..
            } => CloudflareRouterAuthContextV1::authenticated_session(
                subject_id,
                wallet_session_id.clone(),
            ),
            Self::OperationStepUp {
                authorization_session_id,
                ..
            } => CloudflareRouterAuthContextV1::operation_step_up_session(
                subject_id,
                authorization_session_id.clone(),
            ),
        }
    }
}

/// Pre-gate Router admission candidate for typed normal-signing v2 prepare.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareRouterNormalSigningPrepareAdmissionCandidateV2 {
    /// Canonical organization id.
    pub org_id: String,
    /// Canonical project id.
    pub project_id: String,
    /// Deployment environment label.
    pub environment: String,
    /// Account, wallet, or root resource id.
    pub account_id: String,
    /// Canonical subject id from verified wallet auth.
    pub subject_id: String,
    /// Exact Router-verified authorization branch.
    pub authorization: CloudflareRouterNormalSigningAuthorizationV2,
    /// Active SigningWorker id authorized for this request.
    pub signing_worker_id: String,
    /// Router request id from the typed normal-signing scope.
    pub request_id: String,
    /// Digest of the canonical typed intent.
    pub intent_digest: PublicDigest32,
    /// Digest of the canonical typed signing payload.
    pub signing_payload_digest: PublicDigest32,
    /// Exact 32-byte digest admitted for the SigningWorker finalizer.
    pub admitted_signing_digest: PublicDigest32,
    /// Prepared round-1 binding digest when the request has reached prepare admission.
    pub round1_binding_digest: Option<PublicDigest32>,
    /// Digest of trusted source metadata, such as edge client address.
    pub trusted_source_digest: PublicDigest32,
    /// Request expiry in Unix milliseconds.
    pub expires_at_ms: u64,
}

impl CloudflareRouterNormalSigningPrepareAdmissionCandidateV2 {
    /// Creates validated internal normal-signing v2 prepare admission candidate data.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        org_id: impl Into<String>,
        project_id: impl Into<String>,
        environment: impl Into<String>,
        account_id: impl Into<String>,
        subject_id: impl Into<String>,
        authorization: CloudflareRouterNormalSigningAuthorizationV2,
        signing_worker_id: impl Into<String>,
        request_id: impl Into<String>,
        intent_digest: PublicDigest32,
        signing_payload_digest: PublicDigest32,
        admitted_signing_digest: PublicDigest32,
        round1_binding_digest: Option<PublicDigest32>,
        trusted_source_digest: PublicDigest32,
        expires_at_ms: u64,
    ) -> RouterAbProtocolResult<Self> {
        let admission = Self {
            org_id: org_id.into(),
            project_id: project_id.into(),
            environment: environment.into(),
            account_id: account_id.into(),
            subject_id: subject_id.into(),
            authorization,
            signing_worker_id: signing_worker_id.into(),
            request_id: request_id.into(),
            intent_digest,
            signing_payload_digest,
            admitted_signing_digest,
            round1_binding_digest,
            trusted_source_digest,
            expires_at_ms,
        };
        admission.validate()?;
        Ok(admission)
    }

    /// Builds a prepare admission candidate from a verified Wallet Session and typed request.
    pub fn from_prepare_request(
        wallet_session: &CloudflareRouterVerifiedWalletSessionV1,
        request: &RouterAbEd25519NormalSigningPrepareRequestV2,
        now_unix_ms: u64,
    ) -> RouterAbProtocolResult<Self> {
        wallet_session.validate_for_normal_signing_prepare_request_v2(request, now_unix_ms)?;
        let material = request.admission_material()?;
        let authorization = match &request.scope.authorization {
            NormalSigningAuthorizationV1::ReusableWalletSession { .. } => {
                CloudflareRouterNormalSigningAuthorizationV2::reusable_wallet_session(
                    wallet_session.authorization_id.clone(),
                    wallet_session.wallet_session_id.clone(),
                )?
            }
            NormalSigningAuthorizationV1::OperationStepUp => {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidGateDecision,
                    "Wallet Session bearer cannot authorize operation-step-up signing",
                ));
            }
        };
        let admission = Self::new(
            wallet_session.org_id.clone(),
            wallet_session.project_id.clone(),
            wallet_session.environment.clone(),
            wallet_session.account_id.clone(),
            wallet_session.subject_id.clone(),
            authorization,
            wallet_session.signing_worker_id.clone(),
            request.scope.request_id.clone(),
            material.intent_digest,
            material.signing_payload_digest,
            material.admitted_signing_digest,
            Some(request.round1_binding_digest()?),
            wallet_session.trusted_source_digest,
            request.expires_at_ms,
        )?;
        admission.validate_for_prepare_request(request)?;
        Ok(admission)
    }

    /// Validates internal admission fields independent of a request body.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("normal-signing v2 org_id", &self.org_id)?;
        require_non_empty("normal-signing v2 project_id", &self.project_id)?;
        require_non_empty("normal-signing v2 environment", &self.environment)?;
        require_non_empty("normal-signing v2 account_id", &self.account_id)?;
        require_non_empty("normal-signing v2 subject_id", &self.subject_id)?;
        self.authorization.validate()?;
        require_non_empty(
            "normal-signing v2 signing_worker_id",
            &self.signing_worker_id,
        )?;
        require_non_empty("normal-signing v2 request_id", &self.request_id)?;
        require_positive_ms("normal-signing v2 expires_at_ms", self.expires_at_ms)
    }

    /// Returns the v2 digest material carried by this prepare admission candidate.
    pub fn admission_material(
        &self,
    ) -> RouterAbProtocolResult<RouterAbEd25519NormalSigningAdmissionMaterialV2> {
        self.validate()?;
        Ok(RouterAbEd25519NormalSigningAdmissionMaterialV2 {
            intent_digest: self.intent_digest,
            signing_payload_digest: self.signing_payload_digest,
            admitted_signing_digest: self.admitted_signing_digest,
        })
    }

    /// Validates a prepare admission candidate against a typed prepare request.
    pub fn validate_for_prepare_request(
        &self,
        request: &RouterAbEd25519NormalSigningPrepareRequestV2,
    ) -> RouterAbProtocolResult<()> {
        self.validate()?;
        request.validate()?;
        if self.account_id != request.scope.account_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "normal-signing v2 admission account_id does not match request scope",
            ));
        }
        self.authorization
            .validate_for_scope(&request.scope.authorization)?;
        if self.signing_worker_id != request.scope.signing_worker_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "normal-signing v2 admission signing_worker_id does not match request scope",
            ));
        }
        if self.request_id != request.scope.request_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "normal-signing v2 admission request_id does not match request scope",
            ));
        }
        if self.expires_at_ms != request.expires_at_ms {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "normal-signing v2 admission expires_at_ms does not match request",
            ));
        }

        let expected = request.admission_material()?;
        if self.intent_digest != expected.intent_digest {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "normal-signing v2 admission intent digest does not match request",
            ));
        }
        if self.signing_payload_digest != expected.signing_payload_digest {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "normal-signing v2 admission signing payload digest does not match request",
            ));
        }
        if self.admitted_signing_digest != expected.admitted_signing_digest {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "normal-signing v2 admission admitted signing digest does not match request",
            ));
        }

        let Some(round1_binding_digest) = self.round1_binding_digest else {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "normal-signing v2 prepare admission requires round1 binding digest",
            ));
        };
        if round1_binding_digest != request.round1_binding_digest()? {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "normal-signing v2 admission round1 binding digest does not match request",
            ));
        }
        Ok(())
    }

    /// Converts the candidate to trusted Router metadata.
    pub fn to_v1_trusted_metadata(
        &self,
    ) -> RouterAbProtocolResult<CloudflareRouterNormalSigningTrustedMetadataV1> {
        self.validate()?;
        CloudflareRouterNormalSigningTrustedMetadataV1::new(
            self.org_id.clone(),
            self.project_id.clone(),
            self.environment.clone(),
            self.account_id.clone(),
            self.authorization
                .to_auth_context(self.subject_id.clone())?,
            self.trusted_source_digest,
            self.intent_digest,
        )
    }
}

/// Pre-gate Router admission candidate for typed normal-signing v2 finalize.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareRouterNormalSigningFinalizeAdmissionCandidateV2 {
    /// Canonical organization id.
    pub org_id: String,
    /// Canonical project id.
    pub project_id: String,
    /// Deployment environment label.
    pub environment: String,
    /// Account, wallet, or root resource id.
    pub account_id: String,
    /// Canonical subject id from verified wallet auth.
    pub subject_id: String,
    /// Exact Router-verified authorization branch.
    pub authorization: CloudflareRouterNormalSigningAuthorizationV2,
    /// Active SigningWorker id authorized for this request.
    pub signing_worker_id: String,
    /// Router request id from the typed normal-signing scope.
    pub request_id: String,
    /// Digest of the canonical typed intent admitted during prepare.
    pub intent_digest: PublicDigest32,
    /// Digest of the canonical typed signing payload admitted during prepare.
    pub signing_payload_digest: PublicDigest32,
    /// Prepared round-1 binding digest that finalize must consume.
    pub round1_binding_digest: PublicDigest32,
    /// Digest of trusted source metadata, such as edge client address.
    pub trusted_source_digest: PublicDigest32,
    /// Request expiry in Unix milliseconds.
    pub expires_at_ms: u64,
}

impl CloudflareRouterNormalSigningFinalizeAdmissionCandidateV2 {
    /// Creates validated internal normal-signing v2 finalize admission candidate data.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        org_id: impl Into<String>,
        project_id: impl Into<String>,
        environment: impl Into<String>,
        account_id: impl Into<String>,
        subject_id: impl Into<String>,
        authorization: CloudflareRouterNormalSigningAuthorizationV2,
        signing_worker_id: impl Into<String>,
        request_id: impl Into<String>,
        intent_digest: PublicDigest32,
        signing_payload_digest: PublicDigest32,
        round1_binding_digest: PublicDigest32,
        trusted_source_digest: PublicDigest32,
        expires_at_ms: u64,
    ) -> RouterAbProtocolResult<Self> {
        let admission = Self {
            org_id: org_id.into(),
            project_id: project_id.into(),
            environment: environment.into(),
            account_id: account_id.into(),
            subject_id: subject_id.into(),
            authorization,
            signing_worker_id: signing_worker_id.into(),
            request_id: request_id.into(),
            intent_digest,
            signing_payload_digest,
            round1_binding_digest,
            trusted_source_digest,
            expires_at_ms,
        };
        admission.validate()?;
        Ok(admission)
    }

    /// Builds a finalize admission candidate from a verified Wallet Session and typed request.
    pub fn from_finalize_request(
        wallet_session: &CloudflareRouterVerifiedWalletSessionV1,
        request: &RouterAbEd25519NormalSigningFinalizeRequestV2,
        now_unix_ms: u64,
    ) -> RouterAbProtocolResult<Self> {
        wallet_session.validate_for_normal_signing_finalize_request_v2(request, now_unix_ms)?;
        let authorization = match &request.scope.authorization {
            NormalSigningAuthorizationV1::ReusableWalletSession { .. } => {
                CloudflareRouterNormalSigningAuthorizationV2::reusable_wallet_session(
                    wallet_session.authorization_id.clone(),
                    wallet_session.wallet_session_id.clone(),
                )?
            }
            NormalSigningAuthorizationV1::OperationStepUp => {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidGateDecision,
                    "Wallet Session bearer cannot authorize operation-step-up signing",
                ));
            }
        };
        let admission = Self::new(
            wallet_session.org_id.clone(),
            wallet_session.project_id.clone(),
            wallet_session.environment.clone(),
            wallet_session.account_id.clone(),
            wallet_session.subject_id.clone(),
            authorization,
            wallet_session.signing_worker_id.clone(),
            request.scope.request_id.clone(),
            request.intent_digest(),
            request.signing_payload_digest(),
            request.round1_binding_digest(),
            wallet_session.trusted_source_digest,
            request.expires_at_ms,
        )?;
        admission.validate_for_finalize_request(request)?;
        Ok(admission)
    }

    /// Validates internal finalize admission fields independent of a request body.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("normal-signing v2 finalize org_id", &self.org_id)?;
        require_non_empty("normal-signing v2 finalize project_id", &self.project_id)?;
        require_non_empty("normal-signing v2 finalize environment", &self.environment)?;
        require_non_empty("normal-signing v2 finalize account_id", &self.account_id)?;
        require_non_empty("normal-signing v2 finalize subject_id", &self.subject_id)?;
        self.authorization.validate()?;
        require_non_empty(
            "normal-signing v2 finalize signing_worker_id",
            &self.signing_worker_id,
        )?;
        require_non_empty("normal-signing v2 finalize request_id", &self.request_id)?;
        require_positive_ms(
            "normal-signing v2 finalize expires_at_ms",
            self.expires_at_ms,
        )
    }

    /// Validates a finalize admission candidate against a typed finalize request.
    pub fn validate_for_finalize_request(
        &self,
        request: &RouterAbEd25519NormalSigningFinalizeRequestV2,
    ) -> RouterAbProtocolResult<()> {
        self.validate()?;
        request.validate()?;
        if self.account_id != request.scope.account_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "normal-signing v2 finalize admission account_id does not match request scope",
            ));
        }
        self.authorization
            .validate_for_scope(&request.scope.authorization)?;
        if self.signing_worker_id != request.scope.signing_worker_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "normal-signing v2 finalize admission signing_worker_id does not match request scope",
            ));
        }
        if self.request_id != request.scope.request_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "normal-signing v2 finalize admission request_id does not match request scope",
            ));
        }
        if self.expires_at_ms != request.expires_at_ms {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "normal-signing v2 finalize admission expires_at_ms does not match request",
            ));
        }
        if self.intent_digest != request.intent_digest() {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "normal-signing v2 finalize admission intent digest does not match request",
            ));
        }
        if self.signing_payload_digest != request.signing_payload_digest() {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "normal-signing v2 finalize admission signing payload digest does not match request",
            ));
        }
        if self.round1_binding_digest != request.round1_binding_digest() {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "normal-signing v2 finalize admission round1 binding digest does not match request",
            ));
        }
        Ok(())
    }

    /// Converts the finalize candidate to trusted Router metadata.
    pub fn to_v1_trusted_metadata(
        &self,
    ) -> RouterAbProtocolResult<CloudflareRouterNormalSigningTrustedMetadataV1> {
        self.validate()?;
        CloudflareRouterNormalSigningTrustedMetadataV1::new(
            self.org_id.clone(),
            self.project_id.clone(),
            self.environment.clone(),
            self.account_id.clone(),
            self.authorization
                .to_auth_context(self.subject_id.clone())?,
            self.trusted_source_digest,
            self.intent_digest,
        )
    }
}

/// Pre-gate Router admission candidate for Router A/B ECDSA derivation EVM digest prepare.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareRouterAbEcdsaDerivationEvmDigestPrepareAdmissionCandidateV1 {
    /// Canonical organization id.
    pub org_id: String,
    /// Canonical project id.
    pub project_id: String,
    /// Deployment environment label.
    pub environment: String,
    /// Wallet id authorized by the Wallet Session.
    pub account_id: String,
    /// Canonical subject id from verified wallet auth.
    pub subject_id: String,
    /// Exact Router-verified authorization branch.
    pub authorization: CloudflareRouterNormalSigningAuthorizationV2,
    /// Active SigningWorker id authorized for this request.
    pub signing_worker_id: String,
    /// Router request id from the typed Router A/B ECDSA derivation request.
    pub request_id: String,
    /// Client-selected presignature id that must match the SigningWorker server share.
    pub client_presignature_id: String,
    /// Digest of the active Router A/B ECDSA derivation normal-signing scope.
    pub scope_digest: PublicDigest32,
    /// Canonical Router-admitted Router A/B ECDSA derivation signing request digest.
    pub request_digest: PublicDigest32,
    /// Exact 32-byte EVM digest admitted for SigningWorker finalize.
    pub signing_digest: PublicDigest32,
    /// Digest of trusted source metadata, such as edge client address.
    pub trusted_source_digest: PublicDigest32,
    /// Request expiry in Unix milliseconds.
    pub expires_at_ms: u64,
}

impl CloudflareRouterAbEcdsaDerivationEvmDigestPrepareAdmissionCandidateV1 {
    /// Creates validated internal Router A/B ECDSA derivation prepare admission candidate data.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        org_id: impl Into<String>,
        project_id: impl Into<String>,
        environment: impl Into<String>,
        account_id: impl Into<String>,
        subject_id: impl Into<String>,
        authorization: CloudflareRouterNormalSigningAuthorizationV2,
        signing_worker_id: impl Into<String>,
        request_id: impl Into<String>,
        client_presignature_id: impl Into<String>,
        scope_digest: PublicDigest32,
        request_digest: PublicDigest32,
        signing_digest: PublicDigest32,
        trusted_source_digest: PublicDigest32,
        expires_at_ms: u64,
    ) -> RouterAbProtocolResult<Self> {
        let admission = Self {
            org_id: org_id.into(),
            project_id: project_id.into(),
            environment: environment.into(),
            account_id: account_id.into(),
            subject_id: subject_id.into(),
            authorization,
            signing_worker_id: signing_worker_id.into(),
            request_id: request_id.into(),
            client_presignature_id: client_presignature_id.into(),
            scope_digest,
            request_digest,
            signing_digest,
            trusted_source_digest,
            expires_at_ms,
        };
        admission.validate()?;
        Ok(admission)
    }

    /// Builds a Router A/B ECDSA derivation prepare admission candidate from a verified Wallet Session.
    pub fn from_prepare_request(
        wallet_session: &CloudflareRouterVerifiedWalletSessionV1,
        request: &RouterAbEcdsaDerivationEvmDigestSigningRequestV1,
        now_unix_ms: u64,
    ) -> RouterAbProtocolResult<Self> {
        wallet_session.validate_for_router_ab_ecdsa_derivation_evm_digest_signing_request_v1(
            request,
            now_unix_ms,
        )?;
        let authorization = match &request.authorization {
            NormalSigningAuthorizationV1::ReusableWalletSession { .. } => {
                CloudflareRouterNormalSigningAuthorizationV2::reusable_wallet_session(
                    wallet_session.authorization_id.clone(),
                    wallet_session.wallet_session_id.clone(),
                )?
            }
            NormalSigningAuthorizationV1::OperationStepUp => {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidGateDecision,
                    "Wallet Session bearer cannot authorize operation-step-up signing",
                ));
            }
        };
        let admission = Self::new(
            wallet_session.org_id.clone(),
            wallet_session.project_id.clone(),
            wallet_session.environment.clone(),
            wallet_session.account_id.clone(),
            wallet_session.subject_id.clone(),
            authorization,
            wallet_session.signing_worker_id.clone(),
            request.request_id.clone(),
            request.client_presignature_id.clone(),
            request.scope.scope_digest()?,
            request.request_digest()?,
            request.signing_digest()?,
            wallet_session.trusted_source_digest,
            request.expires_at_ms,
        )?;
        admission.validate_for_prepare_request(request)?;
        Ok(admission)
    }

    /// Validates internal Router A/B ECDSA derivation admission fields independent of a request body.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("Router A/B ECDSA derivation prepare org_id", &self.org_id)?;
        require_non_empty(
            "Router A/B ECDSA derivation prepare project_id",
            &self.project_id,
        )?;
        require_non_empty(
            "Router A/B ECDSA derivation prepare environment",
            &self.environment,
        )?;
        require_non_empty(
            "Router A/B ECDSA derivation prepare account_id",
            &self.account_id,
        )?;
        require_non_empty(
            "Router A/B ECDSA derivation prepare subject_id",
            &self.subject_id,
        )?;
        self.authorization.validate()?;
        require_non_empty(
            "Router A/B ECDSA derivation prepare signing_worker_id",
            &self.signing_worker_id,
        )?;
        require_non_empty(
            "Router A/B ECDSA derivation prepare request_id",
            &self.request_id,
        )?;
        require_non_empty(
            "Router A/B ECDSA derivation prepare client_presignature_id",
            &self.client_presignature_id,
        )?;
        require_positive_ms(
            "Router A/B ECDSA derivation prepare expires_at_ms",
            self.expires_at_ms,
        )
    }

    /// Validates a Router A/B ECDSA derivation prepare admission candidate against a typed request.
    pub fn validate_for_prepare_request(
        &self,
        request: &RouterAbEcdsaDerivationEvmDigestSigningRequestV1,
    ) -> RouterAbProtocolResult<()> {
        self.validate()?;
        request.validate()?;
        if self.account_id != request.scope.wallet_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "Router A/B ECDSA derivation prepare admission account_id does not match request scope",
            ));
        }
        self.authorization
            .validate_for_scope(&request.authorization)
            .map_err(|_| {
                RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidGateDecision,
                    "Router A/B ECDSA derivation prepare admission authorization does not match request scope",
                )
            })?;
        if self.signing_worker_id != request.scope.signing_worker.server_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "Router A/B ECDSA derivation prepare admission signing_worker_id does not match request scope",
            ));
        }
        if self.request_id != request.request_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "Router A/B ECDSA derivation prepare admission request_id does not match request",
            ));
        }
        if self.client_presignature_id != request.client_presignature_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "Router A/B ECDSA derivation prepare admission presignature id does not match request",
            ));
        }
        if self.expires_at_ms != request.expires_at_ms {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "Router A/B ECDSA derivation prepare admission expires_at_ms does not match request",
            ));
        }
        if self.scope_digest != request.scope.scope_digest()? {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "Router A/B ECDSA derivation prepare admission scope digest does not match request",
            ));
        }
        if self.request_digest != request.request_digest()? {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "Router A/B ECDSA derivation prepare admission request digest does not match request",
            ));
        }
        if self.signing_digest != request.signing_digest()? {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "Router A/B ECDSA derivation prepare admission signing digest does not match request",
            ));
        }
        Ok(())
    }

    /// Converts the candidate to the shared normal-signing trusted metadata shape.
    pub fn to_normal_signing_trusted_metadata(
        &self,
    ) -> RouterAbProtocolResult<CloudflareRouterNormalSigningTrustedMetadataV1> {
        self.validate()?;
        CloudflareRouterNormalSigningTrustedMetadataV1::new(
            self.org_id.clone(),
            self.project_id.clone(),
            self.environment.clone(),
            self.account_id.clone(),
            self.authorization
                .to_auth_context(self.subject_id.clone())?,
            self.trusted_source_digest,
            self.request_digest,
        )
    }
}

/// Pre-gate Router admission candidate for Router A/B ECDSA derivation EVM digest finalize.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareRouterAbEcdsaDerivationEvmDigestFinalizeAdmissionCandidateV1 {
    /// Canonical organization id.
    pub org_id: String,
    /// Canonical project id.
    pub project_id: String,
    /// Deployment environment label.
    pub environment: String,
    /// Wallet id authorized by the Wallet Session.
    pub account_id: String,
    /// Canonical subject id from verified wallet auth.
    pub subject_id: String,
    /// Exact Router-verified authorization branch.
    pub authorization: CloudflareRouterNormalSigningAuthorizationV2,
    /// Active SigningWorker id authorized for this request.
    pub signing_worker_id: String,
    /// Router request id from the typed Router A/B ECDSA derivation finalize request.
    pub request_id: String,
    /// Digest of the active Router A/B ECDSA derivation normal-signing scope.
    pub scope_digest: PublicDigest32,
    /// Canonical prepare request digest that the presignature must match.
    pub prepare_request_digest: PublicDigest32,
    /// Canonical finalize request digest admitted by the Router.
    pub finalize_request_digest: PublicDigest32,
    /// Exact 32-byte EVM digest admitted for SigningWorker finalize.
    pub signing_digest: PublicDigest32,
    /// SigningWorker-local presignature id consumed by finalize.
    pub server_presignature_id: String,
    /// Digest of trusted source metadata, such as edge client address.
    pub trusted_source_digest: PublicDigest32,
    /// Request expiry in Unix milliseconds.
    pub expires_at_ms: u64,
}

impl CloudflareRouterAbEcdsaDerivationEvmDigestFinalizeAdmissionCandidateV1 {
    /// Creates validated internal Router A/B ECDSA derivation finalize admission candidate data.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        org_id: impl Into<String>,
        project_id: impl Into<String>,
        environment: impl Into<String>,
        account_id: impl Into<String>,
        subject_id: impl Into<String>,
        authorization: CloudflareRouterNormalSigningAuthorizationV2,
        signing_worker_id: impl Into<String>,
        request_id: impl Into<String>,
        scope_digest: PublicDigest32,
        prepare_request_digest: PublicDigest32,
        finalize_request_digest: PublicDigest32,
        signing_digest: PublicDigest32,
        server_presignature_id: impl Into<String>,
        trusted_source_digest: PublicDigest32,
        expires_at_ms: u64,
    ) -> RouterAbProtocolResult<Self> {
        let admission = Self {
            org_id: org_id.into(),
            project_id: project_id.into(),
            environment: environment.into(),
            account_id: account_id.into(),
            subject_id: subject_id.into(),
            authorization,
            signing_worker_id: signing_worker_id.into(),
            request_id: request_id.into(),
            scope_digest,
            prepare_request_digest,
            finalize_request_digest,
            signing_digest,
            server_presignature_id: server_presignature_id.into(),
            trusted_source_digest,
            expires_at_ms,
        };
        admission.validate()?;
        Ok(admission)
    }

    /// Builds a Router A/B ECDSA derivation finalize admission candidate from a verified Wallet Session.
    pub fn from_finalize_request(
        wallet_session: &CloudflareRouterVerifiedWalletSessionV1,
        request: &RouterAbEcdsaDerivationEvmDigestSigningFinalizeRequestV1,
        now_unix_ms: u64,
    ) -> RouterAbProtocolResult<Self> {
        wallet_session.validate_for_router_ab_ecdsa_derivation_evm_digest_finalize_request_v1(
            request,
            now_unix_ms,
        )?;
        let authorization = match &request.authorization {
            NormalSigningAuthorizationV1::ReusableWalletSession { .. } => {
                CloudflareRouterNormalSigningAuthorizationV2::reusable_wallet_session(
                    wallet_session.authorization_id.clone(),
                    wallet_session.wallet_session_id.clone(),
                )?
            }
            NormalSigningAuthorizationV1::OperationStepUp => {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidGateDecision,
                    "Wallet Session bearer cannot authorize operation-step-up signing",
                ));
            }
        };
        let admission = Self::new(
            wallet_session.org_id.clone(),
            wallet_session.project_id.clone(),
            wallet_session.environment.clone(),
            wallet_session.account_id.clone(),
            wallet_session.subject_id.clone(),
            authorization,
            wallet_session.signing_worker_id.clone(),
            request.request_id.clone(),
            request.scope.scope_digest()?,
            request.prepare_request_digest()?,
            request.request_digest()?,
            request.signing_digest()?,
            request.server_presignature_id.clone(),
            wallet_session.trusted_source_digest,
            request.expires_at_ms,
        )?;
        admission.validate_for_finalize_request(request)?;
        Ok(admission)
    }

    /// Validates internal Router A/B ECDSA derivation finalize admission fields independent of a request body.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("Router A/B ECDSA derivation finalize org_id", &self.org_id)?;
        require_non_empty(
            "Router A/B ECDSA derivation finalize project_id",
            &self.project_id,
        )?;
        require_non_empty(
            "Router A/B ECDSA derivation finalize environment",
            &self.environment,
        )?;
        require_non_empty(
            "Router A/B ECDSA derivation finalize account_id",
            &self.account_id,
        )?;
        require_non_empty(
            "Router A/B ECDSA derivation finalize subject_id",
            &self.subject_id,
        )?;
        self.authorization.validate()?;
        require_non_empty(
            "Router A/B ECDSA derivation finalize signing_worker_id",
            &self.signing_worker_id,
        )?;
        require_non_empty(
            "Router A/B ECDSA derivation finalize request_id",
            &self.request_id,
        )?;
        require_non_empty(
            "Router A/B ECDSA derivation finalize server_presignature_id",
            &self.server_presignature_id,
        )?;
        require_positive_ms(
            "Router A/B ECDSA derivation finalize expires_at_ms",
            self.expires_at_ms,
        )
    }

    /// Validates a Router A/B ECDSA derivation finalize admission candidate against a typed request.
    pub fn validate_for_finalize_request(
        &self,
        request: &RouterAbEcdsaDerivationEvmDigestSigningFinalizeRequestV1,
    ) -> RouterAbProtocolResult<()> {
        self.validate()?;
        request.validate()?;
        if self.account_id != request.scope.wallet_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "Router A/B ECDSA derivation finalize admission account_id does not match request scope",
            ));
        }
        self.authorization
            .validate_for_scope(&request.authorization)
            .map_err(|_| {
                RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidGateDecision,
                    "Router A/B ECDSA derivation finalize admission authorization does not match request scope",
                )
            })?;
        if self.signing_worker_id != request.scope.signing_worker.server_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "Router A/B ECDSA derivation finalize admission signing_worker_id does not match request scope",
            ));
        }
        if self.request_id != request.request_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "Router A/B ECDSA derivation finalize admission request_id does not match request",
            ));
        }
        if self.expires_at_ms != request.expires_at_ms {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "Router A/B ECDSA derivation finalize admission expires_at_ms does not match request",
            ));
        }
        if self.scope_digest != request.scope.scope_digest()? {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "Router A/B ECDSA derivation finalize admission scope digest does not match request",
            ));
        }
        if self.prepare_request_digest != request.prepare_request_digest()? {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "Router A/B ECDSA derivation finalize admission prepare digest does not match request",
            ));
        }
        if self.finalize_request_digest != request.request_digest()? {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "Router A/B ECDSA derivation finalize admission request digest does not match request",
            ));
        }
        if self.signing_digest != request.signing_digest()? {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "Router A/B ECDSA derivation finalize admission signing digest does not match request",
            ));
        }
        if self.server_presignature_id != request.server_presignature_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "Router A/B ECDSA derivation finalize admission presignature id does not match request",
            ));
        }
        Ok(())
    }

    /// Converts the candidate to the shared normal-signing trusted metadata shape.
    pub fn to_normal_signing_trusted_metadata(
        &self,
    ) -> RouterAbProtocolResult<CloudflareRouterNormalSigningTrustedMetadataV1> {
        self.validate()?;
        CloudflareRouterNormalSigningTrustedMetadataV1::new(
            self.org_id.clone(),
            self.project_id.clone(),
            self.environment.clone(),
            self.account_id.clone(),
            self.authorization
                .to_auth_context(self.subject_id.clone())?,
            self.trusted_source_digest,
            self.finalize_request_digest,
        )
    }
}

/// Gate-aware Router work plan after public request normalization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "admission", rename_all = "snake_case")]
pub enum CloudflareRouterPublicAdmissionPlanV1 {
    /// Gate accepted or selected an existing lifecycle, so signer forwarding is allowed.
    Forward {
        /// Trusted Router-owned gate data.
        trusted_admission: CloudflareRouterTrustedAdmissionV1,
        /// Canonical Router-to-Signer A wire message.
        deriver_a_message: WireMessageV1,
        /// Canonical Router-to-Signer B wire message.
        deriver_b_message: WireMessageV1,
    },
    /// Gate deferred or rejected the request before signer forwarding.
    Stop {
        /// Trusted Router-owned gate data.
        trusted_admission: CloudflareRouterTrustedAdmissionV1,
    },
}

impl CloudflareRouterPublicAdmissionPlanV1 {
    /// Validates admission branch consistency.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.trusted_admission().validate()?;
        match self {
            Self::Forward {
                deriver_a_message,
                deriver_b_message,
                trusted_admission,
                ..
            } => {
                if !trusted_admission.allows_signer_forwarding()? {
                    return Err(RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::InvalidGateDecision,
                        "public Router admission plan forward branch requires accepted gate decision",
                    ));
                }
                if deriver_a_message.kind != WireMessageKindV1::RouterToSignerA {
                    return Err(RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                        "public Router admission plan Signer A message has wrong branch",
                    ));
                }
                if deriver_b_message.kind != WireMessageKindV1::RouterToSignerB {
                    return Err(RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                        "public Router admission plan Signer B message has wrong branch",
                    ));
                }
                if deriver_a_message.transcript_digest != deriver_b_message.transcript_digest {
                    return Err(RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                        "public Router admission plan signer messages must share transcript digest",
                    ));
                }
                Ok(())
            }
            Self::Stop {
                trusted_admission, ..
            } => {
                if trusted_admission.allows_signer_forwarding()? {
                    return Err(RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::InvalidGateDecision,
                        "public Router admission plan stop branch requires defer or reject gate decision",
                    ));
                }
                Ok(())
            }
        }
    }

    /// Returns trusted admission data.
    pub fn trusted_admission(&self) -> &CloudflareRouterTrustedAdmissionV1 {
        match self {
            Self::Forward {
                trusted_admission, ..
            }
            | Self::Stop {
                trusted_admission, ..
            } => trusted_admission,
        }
    }
}
