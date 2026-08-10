use crate::*;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

use router_ab_ecdsa_online::{
    combine_rerandomization_contributions, finalize_signing_worker_signature, OnlineError,
    SigningWorkerOnlineInput, SigningWorkerPresignMaterial,
};
use signer_core::error::{SignerCoreError, SignerCoreErrorCode};
use signer_core::near_threshold_ed25519::{
    aggregate_signature, build_signing_package, key_package_from_signing_share_bytes,
    signature_share_from_b64u, verifying_share_bytes_from_signing_share_bytes,
    verifying_share_from_b64u,
};

#[cfg(feature = "workers-rs")]
mod private_d1;
#[cfg(feature = "workers-rs")]
pub use private_d1::*;
mod ecdsa_lane;
pub use ecdsa_lane::*;
mod lane_private_d1;
pub use lane_private_d1::*;

/// Platform-neutral signer logic behind the Cloudflare transport wrapper.
pub trait CloudflareSignerWireHandlerV1 {
    /// Handles one validated Router-to-signer wire message.
    fn handle_signer_wire_message(
        &self,
        message: WireMessageV1,
    ) -> RouterAbProtocolResult<WireMessageV1>;
}

/// Strict proof-bundle signer logic behind the Cloudflare transport wrapper.
pub trait CloudflareSignerRecipientProofBundleWireHandlerV1 {
    /// Handles one validated Router-to-signer message and returns strict proof-bundle delivery.
    fn handle_signer_recipient_proof_bundle_wire_message(
        &self,
        message: WireMessageV1,
    ) -> RouterAbProtocolResult<CloudflareSignerRecipientProofBundleResponseV1>;
}

/// SigningWorker v2 prepare logic behind the Cloudflare transport wrapper.
pub trait CloudflareSigningWorkerNormalSigningPrepareHandlerV2 {
    /// Handles one Router-admitted v2 prepare request.
    fn handle_normal_signing_prepare_request_v2(
        &self,
        request: CloudflareSigningWorkerMaterializedNormalSigningPrepareRequestV2,
    ) -> RouterAbProtocolResult<CloudflareSigningWorkerNormalSigningRound1PreparedV1>;
}

/// SigningWorker v2 finalize logic behind the Cloudflare transport wrapper.
pub trait CloudflareSigningWorkerNormalSigningFinalizeHandlerV2 {
    /// Handles one Router-admitted v2 finalize request.
    fn handle_normal_signing_finalize_request_v2(
        &self,
        request: CloudflareSigningWorkerMaterializedNormalSigningFinalizeRequestV2,
    ) -> RouterAbProtocolResult<NormalSigningResponseV1>;
}

/// SigningWorker Router A/B ECDSA derivation finalize logic behind the Cloudflare transport wrapper.
pub trait CloudflareSigningWorkerRouterAbEcdsaDerivationEvmDigestFinalizeHandlerV1 {
    /// Handles one materialized Router A/B ECDSA derivation finalize request.
    fn handle_router_ab_ecdsa_derivation_evm_digest_finalize_request_v1(
        &self,
        request: CloudflareSigningWorkerMaterializedRouterAbEcdsaDerivationEvmDigestFinalizeRequestV1,
    ) -> RouterAbProtocolResult<RouterAbEcdsaDerivationEvmDigestSigningResponseV1>;
}

fn cloudflare_signing_worker_digest_hex_v1(digest: PublicDigest32) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(64);
    for byte in digest.as_bytes() {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

/// Client-requested phase for one SigningWorker-owned ECDSA presign session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CloudflareSigningWorkerEcdsaPresignRequestedStageV1 {
    Triples,
    Presign,
}

/// Private request to create a SigningWorker-owned ECDSA presign session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareSigningWorkerEcdsaPresignSessionInitRequestV1 {
    pub scope: RouterAbEcdsaDerivationNormalSigningScopeV1,
    pub presign_session_id: String,
    pub expires_at_ms: u64,
}

impl CloudflareSigningWorkerEcdsaPresignSessionInitRequestV1 {
    pub fn validate_at(&self, now_unix_ms: u64) -> RouterAbProtocolResult<()> {
        self.scope.validate()?;
        require_non_empty("presign_session_id", &self.presign_session_id)?;
        require_positive_ms("ECDSA presign session expires_at_ms", self.expires_at_ms)?;
        require_positive_ms("ECDSA presign session now_unix_ms", now_unix_ms)?;
        if self.expires_at_ms <= now_unix_ms {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ExpiredLocalRequest,
                "ECDSA presign session request expired",
            ));
        }
        Ok(())
    }
}

/// Private request to advance a SigningWorker-owned ECDSA presign session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareSigningWorkerEcdsaPresignSessionStepRequestV1 {
    pub scope: RouterAbEcdsaDerivationNormalSigningScopeV1,
    pub presign_session_id: String,
    pub requested_stage: CloudflareSigningWorkerEcdsaPresignRequestedStageV1,
    pub outgoing_messages_b64u: Vec<String>,
    pub expires_at_ms: u64,
}

impl CloudflareSigningWorkerEcdsaPresignSessionStepRequestV1 {
    pub fn validate_at(&self, now_unix_ms: u64) -> RouterAbProtocolResult<()> {
        self.scope.validate()?;
        require_non_empty("presign_session_id", &self.presign_session_id)?;
        require_positive_ms("ECDSA presign session expires_at_ms", self.expires_at_ms)?;
        require_positive_ms("ECDSA presign session now_unix_ms", now_unix_ms)?;
        if self.expires_at_ms <= now_unix_ms {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ExpiredLocalRequest,
                "ECDSA presign session request expired",
            ));
        }
        for message in &self.outgoing_messages_b64u {
            let decoded = decode_base64url_bytes_v1("ECDSA presign message", message)?;
            require_non_empty_vec("ECDSA presign message", &decoded)?;
        }
        Ok(())
    }
}

/// Public progress returned by the SigningWorker-owned ECDSA presign session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CloudflareSigningWorkerEcdsaPresignSessionProgressV1 {
    Continue {
        presign_session_id: String,
        stage: String,
        event: String,
        outgoing_messages_b64u: Vec<String>,
    },
    Complete {
        presign_session_id: String,
        server_presignature_id: String,
        server_big_r33_b64u: String,
    },
}

/// Private SigningWorker request to fill the Router A/B ECDSA derivation presignature pool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareSigningWorkerRouterAbEcdsaDerivationPresignaturePoolPutRequestV1 {
    /// Normal-signing identity and active SigningWorker scope.
    pub scope: RouterAbEcdsaDerivationNormalSigningScopeV1,
    /// Client-selected presignature id shared by the client and SigningWorker.
    pub server_presignature_id: String,
    /// Compressed secp256k1 presignature R point encoded as unpadded base64url.
    pub server_big_r33_b64u: String,
    /// SigningWorker-local ECDSA presignature k share encoded as unpadded base64url.
    pub server_k_share32_b64u: String,
    /// SigningWorker-local ECDSA presignature sigma share encoded as unpadded base64url.
    pub server_sigma_share32_b64u: String,
    /// Expiry timestamp in Unix milliseconds.
    pub expires_at_ms: u64,
}

impl CloudflareSigningWorkerRouterAbEcdsaDerivationPresignaturePoolPutRequestV1 {
    /// Creates a validated Router A/B ECDSA derivation presignature pool-fill request.
    pub fn new(
        scope: RouterAbEcdsaDerivationNormalSigningScopeV1,
        server_presignature_id: impl Into<String>,
        server_big_r33_b64u: impl Into<String>,
        server_k_share32_b64u: impl Into<String>,
        server_sigma_share32_b64u: impl Into<String>,
        expires_at_ms: u64,
    ) -> RouterAbProtocolResult<Self> {
        let request = Self {
            scope,
            server_presignature_id: server_presignature_id.into(),
            server_big_r33_b64u: server_big_r33_b64u.into(),
            server_k_share32_b64u: server_k_share32_b64u.into(),
            server_sigma_share32_b64u: server_sigma_share32_b64u.into(),
            expires_at_ms,
        };
        request.validate()?;
        Ok(request)
    }

    /// Validates request fields without applying wall-clock expiry.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.scope.validate()?;
        require_non_empty("server_presignature_id", &self.server_presignature_id)?;
        decode_base64url_fixed_33_v1("server_big_r33_b64u", &self.server_big_r33_b64u)?;
        decode_base64url_fixed_32_v1("server_k_share32_b64u", &self.server_k_share32_b64u)?;
        decode_base64url_fixed_32_v1("server_sigma_share32_b64u", &self.server_sigma_share32_b64u)?;
        require_positive_ms(
            "Router A/B ECDSA derivation presignature pool fill expires_at_ms",
            self.expires_at_ms,
        )
    }

    /// Validates this pool-fill request can be accepted at the supplied timestamp.
    pub fn validate_at(&self, now_unix_ms: u64) -> RouterAbProtocolResult<()> {
        self.validate()?;
        require_positive_ms(
            "Router A/B ECDSA derivation presignature pool fill now_unix_ms",
            now_unix_ms,
        )?;
        if self.expires_at_ms <= now_unix_ms {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ExpiredLocalRequest,
                "Router A/B ECDSA derivation presignature pool fill request expired",
            ));
        }
        Ok(())
    }

    /// Builds the unbound pool record for the resolved active SigningWorker.
    pub fn to_pool_record(
        &self,
        active_signing_worker: ActiveSigningWorkerStateV1,
        active_material: &CloudflareServerOutputMaterialRecordV1,
        now_unix_ms: u64,
    ) -> RouterAbProtocolResult<CloudflareSigningWorkerEcdsaPresignaturePoolRecordV1> {
        self.validate_at(now_unix_ms)?;
        let lookup =
            CloudflareActiveSigningWorkerStateLookupV1::from_router_ab_ecdsa_derivation_normal_signing_scope(
                &self.scope,
            )?;
        lookup.validate_active_state(&active_signing_worker)?;
        validate_cloudflare_router_ab_ecdsa_derivation_normal_signing_active_material_v1(
            &self.scope,
            &active_signing_worker,
            active_material,
        )?;
        CloudflareSigningWorkerEcdsaPresignaturePoolRecordV1::new(
            self.scope.clone(),
            active_signing_worker,
            self.server_presignature_id.clone(),
            self.server_big_r33_b64u.clone(),
            self.server_k_share32_b64u.clone(),
            self.server_sigma_share32_b64u.clone(),
            now_unix_ms,
            self.expires_at_ms,
        )
    }
}

/// Router-admitted v2 prepare request sent to SigningWorker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSigningWorkerAdmittedNormalSigningPrepareRequestV2 {
    /// Normal signing identity and active SigningWorker scope.
    pub scope: NormalSigningScopeV1,
    /// Request expiry in Unix milliseconds.
    pub expires_at_ms: u64,
    /// Router-derived v2 normal-signing prepare admission candidate.
    pub admission_candidate: CloudflareRouterNormalSigningPrepareAdmissionCandidateV2,
    /// Accepted Router store admission decision for this request.
    pub trusted_admission: CloudflareRouterNormalSigningTrustedAdmissionV1,
}

impl CloudflareSigningWorkerAdmittedNormalSigningPrepareRequestV2 {
    /// Creates a validated admitted v2 prepare service request.
    pub fn new(
        scope: NormalSigningScopeV1,
        expires_at_ms: u64,
        admission_candidate: CloudflareRouterNormalSigningPrepareAdmissionCandidateV2,
        trusted_admission: CloudflareRouterNormalSigningTrustedAdmissionV1,
    ) -> RouterAbProtocolResult<Self> {
        let request = Self {
            scope,
            expires_at_ms,
            admission_candidate,
            trusted_admission,
        };
        request.validate()?;
        Ok(request)
    }

    /// Validates Router admission accepted this exact v2 prepare request.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.scope.validate()?;
        require_positive_ms(
            "normal-signing v2 prepare expires_at_ms",
            self.expires_at_ms,
        )?;
        self.admission_candidate.validate()?;
        self.trusted_admission.validate()?;
        if self.admission_candidate.account_id != self.scope.account_id
            || self.admission_candidate.signing_worker_id != self.scope.signing_worker_id
            || self.admission_candidate.request_id != self.scope.request_id
            || self.admission_candidate.expires_at_ms != self.expires_at_ms
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "normal-signing v2 prepare admission does not match request scope",
            ));
        }
        self.admission_candidate
            .authorization
            .validate_for_scope(&self.scope.authorization)?;
        if self.admission_candidate.round1_binding_digest.is_none() {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "normal-signing v2 prepare admission requires round1 binding digest",
            ));
        }
        if self.trusted_admission.metadata != self.admission_candidate.to_v1_trusted_metadata()? {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "normal-signing v2 trusted admission metadata does not match internal admission",
            ));
        }
        if self.trusted_admission.allows_signing_worker_forwarding()? {
            return Ok(());
        }
        Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidGateDecision,
            "SigningWorker normal-signing v2 prepare requires accepted Router admission",
        ))
    }

    pub(crate) fn round1_binding_digest(&self) -> RouterAbProtocolResult<PublicDigest32> {
        self.admission_candidate
            .round1_binding_digest
            .ok_or_else(|| {
                RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidGateDecision,
                    "normal-signing v2 prepare admission requires round1 binding digest",
                )
            })
    }
}

/// Router-admitted v2 finalize request sent to SigningWorker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSigningWorkerAdmittedNormalSigningFinalizeRequestV2 {
    /// Typed public finalize request accepted by the Router.
    pub request: RouterAbEd25519NormalSigningFinalizeRequestV2,
    /// Router-derived finalize admission, including the exact authorization branch.
    pub admission_candidate: CloudflareRouterNormalSigningFinalizeAdmissionCandidateV2,
    /// Accepted Router store admission decision for this request.
    pub trusted_admission: CloudflareRouterNormalSigningTrustedAdmissionV1,
    /// Exact accepted operation identity reconstructed by the Router boundary.
    pub authorized_operation_identity: CloudflareSigningWorkerAuthorizedOperationIdentityV1,
    /// Exact claim that the SigningWorker must commit before evaluating crypto.
    pub effect_claim: CloudflareSigningWorkerNormalSigningEffectClaimV1,
}

/// Authorization-specific effect claim committed by SigningWorker private D1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CloudflareSigningWorkerNormalSigningEffectClaimV1 {
    /// Reusable Wallet Session authority carries the durable authorized operation.
    ReusableWalletSession {
        claim: CloudflareSigningWorkerReusableWalletSessionEffectClaimV1,
    },
    /// Operation step-up consumes only its one-operation authorization.
    OperationStepUp {
        authorization_session_id: String,
        authorized_operation_id: String,
        operation_id: String,
        operation_fingerprint_digest: String,
    },
}

/// Stable reusable Wallet Session authorized-operation effect forwarded to SigningWorker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareSigningWorkerReusableWalletSessionEffectClaimV1 {
    /// Exact durable Wallet Session authorization record used for this operation.
    pub authorization_id: String,
    pub wallet_session_id: String,
    pub authorized_operation_id: String,
    pub operation_id: String,
    pub operation_fingerprint_digest: String,
}

/// Exact accepted operation identity forwarded with a SigningWorker finalize effect.
///
/// The Router constructs this value from the already validated accepted-operation
/// wrapper. SigningWorker compares the effect claim against it before any D1 or
/// cryptographic effect, so operation identity cannot be substituted in transit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CloudflareSigningWorkerAuthorizedOperationIdentityV1 {
    ReusableWalletSession {
        authorization_id: String,
        wallet_session_id: String,
        authorized_operation_id: String,
        operation_id: String,
        operation_fingerprint_digest: String,
    },
    OperationStepUp {
        authorization_session_id: String,
        authorized_operation_id: String,
        operation_id: String,
        operation_fingerprint_digest: String,
    },
}

impl CloudflareSigningWorkerAuthorizedOperationIdentityV1 {
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        match self {
            Self::ReusableWalletSession {
                authorization_id,
                wallet_session_id,
                authorized_operation_id,
                operation_id,
                operation_fingerprint_digest,
            } => {
                require_non_empty("accepted operation authorization_id", authorization_id)?;
                require_non_empty("accepted operation wallet_session_id", wallet_session_id)?;
                if authorization_id == wallet_session_id {
                    return Err(RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::InvalidGateDecision,
                        "accepted operation authorization and Wallet Session ids must be pairwise distinct",
                    ));
                }
                require_non_empty(
                    "accepted operation authorized_operation_id",
                    authorized_operation_id,
                )?;
                require_non_empty("accepted operation operation_id", operation_id)?;
                require_non_empty(
                    "accepted operation operation_fingerprint_digest",
                    operation_fingerprint_digest,
                )
            }
            Self::OperationStepUp {
                authorization_session_id,
                authorized_operation_id,
                operation_id,
                operation_fingerprint_digest,
            } => {
                require_non_empty(
                    "accepted operation authorization_session_id",
                    authorization_session_id,
                )?;
                require_non_empty(
                    "accepted operation authorized_operation_id",
                    authorized_operation_id,
                )?;
                require_non_empty("accepted operation operation_id", operation_id)?;
                require_non_empty(
                    "accepted operation operation_fingerprint_digest",
                    operation_fingerprint_digest,
                )
            }
        }
    }
}

impl CloudflareSigningWorkerReusableWalletSessionEffectClaimV1 {
    pub fn new(
        authorization_id: impl Into<String>,
        wallet_session_id: impl Into<String>,
        authorized_operation_id: impl Into<String>,
        operation_id: impl Into<String>,
        operation_fingerprint_digest: impl Into<String>,
    ) -> RouterAbProtocolResult<Self> {
        let claim = Self {
            authorization_id: authorization_id.into(),
            wallet_session_id: wallet_session_id.into(),
            authorized_operation_id: authorized_operation_id.into(),
            operation_id: operation_id.into(),
            operation_fingerprint_digest: operation_fingerprint_digest.into(),
        };
        claim.validate()?;
        Ok(claim)
    }

    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty(
            "normal-signing effect claim authorization_id",
            &self.authorization_id,
        )?;
        require_non_empty(
            "normal-signing effect claim wallet_session_id",
            &self.wallet_session_id,
        )?;
        if self.authorization_id == self.wallet_session_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "normal-signing effect claim authorization and Wallet Session ids must be pairwise distinct",
            ));
        }
        require_non_empty(
            "normal-signing effect claim authorized_operation_id",
            &self.authorized_operation_id,
        )?;
        require_non_empty(
            "normal-signing effect claim operation_id",
            &self.operation_id,
        )?;
        require_non_empty(
            "normal-signing effect claim operation_fingerprint_digest",
            &self.operation_fingerprint_digest,
        )
    }
}

/// Durable terminal result for one claimed normal-signing effect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CloudflareSigningWorkerNormalSigningTerminalV1 {
    Success {
        response: NormalSigningResponseV1,
    },
    Failure {
        code: RouterAbProtocolErrorCode,
        message: String,
    },
}

impl CloudflareSigningWorkerNormalSigningTerminalV1 {
    pub fn from_result(result: RouterAbProtocolResult<NormalSigningResponseV1>) -> Self {
        match result {
            Ok(response) => Self::Success { response },
            Err(error) => Self::Failure {
                code: error.code(),
                message: error.message().to_owned(),
            },
        }
    }

    pub fn validate_for_request(
        &self,
        request: &CloudflareSigningWorkerAdmittedNormalSigningFinalizeRequestV2,
    ) -> RouterAbProtocolResult<()> {
        request.validate()?;
        match self {
            Self::Success { response } => {
                response.validate()?;
                if response.scope == request.request.scope
                    && response.signing_payload_digest == request.request.signing_payload_digest()
                    && response.signature_scheme == request.request.protocol.signature_scheme()
                {
                    return Ok(());
                }
                Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                    "SigningWorker terminal success does not match admitted request",
                ))
            }
            Self::Failure { message, .. } => {
                require_non_empty("SigningWorker terminal failure message", message)
            }
        }
    }

    pub fn into_result(self) -> RouterAbProtocolResult<NormalSigningResponseV1> {
        match self {
            Self::Success { response } => Ok(response),
            Self::Failure { code, message } => Err(RouterAbProtocolError::new(code, message)),
        }
    }
}

impl CloudflareSigningWorkerNormalSigningEffectClaimV1 {
    /// Validates every operation identity field against the accepted Router record.
    pub fn validate_for_authorized_operation_identity(
        &self,
        identity: &CloudflareSigningWorkerAuthorizedOperationIdentityV1,
    ) -> RouterAbProtocolResult<()> {
        identity.validate()?;
        let matches = match (self, identity) {
            (
                Self::ReusableWalletSession { claim },
                CloudflareSigningWorkerAuthorizedOperationIdentityV1::ReusableWalletSession {
                    authorization_id,
                    wallet_session_id,
                    authorized_operation_id,
                    operation_id,
                    operation_fingerprint_digest,
                },
            ) => {
                claim.validate()?;
                claim.authorization_id == *authorization_id
                    && claim.wallet_session_id == *wallet_session_id
                    && claim.authorized_operation_id == *authorized_operation_id
                    && claim.operation_id == *operation_id
                    && claim.operation_fingerprint_digest == *operation_fingerprint_digest
            }
            (
                Self::OperationStepUp {
                    authorization_session_id,
                    authorized_operation_id,
                    operation_id,
                    operation_fingerprint_digest,
                },
                CloudflareSigningWorkerAuthorizedOperationIdentityV1::OperationStepUp {
                    authorization_session_id: expected_session_id,
                    authorized_operation_id: expected_authorized_operation_id,
                    operation_id: expected_operation_id,
                    operation_fingerprint_digest: expected_fingerprint,
                },
            ) => {
                require_non_empty(
                    "normal-signing effect claim authorization_session_id",
                    authorization_session_id,
                )?;
                require_non_empty(
                    "normal-signing effect claim authorized_operation_id",
                    authorized_operation_id,
                )?;
                require_non_empty("normal-signing effect claim operation_id", operation_id)?;
                require_non_empty(
                    "normal-signing effect claim operation_fingerprint_digest",
                    operation_fingerprint_digest,
                )?;
                authorization_session_id == expected_session_id
                    && authorized_operation_id == expected_authorized_operation_id
                    && operation_id == expected_operation_id
                    && operation_fingerprint_digest == expected_fingerprint
            }
            _ => false,
        };
        if matches {
            Ok(())
        } else {
            Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "SigningWorker effect claim does not match accepted operation identity",
            ))
        }
    }

    /// Validates the claim against the exact Router-admitted authorization.
    pub fn validate_for_admission(
        &self,
        admission: &CloudflareRouterNormalSigningFinalizeAdmissionCandidateV2,
    ) -> RouterAbProtocolResult<()> {
        admission.validate()?;
        let matches = match (self, &admission.authorization) {
            (
                Self::ReusableWalletSession { claim },
                CloudflareRouterNormalSigningAuthorizationV2::ReusableWalletSession {
                    authorization_id,
                    wallet_session_id,
                },
            ) => {
                claim.validate()?;
                claim.authorization_id == *authorization_id
                    && claim.wallet_session_id == *wallet_session_id
            }
            (
                Self::OperationStepUp {
                    authorization_session_id,
                    authorized_operation_id,
                    operation_id,
                    operation_fingerprint_digest,
                },
                CloudflareRouterNormalSigningAuthorizationV2::OperationStepUp {
                    authorization_session_id: admitted_session_id,
                    ..
                },
            ) => {
                require_non_empty(
                    "normal-signing effect claim authorization_session_id",
                    authorization_session_id,
                )?;
                require_non_empty(
                    "normal-signing effect claim authorized_operation_id",
                    authorized_operation_id,
                )?;
                require_non_empty("normal-signing effect claim operation_id", operation_id)?;
                require_non_empty(
                    "normal-signing effect claim operation_fingerprint_digest",
                    operation_fingerprint_digest,
                )?;
                authorization_session_id == admitted_session_id
            }
            _ => false,
        };
        if matches {
            Ok(())
        } else {
            Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "normal-signing effect claim does not match Router admission",
            ))
        }
    }

    /// Validates the claim against the exact ECDSA authorization and operation digests.
    pub fn validate_for_ecdsa_finalize_request(
        &self,
        request: &RouterAbEcdsaDerivationEvmDigestSigningFinalizeRequestV1,
    ) -> RouterAbProtocolResult<()> {
        request.validate()?;
        let matches = match (self, &request.authorization) {
            (
                Self::ReusableWalletSession { claim },
                router_ab_core::NormalSigningAuthorizationV1::ReusableWalletSession {
                    wallet_session_id,
                },
            ) => {
                claim.validate()?;
                claim.wallet_session_id == *wallet_session_id
            }
            (
                Self::OperationStepUp {
                    authorization_session_id,
                    authorized_operation_id,
                    operation_id,
                    operation_fingerprint_digest,
                    ..
                },
                router_ab_core::NormalSigningAuthorizationV1::OperationStepUp,
            ) => {
                require_non_empty(
                    "ECDSA effect claim authorization_session_id",
                    authorization_session_id,
                )?;
                require_non_empty(
                    "ECDSA effect claim authorized_operation_id",
                    authorized_operation_id,
                )?;
                require_non_empty("ECDSA effect claim operation_id", operation_id)?;
                require_non_empty(
                    "ECDSA effect claim operation_fingerprint_digest",
                    operation_fingerprint_digest,
                )?;
                true
            }
            _ => false,
        };
        if !matches {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "ECDSA effect claim does not match Router authorization",
            ));
        }
        if request.operation_id != self.claim_operation_id() {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "ECDSA effect claim does not match finalize operation",
            ));
        }
        Ok(())
    }

    fn claim_operation_id(&self) -> &str {
        match self {
            Self::ReusableWalletSession { claim } => &claim.operation_id,
            Self::OperationStepUp { operation_id, .. } => operation_id,
        }
    }
}

impl CloudflareSigningWorkerAdmittedNormalSigningFinalizeRequestV2 {
    /// Creates a validated admitted v2 finalize service request.
    pub fn new(
        request: RouterAbEd25519NormalSigningFinalizeRequestV2,
        admission_candidate: CloudflareRouterNormalSigningFinalizeAdmissionCandidateV2,
        trusted_admission: CloudflareRouterNormalSigningTrustedAdmissionV1,
        authorized_operation_identity: CloudflareSigningWorkerAuthorizedOperationIdentityV1,
        effect_claim: CloudflareSigningWorkerNormalSigningEffectClaimV1,
    ) -> RouterAbProtocolResult<Self> {
        let request = Self {
            request,
            admission_candidate,
            trusted_admission,
            authorized_operation_identity,
            effect_claim,
        };
        request.validate()?;
        Ok(request)
    }

    /// Validates Router admission accepted this exact v2 finalize request.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.request.validate()?;
        self.admission_candidate
            .validate_for_finalize_request(&self.request)?;
        self.trusted_admission
            .validate_for_finalize_request_v2(&self.request)?;
        if self.trusted_admission.metadata != self.admission_candidate.to_v1_trusted_metadata()? {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "normal-signing finalize trusted admission does not match admission candidate",
            ));
        }
        self.effect_claim
            .validate_for_admission(&self.admission_candidate)?;
        self.effect_claim
            .validate_for_authorized_operation_identity(&self.authorized_operation_identity)?;
        if self.trusted_admission.allows_signing_worker_forwarding()? {
            return Ok(());
        }
        Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidGateDecision,
            "SigningWorker normal-signing v2 finalize requires accepted Router admission",
        ))
    }

    /// Stable effect key derived only from the admitted account and canonical intent.
    pub fn effect_operation_key(&self) -> RouterAbProtocolResult<String> {
        self.validate()?;
        Ok(format!(
            "near-ed25519/{}/{}/{}",
            self.request.scope.account_id,
            self.request.scope.material_activation.activation_id,
            cloudflare_signing_worker_digest_hex_v1(self.request.intent_digest())
        ))
    }

    /// Exact digest whose terminal response may be replayed for this operation key.
    pub fn effect_request_digest(&self) -> RouterAbProtocolResult<PublicDigest32> {
        self.validate()?;
        let mut hasher = Sha256::new();
        hasher.update(b"seams/signing-worker/near-effect/v1");
        hasher.update(serde_json::to_vec(self).map_err(|error| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                format!("normal-signing finalize serialization failed: {error}"),
            )
        })?);
        Ok(PublicDigest32::new(hasher.finalize().into()))
    }
}

/// SigningWorker v2 prepare request after active material lookup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSigningWorkerMaterializedNormalSigningPrepareRequestV2 {
    /// Router-admitted v2 prepare request.
    pub request: CloudflareSigningWorkerAdmittedNormalSigningPrepareRequestV2,
    /// Active SigningWorker state selected by the Router.
    pub active_signing_worker: ActiveSigningWorkerStateV1,
    /// Active SigningWorker material opened during activation.
    pub material: CloudflareServerOutputMaterialRecordV1,
    /// Prepare timestamp in Unix milliseconds.
    pub prepared_at_ms: u64,
}

impl CloudflareSigningWorkerMaterializedNormalSigningPrepareRequestV2 {
    /// Creates a validated materialized v2 prepare request.
    pub fn new(
        request: CloudflareSigningWorkerAdmittedNormalSigningPrepareRequestV2,
        active_signing_worker: ActiveSigningWorkerStateV1,
        material: CloudflareServerOutputMaterialRecordV1,
        prepared_at_ms: u64,
    ) -> RouterAbProtocolResult<Self> {
        let request = Self {
            request,
            active_signing_worker,
            material,
            prepared_at_ms,
        };
        request.validate()?;
        Ok(request)
    }

    /// Validates forwarded v2 prepare request and active material agree.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.request.validate()?;
        if self.prepared_at_ms >= self.request.expires_at_ms {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ExpiredLocalRequest,
                "normal-signing v2 prepare request expired",
            ));
        }
        self.active_signing_worker
            .validate_for_scope(&self.request.scope)?;
        self.material.validate()?;
        require_positive_ms("normal-signing v2 prepared_at_ms", self.prepared_at_ms)?;
        if self.material.transcript_digest
            == self.active_signing_worker.activation_transcript_digest
            && self.material.recipient_identity
                == self.active_signing_worker.signing_worker.server_id
        {
            return Ok(());
        }
        Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "SigningWorker v2 prepare material does not match active state",
        ))
    }
}

/// SigningWorker v2 finalize request after active material and round-1 lookup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSigningWorkerMaterializedNormalSigningFinalizeRequestV2 {
    /// Router-admitted v2 finalize request.
    pub request: CloudflareSigningWorkerAdmittedNormalSigningFinalizeRequestV2,
    /// Active SigningWorker state selected by the Router.
    pub active_signing_worker: ActiveSigningWorkerStateV1,
    /// Active SigningWorker material opened during activation.
    pub material: CloudflareServerOutputMaterialRecordV1,
    /// Exact persisted server round-1 nonce state for this finalize request.
    pub server_round1: CloudflareSigningWorkerRound1RecordV1,
    /// Signing timestamp in Unix milliseconds.
    pub signed_at_ms: u64,
}

impl CloudflareSigningWorkerMaterializedNormalSigningFinalizeRequestV2 {
    /// Creates a validated materialized v2 finalize request.
    pub fn new(
        request: CloudflareSigningWorkerAdmittedNormalSigningFinalizeRequestV2,
        active_signing_worker: ActiveSigningWorkerStateV1,
        material: CloudflareServerOutputMaterialRecordV1,
        server_round1: CloudflareSigningWorkerRound1RecordV1,
        signed_at_ms: u64,
    ) -> RouterAbProtocolResult<Self> {
        let request = Self {
            request,
            active_signing_worker,
            material,
            server_round1,
            signed_at_ms,
        };
        request.validate()?;
        Ok(request)
    }

    /// Validates forwarded v2 finalize request, active material, and round-1 state agree.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.request.validate()?;
        self.request.request.validate_at(self.signed_at_ms)?;
        self.active_signing_worker
            .validate_for_scope(&self.request.request.scope)?;
        self.material.validate()?;
        self.server_round1.validate()?;
        require_positive_ms("normal-signing v2 signed_at_ms", self.signed_at_ms)?;
        if self.material.transcript_digest
            != self.active_signing_worker.activation_transcript_digest
            || self.material.recipient_identity
                != self.active_signing_worker.signing_worker.server_id
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "SigningWorker v2 finalize material does not match active state",
            ));
        }
        if self.server_round1.active_signing_worker_state == self.active_signing_worker
            && self.server_round1.server_round1_handle
                == self.request.request.server_round1_handle()
            && self.server_round1.round1_binding_digest
                == self.request.request.round1_binding_digest()
            && self.server_round1.intent_digest == self.request.admission_candidate.intent_digest
            && self.server_round1.signing_payload_digest
                == self.request.admission_candidate.signing_payload_digest
            && self.server_round1.expires_at_ms == self.request.request.expires_at_ms
        {
            return Ok(());
        }
        Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "SigningWorker v2 round-1 record does not match materialized finalize request",
        ))
    }
}

/// Router-admitted Router A/B ECDSA derivation normal-signing request sent to SigningWorker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSigningWorkerAdmittedRouterAbEcdsaDerivationEvmDigestSigningRequestV1 {
    /// Typed public Router A/B ECDSA derivation normal-signing request accepted by the Router.
    pub request: RouterAbEcdsaDerivationEvmDigestSigningRequestV1,
    /// Accepted Router store admission decision for this request.
    pub trusted_admission: CloudflareRouterNormalSigningTrustedAdmissionV1,
}

impl CloudflareSigningWorkerAdmittedRouterAbEcdsaDerivationEvmDigestSigningRequestV1 {
    /// Creates a validated admitted Router A/B ECDSA derivation normal-signing service request.
    pub fn new(
        request: RouterAbEcdsaDerivationEvmDigestSigningRequestV1,
        trusted_admission: CloudflareRouterNormalSigningTrustedAdmissionV1,
    ) -> RouterAbProtocolResult<Self> {
        let request = Self {
            request,
            trusted_admission,
        };
        request.validate()?;
        Ok(request)
    }

    /// Validates Router-admitted Router A/B ECDSA derivation normal-signing material.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.request.validate()?;
        self.trusted_admission.validate()?;
        if self.trusted_admission.metadata.account_id != self.request.scope.wallet_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "Router A/B ECDSA derivation trusted admission account_id does not match request scope",
            ));
        }
        match (
            &self.trusted_admission.metadata.auth,
            &self.request.authorization,
        ) {
            (
                CloudflareRouterAuthContextV1::AuthenticatedSession { session_id, .. },
                NormalSigningAuthorizationV1::ReusableWalletSession { wallet_session_id },
            ) if session_id == wallet_session_id => {}
            (
                CloudflareRouterAuthContextV1::OperationStepUpSession { .. },
                NormalSigningAuthorizationV1::OperationStepUp,
            ) => {}
            _ => {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidGateDecision,
                    "Router A/B ECDSA derivation trusted authorization does not match request",
                ));
            }
        }
        if self.trusted_admission.metadata.intent_digest != self.request.request_digest()? {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "Router A/B ECDSA derivation trusted admission digest does not match request",
            ));
        }
        if self.trusted_admission.allows_signing_worker_forwarding()? {
            return Ok(());
        }
        Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidGateDecision,
            "SigningWorker Router A/B ECDSA derivation prepare requires accepted Router admission",
        ))
    }
}

/// Router-admitted Router A/B ECDSA derivation finalize request sent to SigningWorker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSigningWorkerAdmittedRouterAbEcdsaDerivationEvmDigestFinalizeRequestV1 {
    /// Typed public Router A/B ECDSA derivation finalize request accepted by the Router.
    pub request: RouterAbEcdsaDerivationEvmDigestSigningFinalizeRequestV1,
    /// Accepted Router store admission decision for this request.
    pub trusted_admission: CloudflareRouterNormalSigningTrustedAdmissionV1,
    /// Exact accepted operation identity reconstructed by the Router boundary.
    pub authorized_operation_identity: CloudflareSigningWorkerAuthorizedOperationIdentityV1,
    /// Exact Gateway authorization claim converted by Router into the worker effect claim.
    pub effect_claim: CloudflareSigningWorkerNormalSigningEffectClaimV1,
}

impl CloudflareSigningWorkerAdmittedRouterAbEcdsaDerivationEvmDigestFinalizeRequestV1 {
    /// Creates a validated admitted Router A/B ECDSA derivation finalize service request.
    pub fn new(
        request: RouterAbEcdsaDerivationEvmDigestSigningFinalizeRequestV1,
        trusted_admission: CloudflareRouterNormalSigningTrustedAdmissionV1,
        authorized_operation_identity: CloudflareSigningWorkerAuthorizedOperationIdentityV1,
        effect_claim: CloudflareSigningWorkerNormalSigningEffectClaimV1,
    ) -> RouterAbProtocolResult<Self> {
        let request = Self {
            request,
            trusted_admission,
            authorized_operation_identity,
            effect_claim,
        };
        request.validate()?;
        Ok(request)
    }

    /// Validates Router admission accepted this exact Router A/B ECDSA derivation finalize body.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.request.validate()?;
        self.trusted_admission.validate()?;
        if self.trusted_admission.metadata.account_id != self.request.scope.wallet_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "Router A/B ECDSA derivation finalize trusted admission account_id does not match request scope",
            ));
        }
        match (
            &self.trusted_admission.metadata.auth,
            &self.request.authorization,
        ) {
            (
                CloudflareRouterAuthContextV1::AuthenticatedSession { session_id, .. },
                NormalSigningAuthorizationV1::ReusableWalletSession { wallet_session_id },
            ) if session_id == wallet_session_id => {}
            (
                CloudflareRouterAuthContextV1::OperationStepUpSession { .. },
                NormalSigningAuthorizationV1::OperationStepUp,
            ) => {}
            _ => {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidGateDecision,
                    "Router A/B ECDSA derivation finalize trusted authorization does not match request",
                ));
            }
        }
        if self.trusted_admission.metadata.intent_digest != self.request.request_digest()? {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "Router A/B ECDSA derivation finalize trusted admission digest does not match request",
            ));
        }
        self.effect_claim
            .validate_for_ecdsa_finalize_request(&self.request)?;
        self.effect_claim
            .validate_for_authorized_operation_identity(&self.authorized_operation_identity)?;
        if self.trusted_admission.allows_signing_worker_forwarding()? {
            return Ok(());
        }
        Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidGateDecision,
            "SigningWorker Router A/B ECDSA derivation finalize requires accepted Router admission",
        ))
    }

    /// Stable effect key shared by retries of one exact ECDSA operation.
    pub fn effect_operation_key(&self) -> RouterAbProtocolResult<String> {
        self.validate()?;
        Ok(format!(
            "evm-ecdsa/{}/{}/{}",
            self.request.scope.wallet_id,
            self.request.material_activation.activation_id,
            self.request.operation_id,
        ))
    }

    /// Exact digest whose terminal response may be replayed for this effect key.
    pub fn effect_request_digest(&self) -> RouterAbProtocolResult<PublicDigest32> {
        self.validate()?;
        let mut hasher = Sha256::new();
        hasher.update(b"seams/signing-worker/evm-ecdsa-effect/v1");
        hasher.update(serde_json::to_vec(self).map_err(|error| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                format!("ECDSA finalize serialization failed: {error}"),
            )
        })?);
        Ok(PublicDigest32::new(hasher.finalize().into()))
    }
}

/// Router A/B ECDSA derivation normal-signing request after active SigningWorker material lookup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSigningWorkerMaterializedRouterAbEcdsaDerivationEvmDigestSigningRequestV1 {
    /// Router-admitted Router A/B ECDSA derivation request.
    pub request: CloudflareSigningWorkerAdmittedRouterAbEcdsaDerivationEvmDigestSigningRequestV1,
    /// Active SigningWorker state selected for this Router A/B ECDSA derivation identity.
    pub active_signing_worker: ActiveSigningWorkerStateV1,
    /// Active Router A/B ECDSA derivation material opened during activation.
    pub material: CloudflareServerOutputMaterialRecordV1,
    /// Materialization timestamp in Unix milliseconds.
    pub materialized_at_ms: u64,
}

impl CloudflareSigningWorkerMaterializedRouterAbEcdsaDerivationEvmDigestSigningRequestV1 {
    /// Creates a validated materialized Router A/B ECDSA derivation normal-signing request.
    pub fn new(
        request: CloudflareSigningWorkerAdmittedRouterAbEcdsaDerivationEvmDigestSigningRequestV1,
        active_signing_worker: ActiveSigningWorkerStateV1,
        material: CloudflareServerOutputMaterialRecordV1,
        materialized_at_ms: u64,
    ) -> RouterAbProtocolResult<Self> {
        let request = Self {
            request,
            active_signing_worker,
            material,
            materialized_at_ms,
        };
        request.validate()?;
        Ok(request)
    }

    /// Validates forwarded Router A/B ECDSA derivation request and active material agree.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.request.validate()?;
        self.request.request.validate_at(self.materialized_at_ms)?;
        require_positive_ms(
            "Router A/B ECDSA derivation normal-signing materialized_at_ms",
            self.materialized_at_ms,
        )?;
        validate_cloudflare_router_ab_ecdsa_derivation_normal_signing_active_material_v1(
            &self.request.request.scope,
            &self.active_signing_worker,
            &self.material,
        )
    }
}

/// Router A/B ECDSA derivation finalize request after active material and one-use presignature lookup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSigningWorkerMaterializedRouterAbEcdsaDerivationEvmDigestFinalizeRequestV1 {
    /// Router-admitted Router A/B ECDSA derivation finalize request.
    pub request: CloudflareSigningWorkerAdmittedRouterAbEcdsaDerivationEvmDigestFinalizeRequestV1,
    /// Active SigningWorker state selected for this Router A/B ECDSA derivation identity.
    pub active_signing_worker: ActiveSigningWorkerStateV1,
    /// Active Router A/B ECDSA derivation material opened during activation.
    pub material: CloudflareServerOutputMaterialRecordV1,
    /// Exact persisted one-use server presignature state for this finalize request.
    pub server_presignature: CloudflareSigningWorkerEcdsaPresignatureRecordV1,
    /// Signing timestamp in Unix milliseconds.
    pub signed_at_ms: u64,
}

impl CloudflareSigningWorkerMaterializedRouterAbEcdsaDerivationEvmDigestFinalizeRequestV1 {
    /// Creates a validated materialized Router A/B ECDSA derivation finalize request.
    pub fn new(
        request: CloudflareSigningWorkerAdmittedRouterAbEcdsaDerivationEvmDigestFinalizeRequestV1,
        active_signing_worker: ActiveSigningWorkerStateV1,
        material: CloudflareServerOutputMaterialRecordV1,
        server_presignature: CloudflareSigningWorkerEcdsaPresignatureRecordV1,
        signed_at_ms: u64,
    ) -> RouterAbProtocolResult<Self> {
        let request = Self {
            request,
            active_signing_worker,
            material,
            server_presignature,
            signed_at_ms,
        };
        request.validate()?;
        Ok(request)
    }

    /// Validates forwarded finalize request, active material, and presignature state agree.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.request.validate()?;
        self.request.request.validate_at(self.signed_at_ms)?;
        require_positive_ms(
            "Router A/B ECDSA derivation finalize signed_at_ms",
            self.signed_at_ms,
        )?;
        validate_cloudflare_router_ab_ecdsa_derivation_normal_signing_active_material_v1(
            &self.request.request.scope,
            &self.active_signing_worker,
            &self.material,
        )?;
        self.server_presignature.validate_for_request(
            &self.active_signing_worker,
            &self.request.request.server_presignature_id,
            self.request.request.prepare_request_digest()?,
            self.request.request.signing_digest()?,
            self.signed_at_ms,
        )
    }

    /// Returns the prepare request identity that the final signature response must bind.
    pub fn prepare_request(
        &self,
    ) -> RouterAbProtocolResult<RouterAbEcdsaDerivationEvmDigestSigningRequestV1> {
        self.validate()?;
        self.request.request.prepare_request()
    }
}

/// Materializes and handles one Router-admitted Router A/B ECDSA derivation finalize request.
pub fn handle_cloudflare_signing_worker_router_ab_ecdsa_derivation_evm_digest_finalize_private_request_v1<
    Handler,
>(
    handler: &Handler,
    now_unix_ms: u64,
    request: CloudflareSigningWorkerAdmittedRouterAbEcdsaDerivationEvmDigestFinalizeRequestV1,
    active_signing_worker: ActiveSigningWorkerStateV1,
    material: CloudflareServerOutputMaterialRecordV1,
    server_presignature: CloudflareSigningWorkerEcdsaPresignatureRecordV1,
) -> RouterAbProtocolResult<RouterAbEcdsaDerivationEvmDigestSigningResponseV1>
where
    Handler: CloudflareSigningWorkerRouterAbEcdsaDerivationEvmDigestFinalizeHandlerV1,
{
    let materialized =
        CloudflareSigningWorkerMaterializedRouterAbEcdsaDerivationEvmDigestFinalizeRequestV1::new(
            request,
            active_signing_worker,
            material,
            server_presignature,
            now_unix_ms,
        )?;
    let finalize_request = materialized.request.request.clone();
    let response =
        handler.handle_router_ab_ecdsa_derivation_evm_digest_finalize_request_v1(materialized)?;
    response.validate_for_request(&finalize_request)?;
    Ok(response)
}

/// SigningWorker-produced Router A/B ECDSA derivation presignature record plus public prepare response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSigningWorkerRouterAbEcdsaDerivationEvmDigestPreparedV1 {
    /// Public response returned to the client through Router.
    pub response: RouterAbEcdsaDerivationEvmDigestSigningPrepareResponseV1,
    /// Private presignature record persisted by SigningWorker-private D1.
    pub record: CloudflareSigningWorkerEcdsaPresignatureRecordV1,
}

impl CloudflareSigningWorkerRouterAbEcdsaDerivationEvmDigestPreparedV1 {
    /// Creates a validated Router A/B ECDSA derivation prepared bundle.
    pub fn new(
        response: RouterAbEcdsaDerivationEvmDigestSigningPrepareResponseV1,
        record: CloudflareSigningWorkerEcdsaPresignatureRecordV1,
        request: &CloudflareSigningWorkerMaterializedRouterAbEcdsaDerivationEvmDigestSigningRequestV1,
    ) -> RouterAbProtocolResult<Self> {
        let prepared = Self { response, record };
        prepared.validate_for_request(request)?;
        Ok(prepared)
    }

    /// Validates the public response and private record bind to a materialized request.
    pub fn validate_for_request(
        &self,
        request: &CloudflareSigningWorkerMaterializedRouterAbEcdsaDerivationEvmDigestSigningRequestV1,
    ) -> RouterAbProtocolResult<()> {
        request.validate()?;
        self.response
            .validate_for_request(&request.request.request)?;
        self.record.validate()?;
        let request_digest = request.request.request.request_digest()?;
        let signing_digest = request.request.request.signing_digest()?;
        if self.response.prepared_at_ms == request.materialized_at_ms
            && self.response.expires_at_ms == request.request.request.expires_at_ms
            && self.record.active_signing_worker_state == request.active_signing_worker
            && self.record.server_presignature_id == self.response.server_presignature_id
            && self.record.request_digest == request_digest
            && self.record.admitted_signing_digest == signing_digest
            && self.record.server_big_r33_b64u == self.response.server_big_r33_b64u
            && self
                .record
                .signing_worker_rerandomization_contribution32_b64u
                == self
                    .response
                    .signing_worker_rerandomization_contribution32_b64u
            && self.record.created_at_ms == request.materialized_at_ms
            && self.record.expires_at_ms == request.request.request.expires_at_ms
        {
            return Ok(());
        }
        Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "SigningWorker Router A/B ECDSA derivation prepared record does not match response",
        ))
    }
}

/// SigningWorker-produced round-1 record plus public prepare response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSigningWorkerNormalSigningRound1PreparedV1 {
    /// Public response returned to the client through Router.
    pub response: NormalSigningRound1PrepareResponseV1,
    /// Private nonce record persisted by SigningWorker-private D1.
    pub record: CloudflareSigningWorkerRound1RecordV1,
}

impl CloudflareSigningWorkerNormalSigningRound1PreparedV1 {
    /// Creates a validated prepared v2 round-1 bundle.
    pub fn new_v2(
        response: NormalSigningRound1PrepareResponseV1,
        record: CloudflareSigningWorkerRound1RecordV1,
        request: &CloudflareSigningWorkerMaterializedNormalSigningPrepareRequestV2,
    ) -> RouterAbProtocolResult<Self> {
        let prepared = Self { response, record };
        prepared.validate_for_v2_request(request)?;
        Ok(prepared)
    }

    /// Validates the public response and private record bind to a v2 materialized request.
    pub fn validate_for_v2_request(
        &self,
        request: &CloudflareSigningWorkerMaterializedNormalSigningPrepareRequestV2,
    ) -> RouterAbProtocolResult<()> {
        request.validate()?;
        self.response.validate()?;
        self.record.validate()?;
        let round1_binding_digest = request.request.round1_binding_digest()?;
        let expected_commitments = self.record.round1_state.commitments.clone();
        let expected_server_verifying_share = verifying_share_bytes_from_signing_share_bytes(
            request.material.output_material.as_bytes(),
        );
        if self.response.scope == request.request.scope
            && self.response.signing_payload_digest
                == request.request.admission_candidate.signing_payload_digest
            && self.response.round1_binding_digest == round1_binding_digest
            && self.response.signing_worker == request.active_signing_worker.signing_worker
            && self.response.expires_at_ms == request.request.expires_at_ms
            && self.record.active_signing_worker_state == request.active_signing_worker
            && self.record.server_round1_handle == self.response.server_round1_handle
            && self.record.round1_binding_digest == round1_binding_digest
            && self.record.intent_digest == request.request.admission_candidate.intent_digest
            && self.record.signing_payload_digest
                == request.request.admission_candidate.signing_payload_digest
            && self.record.admitted_signing_digest
                == request.request.admission_candidate.admitted_signing_digest
            && self.record.created_at_ms == request.prepared_at_ms
            && self.record.expires_at_ms == request.request.expires_at_ms
            && self.response.server_commitments == expected_commitments
            && self.response.server_verifying_share_b64u
                == encode_base64url_bytes_v1(&expected_server_verifying_share)
        {
            return Ok(());
        }
        Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "SigningWorker v2 round-1 prepared record does not match response",
        ))
    }
}

/// Production SigningWorker normal-signing handler for Yao-derived Ed25519 shares.
#[derive(Debug, Clone, Copy, Default)]
pub struct CloudflareEd25519YaoNormalSigningHandlerV1;

impl CloudflareSigningWorkerNormalSigningPrepareHandlerV2
    for CloudflareEd25519YaoNormalSigningHandlerV1
{
    fn handle_normal_signing_prepare_request_v2(
        &self,
        request: CloudflareSigningWorkerMaterializedNormalSigningPrepareRequestV2,
    ) -> RouterAbProtocolResult<CloudflareSigningWorkerNormalSigningRound1PreparedV1> {
        request.validate()?;
        let mut rng = CloudflareSignerProofGetrandomRngV1;
        let round1_state = prepare_cloudflare_ed25519_round1_v1(
            request.material.output_material.as_bytes(),
            &mut rng,
        )?;
        let mut handle_random = [0u8; 16];
        rand_core_06::RngCore::fill_bytes(&mut rng, &mut handle_random);
        let server_round1_handle = format!(
            "server-round1/{}/{}",
            request.request.scope.request_id,
            encode_base64url_bytes_v1(&handle_random)
        );
        let server_verifying_share = verifying_share_bytes_from_signing_share_bytes(
            request.material.output_material.as_bytes(),
        );
        let server_commitments = round1_state.commitments.clone();
        let round1_binding_digest = request.request.round1_binding_digest()?;
        let record = CloudflareSigningWorkerRound1RecordV1::new(
            request.active_signing_worker.clone(),
            server_round1_handle.clone(),
            round1_binding_digest,
            request.request.admission_candidate.intent_digest,
            request.request.admission_candidate.signing_payload_digest,
            request.request.admission_candidate.admitted_signing_digest,
            round1_state,
            request.prepared_at_ms,
            request.request.expires_at_ms,
        )?;
        let response = NormalSigningRound1PrepareResponseV1::new(
            request.request.scope.clone(),
            request.request.admission_candidate.signing_payload_digest,
            round1_binding_digest,
            request.active_signing_worker.signing_worker.clone(),
            server_round1_handle,
            server_commitments,
            encode_base64url_bytes_v1(&server_verifying_share),
            NormalSigningSignatureSchemeV1::Ed25519V1,
            request.prepared_at_ms,
            request.request.expires_at_ms,
        )?;
        CloudflareSigningWorkerNormalSigningRound1PreparedV1::new_v2(response, record, &request)
    }
}

impl CloudflareSigningWorkerNormalSigningFinalizeHandlerV2
    for CloudflareEd25519YaoNormalSigningHandlerV1
{
    fn handle_normal_signing_finalize_request_v2(
        &self,
        request: CloudflareSigningWorkerMaterializedNormalSigningFinalizeRequestV2,
    ) -> RouterAbProtocolResult<NormalSigningResponseV1> {
        request.validate()?;
        let finalize_request = &request.request.request;
        let RouterAbEd25519NormalSigningFinalizeProtocolV2::Ed25519TwoPartyFrostFinalizeV1(
            protocol,
        ) = &finalize_request.protocol;
        if protocol.server_commitments != request.server_round1.round1_state.commitments {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "normal-signing v2 server commitments do not match stored round-1 material",
            ));
        }
        let server_commitments =
            decode_cloudflare_normal_signing_commitments_v1(&protocol.server_commitments)?;
        let group_public_key = decode_cloudflare_near_ed25519_public_key_v1(
            "active SigningWorker account_public_key",
            &request.active_signing_worker.account_public_key,
        )?;
        let expected_server_verifying_share = verifying_share_bytes_from_signing_share_bytes(
            request.material.output_material.as_bytes(),
        );
        let supplied_server_verifying_share = decode_base64url_fixed_32_v1(
            "normal-signing v2 server_verifying_share_b64u",
            &protocol.server_verifying_share_b64u,
        )?;
        if supplied_server_verifying_share != expected_server_verifying_share {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "normal-signing server verifying share does not match active Yao material",
            ));
        }
        let client_identifier = frost_ed25519::Identifier::try_from(1_u16)
            .map_err(map_cloudflare_ed25519_frost_error_v1)?;
        let signing_worker_identifier = frost_ed25519::Identifier::try_from(2_u16)
            .map_err(map_cloudflare_ed25519_frost_error_v1)?;
        let mut key_package = key_package_from_signing_share_bytes(
            request.material.output_material.as_bytes(),
            &group_public_key,
            signing_worker_identifier,
        )
        .map_err(map_cloudflare_signer_core_error_v1)?;
        let signing_package = build_signing_package(
            request.server_round1.admitted_signing_digest.as_bytes(),
            BTreeMap::from([
                (
                    client_identifier,
                    decode_cloudflare_normal_signing_commitments_v1(&protocol.client_commitments)?,
                ),
                (signing_worker_identifier, server_commitments),
            ]),
        );
        let mut signing_nonces = request.server_round1.round1_state.signing_nonces()?;
        let signing_worker_signature_share =
            frost_ed25519::round2::sign(&signing_package, &signing_nonces, &key_package)
                .map_err(map_cloudflare_ed25519_frost_error_v1)?;
        zeroize::Zeroize::zeroize(&mut signing_nonces);
        zeroize::Zeroize::zeroize(&mut key_package);
        let verifying_key = frost_ed25519::VerifyingKey::deserialize(&group_public_key)
            .map_err(map_cloudflare_ed25519_frost_error_v1)?;
        let signature = aggregate_signature(
            &signing_package,
            verifying_key,
            BTreeMap::from([
                (
                    client_identifier,
                    verifying_share_from_b64u(&protocol.client_verifying_share_b64u)
                        .map_err(map_cloudflare_signer_core_error_v1)?,
                ),
                (
                    signing_worker_identifier,
                    verifying_share_from_b64u(&protocol.server_verifying_share_b64u)
                        .map_err(map_cloudflare_signer_core_error_v1)?,
                ),
            ]),
            BTreeMap::from([
                (
                    client_identifier,
                    signature_share_from_b64u(&protocol.client_signature_share_b64u)
                        .map_err(map_cloudflare_signer_core_error_v1)?,
                ),
                (signing_worker_identifier, signing_worker_signature_share),
            ]),
        )
        .map_err(map_cloudflare_signer_core_error_v1)?;
        NormalSigningResponseV1::new(
            finalize_request.scope.clone(),
            finalize_request.signing_payload_digest(),
            request.active_signing_worker.signing_worker.clone(),
            finalize_request.protocol.signature_scheme(),
            CanonicalWireBytesV1::new(signature.to_vec())?,
            request.signed_at_ms,
        )
    }
}

/// Production SigningWorker finalize handler for Router A/B ECDSA derivation EVM digest signing.
#[derive(Debug, Clone, Copy, Default)]
pub struct CloudflareRoleSeparatedRouterAbEcdsaDerivationEvmDigestFinalizeHandlerV1;

impl CloudflareSigningWorkerRouterAbEcdsaDerivationEvmDigestFinalizeHandlerV1
    for CloudflareRoleSeparatedRouterAbEcdsaDerivationEvmDigestFinalizeHandlerV1
{
    fn handle_router_ab_ecdsa_derivation_evm_digest_finalize_request_v1(
        &self,
        request: CloudflareSigningWorkerMaterializedRouterAbEcdsaDerivationEvmDigestFinalizeRequestV1,
    ) -> RouterAbProtocolResult<RouterAbEcdsaDerivationEvmDigestSigningResponseV1> {
        request.validate()?;
        let prepare_request = request.prepare_request()?;
        let public_key33 = decode_base64url_fixed_33_v1(
            "Router A/B ECDSA derivation threshold_public_key33_b64u",
            &prepare_request
                .scope
                .public_identity
                .threshold_public_key33_b64u,
        )?;
        let server_big_r33 = decode_base64url_fixed_33_v1(
            "Router A/B ECDSA derivation server_big_r33_b64u",
            &request.server_presignature.server_big_r33_b64u,
        )?;
        let server_k_share32 = decode_base64url_fixed_32_v1(
            "Router A/B ECDSA derivation server_k_share32_b64u",
            &request.server_presignature.server_k_share32_b64u,
        )?;
        let server_sigma_share32 = decode_base64url_fixed_32_v1(
            "Router A/B ECDSA derivation server_sigma_share32_b64u",
            &request.server_presignature.server_sigma_share32_b64u,
        )?;
        let signing_worker_rerandomization_contribution32 = decode_base64url_fixed_32_v1(
            "Router A/B ECDSA derivation signing_worker_rerandomization_contribution32_b64u",
            &request
                .server_presignature
                .signing_worker_rerandomization_contribution32_b64u,
        )?;
        let rerandomization_entropy32 = combine_rerandomization_contributions(
            request
                .request
                .request
                .client_rerandomization_contribution32()?,
            signing_worker_rerandomization_contribution32,
        );
        let client_signature_share32 = request.request.request.client_signature_share32()?;
        let material = SigningWorkerPresignMaterial::from_bytes(
            server_big_r33,
            server_k_share32,
            server_sigma_share32,
        )
        .map_err(map_cloudflare_online_ecdsa_error_v1)?;
        let input = SigningWorkerOnlineInput::new(
            public_key33,
            server_big_r33,
            *request
                .server_presignature
                .admitted_signing_digest
                .as_bytes(),
            rerandomization_entropy32,
        )
        .map_err(map_cloudflare_online_ecdsa_error_v1)?;
        let committed = material
            .reserve()
            .commit(input)
            .map_err(map_cloudflare_online_ecdsa_error_v1)?;
        let signature65 = finalize_signing_worker_signature(committed, client_signature_share32)
            .map_err(map_cloudflare_online_ecdsa_error_v1)?;
        RouterAbEcdsaDerivationEvmDigestSigningResponseV1::new_for_request(
            &request.request.request,
            encode_base64url_bytes_v1(&signature65),
        )
    }
}

fn decode_cloudflare_normal_signing_commitments_v1(
    commitments: &NormalSigningEd25519TwoPartyFrostCommitmentsV1,
) -> RouterAbProtocolResult<frost_ed25519::round1::SigningCommitments> {
    let hiding = frost_ed25519::round1::NonceCommitment::deserialize(
        &decode_base64url_fixed_32_v1("normal-signing commitments.hiding", &commitments.hiding)?,
    )
    .map_err(map_cloudflare_ed25519_frost_error_v1)?;
    let binding = frost_ed25519::round1::NonceCommitment::deserialize(
        &decode_base64url_fixed_32_v1("normal-signing commitments.binding", &commitments.binding)?,
    )
    .map_err(map_cloudflare_ed25519_frost_error_v1)?;
    Ok(frost_ed25519::round1::SigningCommitments::new(
        hiding, binding,
    ))
}

fn prepare_cloudflare_ed25519_round1_v1<Rng>(
    signing_share_bytes: &[u8; 32],
    rng: &mut Rng,
) -> RouterAbProtocolResult<CloudflareEd25519Round1StateV1>
where
    Rng: rand_core_06::CryptoRng + rand_core_06::RngCore,
{
    let signing_share = frost_ed25519::keys::SigningShare::deserialize(signing_share_bytes)
        .map_err(map_cloudflare_ed25519_frost_error_v1)?;
    let (signing_nonces, commitments) = frost_ed25519::round1::commit(&signing_share, rng);
    CloudflareEd25519Round1StateV1::new(signing_nonces, commitments)
}

fn decode_cloudflare_near_ed25519_public_key_v1(
    field: &str,
    value: &str,
) -> RouterAbProtocolResult<[u8; 32]> {
    let Some(encoded) = value.strip_prefix("ed25519:") else {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("{field} must use ed25519:<base58-public-key> format"),
        ));
    };
    let decoded = bs58::decode(encoded).into_vec().map_err(|err| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("{field} base58 decode failed: {err}"),
        )
    })?;
    let bytes: [u8; 32] = decoded.try_into().map_err(|decoded: Vec<u8>| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("{field} must decode to 32 bytes, got {}", decoded.len()),
        )
    })?;
    Ok(bytes)
}

fn map_cloudflare_ed25519_frost_error_v1(error: impl core::fmt::Display) -> RouterAbProtocolError {
    RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::MalformedWirePayload,
        format!("Ed25519 FROST signing failed: {error}"),
    )
}

fn map_cloudflare_signer_core_error_v1(error: SignerCoreError) -> RouterAbProtocolError {
    let code = match error.code {
        SignerCoreErrorCode::InvalidInput
        | SignerCoreErrorCode::InvalidLength
        | SignerCoreErrorCode::DecodeError
        | SignerCoreErrorCode::Utf8Error
        | SignerCoreErrorCode::Unsupported => RouterAbProtocolErrorCode::MalformedWirePayload,
        SignerCoreErrorCode::EncodeError
        | SignerCoreErrorCode::HkdfError
        | SignerCoreErrorCode::CryptoError
        | SignerCoreErrorCode::Internal => RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
    };
    RouterAbProtocolError::new(
        code,
        format!("Ed25519 FROST signing failed: {}", error.message),
    )
}

fn map_cloudflare_online_ecdsa_error_v1(error: OnlineError) -> RouterAbProtocolError {
    let code = match error {
        OnlineError::InvalidPoint
        | OnlineError::IdentityPoint
        | OnlineError::NonCanonicalScalar
        | OnlineError::ZeroScalar
        | OnlineError::PresignCommitmentMismatch => RouterAbProtocolErrorCode::MalformedWirePayload,
        OnlineError::RandomnessDerivation
        | OnlineError::SignatureVerification
        | OnlineError::RecoveryId => RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
    };
    RouterAbProtocolError::new(
        code,
        format!(
            "Router A/B ECDSA derivation normal signing finalize failed: {}",
            error
        ),
    )
}
