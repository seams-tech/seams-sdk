use crate::*;
use std::collections::BTreeMap;

use signer_core::error::{SignerCoreError, SignerCoreErrorCode};
use signer_core::near_threshold_ed25519::{
    aggregate_signature, build_signing_package, key_package_from_signing_share_bytes,
    signature_share_from_b64u, verifying_share_bytes_from_signing_share_bytes,
    verifying_share_from_b64u,
};
use signer_core::threshold_ecdsa::threshold_ecdsa_finalize_signature;

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

/// SigningWorker ECDSA-HSS finalize logic behind the Cloudflare transport wrapper.
pub trait CloudflareSigningWorkerEcdsaHssEvmDigestFinalizeHandlerV1 {
    /// Handles one materialized ECDSA-HSS finalize request.
    fn handle_ecdsa_hss_evm_digest_finalize_request_v1(
        &self,
        request: CloudflareSigningWorkerMaterializedEcdsaHssEvmDigestFinalizeRequestV1,
    ) -> RouterAbProtocolResult<RouterAbEcdsaHssEvmDigestSigningResponseV1>;
}

/// Private SigningWorker request to fill the ECDSA-HSS presignature pool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareSigningWorkerEcdsaHssPresignaturePoolPutRequestV1 {
    /// Normal-signing identity and active SigningWorker scope.
    pub scope: RouterAbEcdsaHssNormalSigningScopeV1,
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

impl CloudflareSigningWorkerEcdsaHssPresignaturePoolPutRequestV1 {
    /// Creates a validated ECDSA-HSS presignature pool-fill request.
    pub fn new(
        scope: RouterAbEcdsaHssNormalSigningScopeV1,
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
            "ECDSA-HSS presignature pool fill expires_at_ms",
            self.expires_at_ms,
        )
    }

    /// Validates this pool-fill request can be accepted at the supplied timestamp.
    pub fn validate_at(&self, now_unix_ms: u64) -> RouterAbProtocolResult<()> {
        self.validate()?;
        require_positive_ms("ECDSA-HSS presignature pool fill now_unix_ms", now_unix_ms)?;
        if self.expires_at_ms <= now_unix_ms {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ExpiredLocalRequest,
                "ECDSA-HSS presignature pool fill request expired",
            ));
        }
        Ok(())
    }

    /// Builds the unbound pool record for the resolved active SigningWorker.
    pub fn to_pool_record(
        &self,
        active_signing_worker: ActiveSigningWorkerStateV1,
        now_unix_ms: u64,
    ) -> RouterAbProtocolResult<CloudflareSigningWorkerEcdsaPresignaturePoolRecordV1> {
        self.validate_at(now_unix_ms)?;
        let lookup =
            CloudflareActiveSigningWorkerStateLookupV1::from_ecdsa_hss_normal_signing_scope(
                &self.scope,
            )?;
        lookup.validate_active_state(&active_signing_worker)?;
        CloudflareSigningWorkerEcdsaPresignaturePoolRecordV1::new(
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
            || self.admission_candidate.threshold_session_id != self.scope.session_id
            || self.admission_candidate.signing_worker_id != self.scope.signing_worker_id
            || self.admission_candidate.request_id != self.scope.request_id
            || self.admission_candidate.expires_at_ms != self.expires_at_ms
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "normal-signing v2 prepare admission does not match request scope",
            ));
        }
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
    /// Accepted Router store admission decision for this request.
    pub trusted_admission: CloudflareRouterNormalSigningTrustedAdmissionV1,
}

impl CloudflareSigningWorkerAdmittedNormalSigningFinalizeRequestV2 {
    /// Creates a validated admitted v2 finalize service request.
    pub fn new(
        request: RouterAbEd25519NormalSigningFinalizeRequestV2,
        trusted_admission: CloudflareRouterNormalSigningTrustedAdmissionV1,
    ) -> RouterAbProtocolResult<Self> {
        let request = Self {
            request,
            trusted_admission,
        };
        request.validate()?;
        Ok(request)
    }

    /// Validates Router admission accepted this exact v2 finalize request.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.request.validate()?;
        self.trusted_admission
            .validate_for_finalize_request_v2(&self.request)?;
        if self.trusted_admission.allows_signing_worker_forwarding()? {
            return Ok(());
        }
        Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidGateDecision,
            "SigningWorker normal-signing v2 finalize requires accepted Router admission",
        ))
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

/// Router-admitted ECDSA-HSS normal-signing request sent to SigningWorker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSigningWorkerAdmittedEcdsaHssEvmDigestSigningRequestV1 {
    /// Typed public ECDSA-HSS normal-signing request accepted by the Router.
    pub request: RouterAbEcdsaHssEvmDigestSigningRequestV1,
    /// Accepted Router store admission decision for this request.
    pub trusted_admission: CloudflareRouterNormalSigningTrustedAdmissionV1,
}

impl CloudflareSigningWorkerAdmittedEcdsaHssEvmDigestSigningRequestV1 {
    /// Creates a validated admitted ECDSA-HSS normal-signing service request.
    pub fn new(
        request: RouterAbEcdsaHssEvmDigestSigningRequestV1,
        trusted_admission: CloudflareRouterNormalSigningTrustedAdmissionV1,
    ) -> RouterAbProtocolResult<Self> {
        let request = Self {
            request,
            trusted_admission,
        };
        request.validate()?;
        Ok(request)
    }

    /// Validates Router-admitted ECDSA-HSS normal-signing material.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.request.validate()?;
        self.trusted_admission.validate()?;
        if self.trusted_admission.metadata.account_id != self.request.scope.wallet_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "ECDSA-HSS trusted admission account_id does not match request scope",
            ));
        }
        if self.trusted_admission.metadata.auth.session_id()
            != cloudflare_ecdsa_hss_active_state_session_id_from_scope_v1(&self.request.scope)?
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "ECDSA-HSS trusted admission session_id does not match request scope",
            ));
        }
        if self.trusted_admission.metadata.intent_digest != self.request.request_digest()? {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "ECDSA-HSS trusted admission digest does not match request",
            ));
        }
        if self.trusted_admission.allows_signing_worker_forwarding()? {
            return Ok(());
        }
        Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidGateDecision,
            "SigningWorker ECDSA-HSS prepare requires accepted Router admission",
        ))
    }
}

/// Router-admitted ECDSA-HSS finalize request sent to SigningWorker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSigningWorkerAdmittedEcdsaHssEvmDigestFinalizeRequestV1 {
    /// Typed public ECDSA-HSS finalize request accepted by the Router.
    pub request: RouterAbEcdsaHssEvmDigestSigningFinalizeRequestV1,
    /// Accepted Router store admission decision for this request.
    pub trusted_admission: CloudflareRouterNormalSigningTrustedAdmissionV1,
}

impl CloudflareSigningWorkerAdmittedEcdsaHssEvmDigestFinalizeRequestV1 {
    /// Creates a validated admitted ECDSA-HSS finalize service request.
    pub fn new(
        request: RouterAbEcdsaHssEvmDigestSigningFinalizeRequestV1,
        trusted_admission: CloudflareRouterNormalSigningTrustedAdmissionV1,
    ) -> RouterAbProtocolResult<Self> {
        let request = Self {
            request,
            trusted_admission,
        };
        request.validate()?;
        Ok(request)
    }

    /// Validates Router admission accepted this exact ECDSA-HSS finalize body.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.request.validate()?;
        self.trusted_admission.validate()?;
        if self.trusted_admission.metadata.account_id != self.request.scope.wallet_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "ECDSA-HSS finalize trusted admission account_id does not match request scope",
            ));
        }
        if self.trusted_admission.metadata.auth.session_id()
            != cloudflare_ecdsa_hss_active_state_session_id_from_scope_v1(&self.request.scope)?
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "ECDSA-HSS finalize trusted admission session_id does not match request scope",
            ));
        }
        if self.trusted_admission.metadata.intent_digest != self.request.request_digest()? {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "ECDSA-HSS finalize trusted admission digest does not match request",
            ));
        }
        if self.trusted_admission.allows_signing_worker_forwarding()? {
            return Ok(());
        }
        Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidGateDecision,
            "SigningWorker ECDSA-HSS finalize requires accepted Router admission",
        ))
    }
}

/// ECDSA-HSS normal-signing request after active SigningWorker material lookup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSigningWorkerMaterializedEcdsaHssEvmDigestSigningRequestV1 {
    /// Router-admitted ECDSA-HSS request.
    pub request: CloudflareSigningWorkerAdmittedEcdsaHssEvmDigestSigningRequestV1,
    /// Active SigningWorker state selected for this ECDSA-HSS identity.
    pub active_signing_worker: ActiveSigningWorkerStateV1,
    /// Active ECDSA-HSS material opened during activation.
    pub material: CloudflareServerOutputMaterialRecordV1,
    /// Materialization timestamp in Unix milliseconds.
    pub materialized_at_ms: u64,
}

impl CloudflareSigningWorkerMaterializedEcdsaHssEvmDigestSigningRequestV1 {
    /// Creates a validated materialized ECDSA-HSS normal-signing request.
    pub fn new(
        request: CloudflareSigningWorkerAdmittedEcdsaHssEvmDigestSigningRequestV1,
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

    /// Validates forwarded ECDSA-HSS request and active material agree.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.request.validate()?;
        self.request.request.validate_at(self.materialized_at_ms)?;
        require_positive_ms(
            "ECDSA-HSS normal-signing materialized_at_ms",
            self.materialized_at_ms,
        )?;
        validate_cloudflare_ecdsa_hss_normal_signing_active_material_v1(
            &self.request.request.scope,
            &self.active_signing_worker,
            &self.material,
        )
    }
}

/// ECDSA-HSS finalize request after active material and one-use presignature lookup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSigningWorkerMaterializedEcdsaHssEvmDigestFinalizeRequestV1 {
    /// Router-admitted ECDSA-HSS finalize request.
    pub request: CloudflareSigningWorkerAdmittedEcdsaHssEvmDigestFinalizeRequestV1,
    /// Active SigningWorker state selected for this ECDSA-HSS identity.
    pub active_signing_worker: ActiveSigningWorkerStateV1,
    /// Active ECDSA-HSS material opened during activation.
    pub material: CloudflareServerOutputMaterialRecordV1,
    /// Exact persisted one-use server presignature state for this finalize request.
    pub server_presignature: CloudflareSigningWorkerEcdsaPresignatureRecordV1,
    /// Signing timestamp in Unix milliseconds.
    pub signed_at_ms: u64,
}

impl CloudflareSigningWorkerMaterializedEcdsaHssEvmDigestFinalizeRequestV1 {
    /// Creates a validated materialized ECDSA-HSS finalize request.
    pub fn new(
        request: CloudflareSigningWorkerAdmittedEcdsaHssEvmDigestFinalizeRequestV1,
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
        require_positive_ms("ECDSA-HSS finalize signed_at_ms", self.signed_at_ms)?;
        validate_cloudflare_ecdsa_hss_normal_signing_active_material_v1(
            &self.request.request.scope,
            &self.active_signing_worker,
            &self.material,
        )?;
        let lookup = CloudflareSigningWorkerEcdsaPresignatureLookupV1::new(
            self.active_signing_worker.clone(),
            self.request.request.server_presignature_id.clone(),
            self.request.request.prepare_request_digest()?,
            self.request.request.signing_digest()?,
            self.signed_at_ms,
        )?;
        self.server_presignature.validate_for_lookup(&lookup)
    }

    /// Returns the prepare request identity that the final signature response must bind.
    pub fn prepare_request(
        &self,
    ) -> RouterAbProtocolResult<RouterAbEcdsaHssEvmDigestSigningRequestV1> {
        self.validate()?;
        self.request.request.prepare_request()
    }
}

/// Materializes and handles one Router-admitted ECDSA-HSS finalize request.
pub fn handle_cloudflare_signing_worker_ecdsa_hss_evm_digest_finalize_private_request_v1<Handler>(
    handler: &Handler,
    now_unix_ms: u64,
    request: CloudflareSigningWorkerAdmittedEcdsaHssEvmDigestFinalizeRequestV1,
    active_signing_worker: ActiveSigningWorkerStateV1,
    material: CloudflareServerOutputMaterialRecordV1,
    server_presignature: CloudflareSigningWorkerEcdsaPresignatureRecordV1,
) -> RouterAbProtocolResult<RouterAbEcdsaHssEvmDigestSigningResponseV1>
where
    Handler: CloudflareSigningWorkerEcdsaHssEvmDigestFinalizeHandlerV1,
{
    let materialized = CloudflareSigningWorkerMaterializedEcdsaHssEvmDigestFinalizeRequestV1::new(
        request,
        active_signing_worker,
        material,
        server_presignature,
        now_unix_ms,
    )?;
    let prepare_request = materialized.prepare_request()?;
    let response = handler.handle_ecdsa_hss_evm_digest_finalize_request_v1(materialized)?;
    response.validate_for_request(&prepare_request)?;
    Ok(response)
}

/// SigningWorker-produced ECDSA-HSS presignature record plus public prepare response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSigningWorkerEcdsaHssEvmDigestPreparedV1 {
    /// Public response returned to the client through Router.
    pub response: RouterAbEcdsaHssEvmDigestSigningPrepareResponseV1,
    /// Private presignature record persisted by the SigningWorker Durable Object.
    pub record: CloudflareSigningWorkerEcdsaPresignatureRecordV1,
}

impl CloudflareSigningWorkerEcdsaHssEvmDigestPreparedV1 {
    /// Creates a validated ECDSA-HSS prepared bundle.
    pub fn new(
        response: RouterAbEcdsaHssEvmDigestSigningPrepareResponseV1,
        record: CloudflareSigningWorkerEcdsaPresignatureRecordV1,
        request: &CloudflareSigningWorkerMaterializedEcdsaHssEvmDigestSigningRequestV1,
    ) -> RouterAbProtocolResult<Self> {
        let prepared = Self { response, record };
        prepared.validate_for_request(request)?;
        Ok(prepared)
    }

    /// Validates the public response and private record bind to a materialized request.
    pub fn validate_for_request(
        &self,
        request: &CloudflareSigningWorkerMaterializedEcdsaHssEvmDigestSigningRequestV1,
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
            && self.record.rerandomization_entropy32_b64u
                == self.response.rerandomization_entropy32_b64u
            && self.record.created_at_ms == request.materialized_at_ms
            && self.record.expires_at_ms == request.request.request.expires_at_ms
        {
            return Ok(());
        }
        Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "SigningWorker ECDSA-HSS prepared record does not match response",
        ))
    }

    /// Validates the Durable Object put receipt matches the prepared record and response.
    pub fn validate_put_receipt(
        &self,
        receipt: &CloudflareSigningWorkerEcdsaPresignaturePutReceiptV1,
    ) -> RouterAbProtocolResult<()> {
        receipt.validate_for_record(&self.record)?;
        if receipt.server_presignature_id == self.response.server_presignature_id
            && receipt.request_digest == self.response.request_digest
            && receipt.admitted_signing_digest == self.response.signing_digest
            && receipt.server_big_r33_b64u == self.response.server_big_r33_b64u
            && receipt.rerandomization_entropy32_b64u
                == self.response.rerandomization_entropy32_b64u
        {
            return Ok(());
        }
        Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "SigningWorker ECDSA-HSS presignature receipt does not match prepare response",
        ))
    }
}

/// Builds a production ECDSA-HSS prepare bundle from a reserved unbound presignature.
pub fn prepare_cloudflare_role_separated_ecdsa_hss_evm_digest_from_pool_record_v1(
    request: CloudflareSigningWorkerMaterializedEcdsaHssEvmDigestSigningRequestV1,
    pool_record: CloudflareSigningWorkerEcdsaPresignaturePoolRecordV1,
    rerandomization_entropy32_b64u: impl Into<String>,
) -> RouterAbProtocolResult<CloudflareSigningWorkerEcdsaHssEvmDigestPreparedV1> {
    request.validate()?;
    let pool_lookup = CloudflareSigningWorkerEcdsaPresignaturePoolLookupV1::new(
        request.active_signing_worker.clone(),
        request.request.request.client_presignature_id.clone(),
        request.materialized_at_ms,
    )?;
    pool_record.validate_for_lookup(&pool_lookup)?;
    let rerandomization_entropy32_b64u = rerandomization_entropy32_b64u.into();
    let response = RouterAbEcdsaHssEvmDigestSigningPrepareResponseV1::new_for_request(
        &request.request.request,
        pool_record.server_presignature_id.clone(),
        pool_record.server_big_r33_b64u.clone(),
        rerandomization_entropy32_b64u.clone(),
        request.materialized_at_ms,
    )?;
    let record = pool_record.to_request_bound_record(
        request.request.request.request_digest()?,
        request.request.request.signing_digest()?,
        rerandomization_entropy32_b64u,
        request.materialized_at_ms,
        request.request.request.expires_at_ms,
    )?;
    CloudflareSigningWorkerEcdsaHssEvmDigestPreparedV1::new(response, record, &request)
}

/// SigningWorker-produced round-1 record plus public prepare response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSigningWorkerNormalSigningRound1PreparedV1 {
    /// Public response returned to the client through Router.
    pub response: NormalSigningRound1PrepareResponseV1,
    /// Private nonce record persisted by the SigningWorker Durable Object.
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

/// Production SigningWorker finalize handler for ECDSA-HSS EVM digest signing.
#[derive(Debug, Clone, Copy, Default)]
pub struct CloudflareRoleSeparatedEcdsaHssEvmDigestFinalizeHandlerV1;

impl CloudflareSigningWorkerEcdsaHssEvmDigestFinalizeHandlerV1
    for CloudflareRoleSeparatedEcdsaHssEvmDigestFinalizeHandlerV1
{
    fn handle_ecdsa_hss_evm_digest_finalize_request_v1(
        &self,
        request: CloudflareSigningWorkerMaterializedEcdsaHssEvmDigestFinalizeRequestV1,
    ) -> RouterAbProtocolResult<RouterAbEcdsaHssEvmDigestSigningResponseV1> {
        request.validate()?;
        let prepare_request = request.prepare_request()?;
        let public_key33 = decode_base64url_fixed_33_v1(
            "ECDSA-HSS threshold_public_key33_b64u",
            &prepare_request
                .scope
                .public_identity
                .threshold_public_key33_b64u,
        )?;
        let server_big_r33 = decode_base64url_fixed_33_v1(
            "ECDSA-HSS server_big_r33_b64u",
            &request.server_presignature.server_big_r33_b64u,
        )?;
        let server_k_share32 = decode_base64url_fixed_32_v1(
            "ECDSA-HSS server_k_share32_b64u",
            &request.server_presignature.server_k_share32_b64u,
        )?;
        let server_sigma_share32 = decode_base64url_fixed_32_v1(
            "ECDSA-HSS server_sigma_share32_b64u",
            &request.server_presignature.server_sigma_share32_b64u,
        )?;
        let rerandomization_entropy32 = decode_base64url_fixed_32_v1(
            "ECDSA-HSS rerandomization_entropy32_b64u",
            &request.server_presignature.rerandomization_entropy32_b64u,
        )?;
        let client_signature_share32 = request.request.request.client_signature_share32()?;
        let participant_ids = ECDSA_HSS_PARTICIPANT_IDS.map(u32::from);
        let signature65 = threshold_ecdsa_finalize_signature(
            &participant_ids,
            2,
            &public_key33,
            &server_big_r33,
            &server_k_share32,
            &server_sigma_share32,
            request
                .server_presignature
                .admitted_signing_digest
                .as_bytes(),
            &rerandomization_entropy32,
            &client_signature_share32,
        )
        .map_err(map_cloudflare_signer_core_ecdsa_error_v1)?;
        RouterAbEcdsaHssEvmDigestSigningResponseV1::new_for_request(
            &prepare_request,
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

fn map_cloudflare_signer_core_ecdsa_error_v1(err: SignerCoreError) -> RouterAbProtocolError {
    let code = match err.code {
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
        format!("ECDSA-HSS normal signing finalize failed: {}", err.message),
    )
}
