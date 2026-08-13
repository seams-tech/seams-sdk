//! Internal Router dispatch contract for one admitted Ed25519 lane ceremony.

use serde::{Deserialize, Serialize};

use crate::derivation::PublicDigest32;

use super::{
    Ed25519YaoCeremonyBindingV1, Ed25519YaoInputPairBindingV1, Ed25519YaoLaneProtocolCommittedV1,
    Ed25519YaoLaneRequestKindV1, RouterAbEd25519YaoLaneExecuteRequestV1,
    RouterAbEd25519YaoLaneResultV1, RouterAbProtocolError, RouterAbProtocolErrorCode,
    RouterAbProtocolResult, RouterAdmittedExecutionAuthorityV1, RouterEd25519YaoExecuteRequestV1,
};

/// Authenticated server-to-Router command for one already-admitted lane job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RouterAbEd25519YaoLaneDispatchRequestV1 {
    /// Public ceremony binding needed by the role-private root loaders.
    pub binding: Ed25519YaoCeremonyBindingV1,
    /// Exact lane job and role-recipient ciphertexts.
    pub request: RouterAbEd25519YaoLaneExecuteRequestV1,
}

impl RouterAbEd25519YaoLaneDispatchRequestV1 {
    /// Creates a dispatch command whose public binding matches the opaque inputs.
    pub fn new(
        binding: Ed25519YaoCeremonyBindingV1,
        request: RouterAbEd25519YaoLaneExecuteRequestV1,
    ) -> RouterAbProtocolResult<Self> {
        let command = Self { binding, request };
        command.validate()?;
        Ok(command)
    }

    /// Revalidates the complete internal dispatch boundary.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.binding.validate()?;
        self.request.job.validate()?;
        let job = &self.request.job;
        if self.binding.operation != job.yao_request_kind.operation()
            || self.binding.session_id.into_bytes() != job.session_v1()?
            || self.binding.stable_key_context_binding.into_bytes()
                != job.stable_context_binding_v1()?
            || self.binding.material_activation() != job.source.material_activation()
            || self.binding.lifecycle.lifecycle_id != job.operation_id
            || self.binding.lifecycle.account_id != job.wallet_id
            || self.binding.lifecycle.selected_server_id != job.source.signing_worker_id()
        {
            return Err(invalid_lane_dispatch(
                "Ed25519 lane dispatch binding does not match the admitted job",
            ));
        }
        Ok(())
    }

    /// Converts the admitted command into the Router's pair-bound execution type.
    pub fn into_router_execute_request(
        self,
        recipient_set_digest: PublicDigest32,
        issued_at_ms: u64,
        expires_at_ms: u64,
    ) -> RouterAbProtocolResult<RouterEd25519YaoExecuteRequestV1> {
        self.validate()?;
        let authorization_digest = PublicDigest32::new(self.request.job.transcript_digest_v1()?);
        let pair_binding = Ed25519YaoInputPairBindingV1::from_ceremony_binding(
            self.binding.clone(),
            &self.request.deriver_a_input,
            &self.request.deriver_b_input,
            recipient_set_digest,
            authorization_digest,
        )?;
        let authority = RouterAdmittedExecutionAuthorityV1::new(
            authorization_digest,
            issued_at_ms,
            expires_at_ms,
        )?;
        match self.request.job.yao_request_kind {
            Ed25519YaoLaneRequestKindV1::LaneProvisioning => {
                RouterEd25519YaoExecuteRequestV1::lane_provisioning(
                    authority,
                    self.binding,
                    pair_binding,
                    self.request.job,
                    self.request.deriver_a_input,
                    self.request.deriver_b_input,
                )
            }
            Ed25519YaoLaneRequestKindV1::LaneRefresh => {
                RouterEd25519YaoExecuteRequestV1::lane_refresh(
                    authority,
                    self.binding,
                    pair_binding,
                    self.request.job,
                    self.request.deriver_a_input,
                    self.request.deriver_b_input,
                )
            }
        }
    }
}

/// Successful internal lane dispatch projection returned only after the
/// SigningWorker has durably committed the exact output artifacts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RouterAbEd25519YaoLaneDispatchResponseV1 {
    /// Exact public lane result.
    pub result: RouterAbEd25519YaoLaneResultV1,
    /// Exact immutable protocol commit receipt.
    pub receipt: Ed25519YaoLaneProtocolCommittedV1,
}

impl RouterAbEd25519YaoLaneDispatchResponseV1 {
    /// Creates a checked result/receipt projection.
    pub fn new(
        result: RouterAbEd25519YaoLaneResultV1,
        receipt: Ed25519YaoLaneProtocolCommittedV1,
    ) -> RouterAbProtocolResult<Self> {
        result.validate()?;
        receipt.validate()?;
        let job = &result.job;
        if receipt.operation_id != job.operation_id
            || receipt.enrollment_id != job.enrollment_id
            || receipt.wallet_id != job.wallet_id
            || receipt.wallet_key_id != job.wallet_key_id
            || receipt.source_lane_id != job.source.lane_id()
            || receipt.source_lane_share_epoch != job.source.lane_share_epoch()
            || receipt.source_revocation_epoch != job.source.revocation_epoch()
            || receipt.source_material_activation != *job.source.material_activation()
            || receipt.target_lane_id != job.target_lane_id()
            || receipt.target_lane_share_epoch != job.target_lane_share_epoch()
            || receipt.target_material_activation_id != job.target_material_activation_id
            || receipt.key_family != job.key_family
            || receipt.public_identity_digest_b64u != result.public_identity_digest_b64u
            || receipt.target_holder_public_commitment_b64u
                != result.target_holder_public_commitment_b64u
            || receipt.target_server_public_commitment_b64u
                != result.target_server_public_commitment_b64u
            || receipt.target_holder_ciphertext_digest_set_b64u
                != result.target_holder_ciphertext_digest_set_b64u
            || receipt.target_server_ciphertext_digest_set_b64u
                != result.target_server_ciphertext_digest_set_b64u
            || receipt.holder_recipient_key_digest_b64u != result.holder_recipient_key_digest_b64u
            || receipt.server_recipient_key_digest_b64u != result.server_recipient_key_digest_b64u
            || receipt.transcript_hash_b64u != result.transcript_hash_b64u
            || receipt.committed_at_ms != result.committed_at_ms
        {
            return Err(invalid_lane_dispatch(
                "Ed25519 lane dispatch result and receipt do not match",
            ));
        }
        Ok(Self { result, receipt })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawRouterAbEd25519YaoLaneDispatchResponseV1 {
    result: RouterAbEd25519YaoLaneResultV1,
    receipt: Ed25519YaoLaneProtocolCommittedV1,
}

impl<'de> Deserialize<'de> for RouterAbEd25519YaoLaneDispatchResponseV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = RawRouterAbEd25519YaoLaneDispatchResponseV1::deserialize(deserializer)?;
        Self::new(raw.result, raw.receipt).map_err(serde::de::Error::custom)
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawRouterAbEd25519YaoLaneDispatchRequestV1 {
    binding: Ed25519YaoCeremonyBindingV1,
    request: RouterAbEd25519YaoLaneExecuteRequestV1,
}

impl<'de> Deserialize<'de> for RouterAbEd25519YaoLaneDispatchRequestV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = RawRouterAbEd25519YaoLaneDispatchRequestV1::deserialize(deserializer)?;
        Self::new(raw.binding, raw.request).map_err(serde::de::Error::custom)
    }
}

fn invalid_lane_dispatch(message: &'static str) -> RouterAbProtocolError {
    RouterAbProtocolError::new(RouterAbProtocolErrorCode::InvalidLifecycleState, message)
}
