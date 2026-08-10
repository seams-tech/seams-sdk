//! Client-owned Ed25519 Yao lane typestate.
//!
//! The client request carries only the immutable public lane job.  Source
//! material and the fresh lane offset stay inside the Deriver/runtime side;
//! this boundary never serializes a seed, root, or base scalar.

use core::fmt;

use router_ab_core::{
    Ed25519YaoDeriverRoleV1, Ed25519YaoEncryptedPackageV1, Ed25519YaoLaneJobV1,
    Ed25519YaoLaneProtocolCommittedV1, Ed25519YaoPackageKindV1, RouterAbEd25519YaoLaneResultV1,
};
use serde::{Deserialize, Serialize};

/// Client lane preparation/completion failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientLaneError {
    /// The lane job failed its admission checks.
    InvalidJob,
    /// A response could not be decoded or did not match the prepared job.
    InvalidResponse,
    /// The one-use preparation state was already consumed.
    Consumed,
}

impl fmt::Display for ClientLaneError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidJob => "Ed25519 Yao lane job is invalid",
            Self::InvalidResponse => "Ed25519 Yao lane response is invalid",
            Self::Consumed => "Ed25519 Yao lane preparation was consumed",
        })
    }
}

impl std::error::Error for ClientLaneError {}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LaneClientPrepareRequestV1 {
    kind: &'static str,
    job: Ed25519YaoLaneJobV1,
}

/// The holder-only package set returned with a committed lane receipt.
///
/// The two encrypted package JSON values remain opaque to this crate and are
/// forwarded to the holder-recipient boundary for authenticated opening.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Ed25519YaoLaneHolderPackageWireV1 {
    /// Fixed holder package-set discriminator.
    pub kind: String,
    /// Deriver A's opaque holder package JSON.
    pub deriver_a_encrypted_package_json: String,
    /// Deriver B's opaque holder package JSON.
    pub deriver_b_encrypted_package_json: String,
}

impl Ed25519YaoLaneHolderPackageWireV1 {
    fn from_result(result: &RouterAbEd25519YaoLaneResultV1) -> Result<Self, ClientLaneError> {
        let holder_package = Self {
            kind: "ed25519_yao_lane_holder_package_set_v1".to_owned(),
            deriver_a_encrypted_package_json: serde_json::to_string(
                &result.deriver_a_holder_package,
            )
            .map_err(|_| ClientLaneError::InvalidResponse)?,
            deriver_b_encrypted_package_json: serde_json::to_string(
                &result.deriver_b_holder_package,
            )
            .map_err(|_| ClientLaneError::InvalidResponse)?,
        };
        holder_package.validate()?;
        Ok(holder_package)
    }

    fn validate(&self) -> Result<(), ClientLaneError> {
        if self.kind != "ed25519_yao_lane_holder_package_set_v1" {
            return Err(ClientLaneError::InvalidResponse);
        }
        validate_holder_package_json(
            &self.deriver_a_encrypted_package_json,
            Ed25519YaoDeriverRoleV1::DeriverA,
        )?;
        validate_holder_package_json(
            &self.deriver_b_encrypted_package_json,
            Ed25519YaoDeriverRoleV1::DeriverB,
        )
    }
}

/// Verified client completion retained for holder delivery and receipt
/// accounting. It contains no plaintext lane material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Ed25519YaoLaneClientCompletionV1 {
    /// Exact terminal protocol receipt.
    pub protocol_commit_receipt: Ed25519YaoLaneProtocolCommittedV1,
    /// Opaque A/B holder package set for later delivery.
    pub holder_package: Ed25519YaoLaneHolderPackageWireV1,
}

impl Ed25519YaoLaneClientCompletionV1 {
    /// Returns the exact protocol commit receipt.
    pub const fn protocol_commit_receipt(&self) -> &Ed25519YaoLaneProtocolCommittedV1 {
        &self.protocol_commit_receipt
    }

    /// Returns the opaque holder package set.
    pub const fn holder_package(&self) -> &Ed25519YaoLaneHolderPackageWireV1 {
        &self.holder_package
    }

    fn validate(&self) -> Result<(), ClientLaneError> {
        self.protocol_commit_receipt
            .validate()
            .map_err(|_| ClientLaneError::InvalidResponse)?;
        self.holder_package.validate()
    }
}

/// Client-owned one-use lane preparation state.
#[derive(Debug)]
pub struct PreparedClientLaneV1 {
    job: Ed25519YaoLaneJobV1,
    request_json: String,
}

impl PreparedClientLaneV1 {
    /// Returns the opaque request JSON for the Router lane endpoint.
    pub fn execute_request_json(&self) -> &str {
        &self.request_json
    }

    /// Returns the prepared job identity without exposing private material.
    pub const fn job(&self) -> &Ed25519YaoLaneJobV1 {
        &self.job
    }
}

/// Validates an immutable lane job and builds the opaque client request.
pub fn prepare_client_lane_v1(
    job: Ed25519YaoLaneJobV1,
) -> Result<PreparedClientLaneV1, ClientLaneError> {
    job.validate().map_err(|_| ClientLaneError::InvalidJob)?;
    let request = LaneClientPrepareRequestV1 {
        kind: "ed25519_yao_lane_client_prepare_v1",
        job: job.clone(),
    };
    let request_json = serde_json::to_string(&request).map_err(|_| ClientLaneError::InvalidJob)?;
    Ok(PreparedClientLaneV1 { job, request_json })
}

/// Consumes preparation state and builds the immutable protocol commit receipt
/// plus the opaque holder package set required for later delivery.
pub fn complete_client_lane_v1(
    prepared: PreparedClientLaneV1,
    response_json: &str,
) -> Result<Ed25519YaoLaneClientCompletionV1, ClientLaneError> {
    let response = serde_json::from_str::<RouterAbEd25519YaoLaneResultV1>(response_json)
        .map_err(|_| ClientLaneError::InvalidResponse)?;
    response
        .validate()
        .map_err(|_| ClientLaneError::InvalidResponse)?;
    if response.job != prepared.job {
        return Err(ClientLaneError::InvalidResponse);
    }
    let job = prepared.job;
    let target_lane_id = job.target_lane_id().to_owned();
    let target_lane_share_epoch = job.target_lane_share_epoch();
    let holder_package = Ed25519YaoLaneHolderPackageWireV1::from_result(&response)?;
    let protocol_commit_receipt = Ed25519YaoLaneProtocolCommittedV1::new(
        job.operation_id,
        job.enrollment_id,
        job.wallet_id,
        job.wallet_key_id,
        job.source.lane_id,
        job.source.lane_share_epoch,
        job.source.revocation_epoch,
        job.source.material_activation,
        target_lane_id,
        target_lane_share_epoch,
        job.target_material_activation_id,
        job.key_family,
        response.public_identity_digest_b64u,
        response.target_holder_public_commitment_b64u,
        response.target_server_public_commitment_b64u,
        response.target_holder_ciphertext_digest_set_b64u,
        response.target_server_ciphertext_digest_set_b64u,
        response.holder_recipient_key_digest_b64u,
        response.server_recipient_key_digest_b64u,
        response.transcript_hash_b64u,
        response.committed_at_ms,
    )
    .map_err(|_| ClientLaneError::InvalidResponse)?;
    let completion = Ed25519YaoLaneClientCompletionV1 {
        protocol_commit_receipt,
        holder_package,
    };
    completion.validate()?;
    Ok(completion)
}

fn validate_holder_package_json(
    package_json: &str,
    deriver: Ed25519YaoDeriverRoleV1,
) -> Result<(), ClientLaneError> {
    let package = serde_json::from_str::<Ed25519YaoEncryptedPackageV1>(package_json)
        .map_err(|_| ClientLaneError::InvalidResponse)?;
    package
        .validate()
        .map_err(|_| ClientLaneError::InvalidResponse)?;
    if package.kind() != Ed25519YaoPackageKindV1::LaneHolder || package.deriver() != deriver {
        return Err(ClientLaneError::InvalidResponse);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn package_json(deriver: Ed25519YaoDeriverRoleV1) -> String {
        serde_json::to_string(
            &Ed25519YaoEncryptedPackageV1::new(
                Ed25519YaoPackageKindV1::LaneHolder,
                deriver,
                [1_u8; 32],
                [2_u8; 32],
                [3_u8; 32],
                vec![4_u8; 16],
            )
            .expect("valid opaque package"),
        )
        .expect("package JSON")
    }

    #[test]
    fn holder_wire_requires_distinct_role_bound_packages() {
        let wire = Ed25519YaoLaneHolderPackageWireV1 {
            kind: "ed25519_yao_lane_holder_package_set_v1".to_owned(),
            deriver_a_encrypted_package_json: package_json(Ed25519YaoDeriverRoleV1::DeriverA),
            deriver_b_encrypted_package_json: package_json(Ed25519YaoDeriverRoleV1::DeriverB),
        };
        wire.validate().expect("role-bound holder package wire");

        let swapped = Ed25519YaoLaneHolderPackageWireV1 {
            deriver_a_encrypted_package_json: wire.deriver_b_encrypted_package_json.clone(),
            ..wire
        };
        assert_eq!(swapped.validate(), Err(ClientLaneError::InvalidResponse));
    }
}
