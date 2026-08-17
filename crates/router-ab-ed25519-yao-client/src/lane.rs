//! Client-owned Ed25519 Yao lane typestate.
//!
//! The client request carries only the immutable public lane job.  Source
//! material and the fresh lane offset stay inside the Deriver/runtime side;
//! this boundary never serializes a seed, root, or base scalar.

use core::fmt;

use base64ct::{Base64UrlUnpadded, Encoding};
use hpke_ng::{DhKemX25519HkdfSha256, Kem};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use router_ab_core::{
    Ed25519YaoCeremonyBindingV1, Ed25519YaoDeriverRoleV1, Ed25519YaoEncryptedInputV1,
    Ed25519YaoEncryptedPackageV1, Ed25519YaoInputKindV1, Ed25519YaoLaneJobV1,
    Ed25519YaoLaneProtocolCommittedV1, Ed25519YaoPackageKindV1,
    RouterAbEd25519YaoApplicationBindingFactsV1, RouterAbEd25519YaoLaneExecuteRequestV1,
    RouterAbEd25519YaoLaneResultV1,
};
use router_ab_ed25519_yao_protocol::{
    ed25519_yao_lane_input_aad_v1, stable_key_derivation_context_v1,
    LocalEd25519YaoClientContributionV1, LocalEd25519YaoLaneDeriverARequestV1,
    LocalEd25519YaoLaneDeriverBRequestV1, LocalEd25519YaoLaneRecipientsV1,
    ED25519_YAO_LANE_INPUT_HPKE_INFO_V1,
};
use serde::{Deserialize, Serialize};
use signer_core::ed25519_yao_derivation::{
    derive_ed25519_yao_client_contributions_v1, Ed25519YaoClientDerivationRootV1,
};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::InputHpkeV1;

/// Client lane preparation/completion failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientLaneError {
    /// The lane job failed its admission checks.
    InvalidJob,
    /// A response could not be decoded or did not match the prepared job.
    InvalidResponse,
    /// The one-use preparation state was already consumed.
    Consumed,
    /// The source capability, ceremony binding, or recipient keys did not match.
    BindingMismatch,
    /// Stable Client contribution derivation failed.
    DerivationFailed,
    /// Lane role-input encryption failed.
    HpkeFailed,
}

impl fmt::Display for ClientLaneError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidJob => "Ed25519 Yao lane job is invalid",
            Self::InvalidResponse => "Ed25519 Yao lane response is invalid",
            Self::Consumed => "Ed25519 Yao lane preparation was consumed",
            Self::BindingMismatch => "Ed25519 Yao lane source binding is invalid",
            Self::DerivationFailed => "Ed25519 Yao lane source derivation failed",
            Self::HpkeFailed => "Ed25519 Yao lane role input encryption failed",
        })
    }
}

impl std::error::Error for ClientLaneError {}

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
}

/// Purpose-separated one-use entropy for the two Deriver input envelopes.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ClientLaneExecutionEntropyV1 {
    deriver_a_seal_seed: [u8; 32],
    deriver_b_seal_seed: [u8; 32],
}

impl ClientLaneExecutionEntropyV1 {
    /// Creates two nonzero, distinct HPKE sender seeds.
    pub fn new(
        deriver_a_seal_seed: [u8; 32],
        deriver_b_seal_seed: [u8; 32],
    ) -> Result<Self, ClientLaneError> {
        let zero = [0_u8; 32];
        let valid = !deriver_a_seal_seed.ct_eq(&zero)
            & !deriver_b_seal_seed.ct_eq(&zero)
            & !deriver_a_seal_seed.ct_eq(&deriver_b_seal_seed);
        if !bool::from(valid) {
            return Err(ClientLaneError::HpkeFailed);
        }
        Ok(Self {
            deriver_a_seal_seed,
            deriver_b_seal_seed,
        })
    }
}

impl fmt::Debug for ClientLaneExecutionEntropyV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ClientLaneExecutionEntropyV1([REDACTED])")
    }
}

/// Post-prepare command containing only recipient-encrypted Deriver inputs.
#[derive(Debug)]
pub struct PreparedClientLaneDispatchV1 {
    execute_request: RouterAbEd25519YaoLaneExecuteRequestV1,
    completion: PreparedClientLaneV1,
}

impl PreparedClientLaneDispatchV1 {
    /// Returns the exact opaque request accepted by the internal Router adapter.
    pub const fn execute_request(&self) -> &RouterAbEd25519YaoLaneExecuteRequestV1 {
        &self.execute_request
    }

    /// Consumes the dispatch into its opaque request and completion state.
    pub fn into_parts(self) -> (RouterAbEd25519YaoLaneExecuteRequestV1, PreparedClientLaneV1) {
        (self.execute_request, self.completion)
    }
}

impl PreparedClientLaneV1 {
    /// Returns the prepared job identity without exposing private material.
    pub const fn job(&self) -> &Ed25519YaoLaneJobV1 {
        &self.job
    }
}

/// Validates an immutable lane job before resolving its source capability.
pub fn prepare_client_lane_v1(
    job: Ed25519YaoLaneJobV1,
) -> Result<PreparedClientLaneV1, ClientLaneError> {
    job.validate().map_err(|_| ClientLaneError::InvalidJob)?;
    Ok(PreparedClientLaneV1 { job })
}

/// Resolves a prepared job against the active source capability and encrypts
/// one exact input for each Deriver. The Client root and derived contributions
/// are consumed inside this boundary.
#[allow(clippy::too_many_arguments)]
pub fn prepare_client_lane_dispatch_with_root_v1(
    prepared: PreparedClientLaneV1,
    binding: &Ed25519YaoCeremonyBindingV1,
    application: &RouterAbEd25519YaoApplicationBindingFactsV1,
    participant_ids: [u16; 2],
    root: &Ed25519YaoClientDerivationRootV1,
    deriver_a_input_public_key: [u8; 32],
    deriver_b_input_public_key: [u8; 32],
    mut entropy: ClientLaneExecutionEntropyV1,
) -> Result<PreparedClientLaneDispatchV1, ClientLaneError> {
    let job = &prepared.job;
    job.validate().map_err(|_| ClientLaneError::InvalidJob)?;
    let context = stable_key_derivation_context_v1(application, participant_ids)
        .map_err(|_| ClientLaneError::DerivationFailed)?;
    if binding.operation != job.yao_request_kind.operation()
        || binding.session_id.into_bytes()
            != job
                .session_v1()
                .map_err(|_| ClientLaneError::BindingMismatch)?
        || binding.stable_key_context_binding.into_bytes() != context.binding_digest()
        || context.binding_digest()
            != job
                .stable_context_binding_v1()
                .map_err(|_| ClientLaneError::BindingMismatch)?
        || binding.material_activation() != job.source.material_activation()
    {
        return Err(ClientLaneError::BindingMismatch);
    }
    let contributions = derive_ed25519_yao_client_contributions_v1(root, &context)
        .map_err(|_| ClientLaneError::DerivationFailed)?;
    let (deriver_a, deriver_b) = contributions.into_parts();
    let (deriver_a_y, deriver_a_tau) = deriver_a.into_parts();
    let (deriver_b_y, deriver_b_tau) = deriver_b.into_parts();
    let recipients = LocalEd25519YaoLaneRecipientsV1 {
        holder_public_key: decode_key_v1(&job.target_holder.hpke_public_key_b64u)?,
        signing_worker_public_key: decode_key_v1(&job.target_signing_worker.hpke_public_key_b64u)?,
    };
    let request_a = LocalEd25519YaoLaneDeriverARequestV1 {
        binding: binding.clone(),
        job: job.clone(),
        application_binding: application.clone(),
        participant_ids,
        client_contribution: LocalEd25519YaoClientContributionV1 {
            y: deriver_a_y.into_bytes(),
            tau: deriver_a_tau.into_bytes(),
        },
        recipients,
    };
    let request_b = LocalEd25519YaoLaneDeriverBRequestV1 {
        binding: binding.clone(),
        job: job.clone(),
        application_binding: application.clone(),
        participant_ids,
        client_contribution: LocalEd25519YaoClientContributionV1 {
            y: deriver_b_y.into_bytes(),
            tau: deriver_b_tau.into_bytes(),
        },
        recipients,
    };
    let deriver_a_input = seal_lane_input_v1(
        Ed25519YaoDeriverRoleV1::DeriverA,
        deriver_a_input_public_key,
        &mut entropy.deriver_a_seal_seed,
        binding,
        job,
        &request_a,
    )?;
    let deriver_b_input = seal_lane_input_v1(
        Ed25519YaoDeriverRoleV1::DeriverB,
        deriver_b_input_public_key,
        &mut entropy.deriver_b_seal_seed,
        binding,
        job,
        &request_b,
    )?;
    let execute_request =
        RouterAbEd25519YaoLaneExecuteRequestV1::new(job.clone(), deriver_a_input, deriver_b_input)
            .map_err(|_| ClientLaneError::BindingMismatch)?;
    Ok(PreparedClientLaneDispatchV1 {
        execute_request,
        completion: prepared,
    })
}

fn seal_lane_input_v1<Request: Serialize>(
    deriver: Ed25519YaoDeriverRoleV1,
    public_key: [u8; 32],
    seed: &mut [u8; 32],
    binding: &Ed25519YaoCeremonyBindingV1,
    job: &Ed25519YaoLaneJobV1,
    request: &Request,
) -> Result<Ed25519YaoEncryptedInputV1, ClientLaneError> {
    let public_key = DhKemX25519HkdfSha256::pk_from_bytes(&public_key)
        .map_err(|_| ClientLaneError::HpkeFailed)?;
    let mut plaintext =
        Zeroizing::new(serde_json::to_vec(request).map_err(|_| ClientLaneError::HpkeFailed)?);
    let session = job.session_v1().map_err(|_| ClientLaneError::InvalidJob)?;
    let stable_context_binding = job
        .stable_context_binding_v1()
        .map_err(|_| ClientLaneError::InvalidJob)?;
    let aad = ed25519_yao_lane_input_aad_v1(
        deriver,
        binding.operation,
        session,
        stable_context_binding,
        job.transcript_digest_v1()
            .map_err(|_| ClientLaneError::InvalidJob)?,
    );
    let mut rng = ChaCha20Rng::from_seed(*seed);
    seed.zeroize();
    let (encapsulated_key, ciphertext) = InputHpkeV1::seal_base(
        &mut rng,
        &public_key,
        ED25519_YAO_LANE_INPUT_HPKE_INFO_V1,
        &aad,
        &plaintext,
    )
    .map_err(|_| ClientLaneError::HpkeFailed)?;
    plaintext.zeroize();
    Ed25519YaoEncryptedInputV1::new(
        Ed25519YaoInputKindV1::LaneMaterialization,
        deriver,
        binding.operation,
        session,
        stable_context_binding,
        encapsulated_key
            .as_ref()
            .try_into()
            .map_err(|_| ClientLaneError::HpkeFailed)?,
        ciphertext,
    )
    .map_err(|_| ClientLaneError::BindingMismatch)
}

fn decode_key_v1(encoded: &str) -> Result<[u8; 32], ClientLaneError> {
    let mut bytes = [0_u8; 32];
    Base64UrlUnpadded::decode(encoded, &mut bytes).map_err(|_| ClientLaneError::BindingMismatch)?;
    Ok(bytes)
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
    let target_lane_share_epoch = job.target_lane_share_epoch().to_owned();
    let holder_package = Ed25519YaoLaneHolderPackageWireV1::from_result(&response)?;
    let protocol_commit_receipt = Ed25519YaoLaneProtocolCommittedV1::new(
        job.operation_id,
        job.enrollment_id,
        job.wallet_id,
        job.wallet_key_id,
        job.source.lane_id(),
        job.source.lane_share_epoch(),
        job.source.revocation_epoch(),
        job.source.material_activation().clone(),
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
