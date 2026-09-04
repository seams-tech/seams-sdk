//! SigningWorker-owned Ed25519 Yao lane activation.
//!
//! The route consumes only the public lane identity and holder acknowledgement.
//! The two encrypted SigningWorker packages are loaded from the committed D1
//! record, opened with the already configured recipient key, and reduced to a
//! private scalar that remains inside the SigningWorker material journal.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use router_ab_core::{
    Ed25519YaoDeriverRoleV1, Ed25519YaoEncryptedPackageV1, Ed25519YaoLaneProtocolCommittedV1,
    Ed25519YaoPackageKindV1, MpcMaterialActivationRefKindV1, MpcMaterialActivationRefV1,
    RouterAbProtocolError, RouterAbProtocolErrorCode, RouterAbProtocolResult,
};
use router_ab_ed25519_yao::{
    ed25519_yao_lane_target_id_digest_v1, open_ed25519_yao_lane_recipient_package_v1,
    Ed25519YaoRecipientPrivateKeyV1,
};
use router_ab_ed25519_yao_protocol::{
    combine_lane_signing_worker_packages_v1, LaneDeriverASigningWorkerPackage,
    LaneDeriverBSigningWorkerPackage,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use worker::{Env, Method, Request, Response};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::hpke::cloudflare_hpke_x25519_public_key_bytes_v1;
use crate::{
    cloudflare_now_unix_ms_v1, cloudflare_router_error_status,
    execute_cloudflare_signing_worker_lane_material_command_v1,
    load_cloudflare_server_output_hpke_private_key_bytes_v1,
    load_cloudflare_signing_worker_lane_material_record_by_operation_v1,
    CloudflareSigningWorkerLaneArtifactKindV1, CloudflareSigningWorkerLaneArtifactV1,
    CloudflareSigningWorkerLaneCommittedArtifactsV1, CloudflareSigningWorkerLaneHolderDeliveryV1,
    CloudflareSigningWorkerLaneKeyFamilyV1, CloudflareSigningWorkerLaneMaterialCommandV1,
    CloudflareSigningWorkerLaneMaterialEffectV1, CloudflareSigningWorkerLaneMaterialIdentityV1,
    CloudflareSigningWorkerLaneMaterialRecordV1, CloudflareSigningWorkerLaneServerActivationV1,
    CloudflareSigningWorkerRuntimeV1,
};

const ED25519_ACTIVE_SERVER_MATERIAL_KIND_V1: &str = "ed25519_yao_lane_active_server_material_v1";

/// Public request for one exact Ed25519 Yao lane activation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CloudflareSigningWorkerEd25519LaneActivateRequestV1 {
    pub identity: CloudflareSigningWorkerLaneMaterialIdentityV1,
    #[serde(with = "MpcMaterialActivationRefWireV1")]
    pub target_material_activation: MpcMaterialActivationRefV1,
    pub holder_delivery_receipt: CloudflareSigningWorkerEd25519LaneHolderDeliveryReceiptV1,
}

/// Holder acknowledgement accepted by the Ed25519 lane activation boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CloudflareSigningWorkerEd25519LaneHolderDeliveryReceiptV1 {
    pub kind: String,
    pub operation_id: String,
    pub enrollment_id: String,
    pub target_lane_id: String,
    pub target_lane_share_epoch: String,
    pub target_material_activation_id: String,
    pub holder_participant_binding_digest_b64u: String,
    pub holder_recipient_key_digest_b64u: String,
    pub holder_ciphertext_digest_set_b64u: String,
    pub sealed_holder_record_digest_b64u: String,
    pub transcript_hash_b64u: String,
    pub acknowledged_at_ms: u64,
}

/// Receipt-only response for one applied or replayed activation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "outcome",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum CloudflareSigningWorkerEd25519LaneActivateEffectV1 {
    Applied {
        receipt: CloudflareEd25519LaneServerActivationReceiptV1,
    },
    Replayed {
        receipt: CloudflareEd25519LaneServerActivationReceiptV1,
    },
}

/// Product-facing public activation receipt. The active scalar never crosses
/// this response boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CloudflareEd25519LaneServerActivationReceiptV1 {
    pub kind: String,
    pub operation_id: String,
    pub enrollment_id: String,
    pub target_lane_id: String,
    pub target_lane_share_epoch: String,
    #[serde(with = "MpcMaterialActivationRefWireV1")]
    pub target_material_activation: MpcMaterialActivationRefV1,
    pub signing_worker_participant_binding_digest_b64u: String,
    pub server_ciphertext_digest_set_b64u: String,
    pub transcript_hash_b64u: String,
    pub activated_at_ms: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(
    remote = "MpcMaterialActivationRefV1",
    rename_all = "camelCase",
    deny_unknown_fields
)]
struct MpcMaterialActivationRefWireV1 {
    kind: MpcMaterialActivationRefKindV1,
    activation_id: String,
    capability: String,
    material_owner: String,
    key_binding: String,
    lifecycle_binding: String,
    signing_worker: String,
}

/// Private scalar artifact retained by the generic lane material journal.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CloudflareEd25519LaneActiveServerMaterialV1 {
    pub kind: String,
    pub signing_worker_scalar_b64u: String,
}

impl core::fmt::Debug for CloudflareEd25519LaneActiveServerMaterialV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("CloudflareEd25519LaneActiveServerMaterialV1")
            .field("kind", &self.kind)
            .field("signing_worker_scalar_b64u", &"[REDACTED]")
            .finish()
    }
}

impl CloudflareEd25519LaneActiveServerMaterialV1 {
    fn new(scalar: [u8; 32]) -> Self {
        Self {
            kind: ED25519_ACTIVE_SERVER_MATERIAL_KIND_V1.to_owned(),
            signing_worker_scalar_b64u: URL_SAFE_NO_PAD.encode(scalar),
        }
    }

    /// Decodes the private lane scalar for in-process signing only.
    pub fn scalar32(&self) -> RouterAbProtocolResult<Zeroizing<[u8; 32]>> {
        if self.kind != ED25519_ACTIVE_SERVER_MATERIAL_KIND_V1 {
            return Err(invalid("Ed25519 active server material kind is invalid"));
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(&self.signing_worker_scalar_b64u)
            .map_err(|_| invalid("Ed25519 active server scalar is invalid"))?;
        let scalar: [u8; 32] = bytes
            .try_into()
            .map_err(|_| invalid("Ed25519 active server scalar must contain 32 bytes"))?;
        Ok(Zeroizing::new(scalar))
    }
}

fn invalid(message: impl Into<String>) -> RouterAbProtocolError {
    RouterAbProtocolError::new(RouterAbProtocolErrorCode::MalformedWirePayload, message)
}

fn map_protocol_error(
    context: &'static str,
    error: RouterAbProtocolError,
) -> RouterAbProtocolError {
    RouterAbProtocolError::new(error.code(), format!("{context}: {}", error.message()))
}

fn decode_digest(label: &'static str, value: &str) -> RouterAbProtocolResult<[u8; 32]> {
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| invalid(format!("{label} is not unpadded base64url")))?;
    decoded
        .try_into()
        .map_err(|_| invalid(format!("{label} must be a 32-byte digest")))
}

fn constant_time_equal(left: &[u8; 32], right: &[u8; 32]) -> bool {
    let mut difference = 0_u8;
    for index in 0..32 {
        difference |= left[index] ^ right[index];
    }
    difference == 0
}

fn decode_artifact_bytes(
    artifact: &CloudflareSigningWorkerLaneArtifactV1,
    kind: CloudflareSigningWorkerLaneArtifactKindV1,
) -> RouterAbProtocolResult<Zeroizing<Vec<u8>>> {
    artifact.validate_kind(kind)?;
    URL_SAFE_NO_PAD
        .decode(&artifact.payload_b64u)
        .map(Zeroizing::new)
        .map_err(|_| invalid("SigningWorker Ed25519 lane artifact payload is invalid"))
}

fn parse_artifact<T: DeserializeOwned>(
    artifact: &CloudflareSigningWorkerLaneArtifactV1,
    kind: CloudflareSigningWorkerLaneArtifactKindV1,
) -> RouterAbProtocolResult<T> {
    serde_json::from_slice(&decode_artifact_bytes(artifact, kind)?)
        .map_err(|_| invalid("SigningWorker Ed25519 lane artifact has invalid JSON"))
}

fn json_artifact<T: Serialize>(
    kind: CloudflareSigningWorkerLaneArtifactKindV1,
    value: &T,
) -> RouterAbProtocolResult<CloudflareSigningWorkerLaneArtifactV1> {
    let bytes = serde_json::to_vec(value)
        .map_err(|_| invalid("SigningWorker Ed25519 lane artifact could not be serialized"))?;
    CloudflareSigningWorkerLaneArtifactV1::from_bytes(kind, &bytes)
}

fn committed_artifacts(
    record: &CloudflareSigningWorkerLaneMaterialRecordV1,
) -> RouterAbProtocolResult<(
    &CloudflareSigningWorkerLaneArtifactV1,
    &CloudflareSigningWorkerLaneArtifactV1,
    &CloudflareSigningWorkerLaneArtifactV1,
    &CloudflareSigningWorkerLaneArtifactV1,
)> {
    match &record.committed_artifacts {
        CloudflareSigningWorkerLaneCommittedArtifactsV1::Ed25519Yao {
            holder_package,
            signing_worker_package,
            protocol_commit_receipt,
            transcript,
        } => Ok((
            holder_package,
            signing_worker_package,
            protocol_commit_receipt,
            transcript,
        )),
        CloudflareSigningWorkerLaneCommittedArtifactsV1::EcdsaAdditive { .. } => Err(invalid(
            "SigningWorker lane operation is committed for another curve",
        )),
    }
}

fn validate_identity(
    identity: &CloudflareSigningWorkerLaneMaterialIdentityV1,
) -> RouterAbProtocolResult<()> {
    identity.validate()?;
    if identity.key_family != CloudflareSigningWorkerLaneKeyFamilyV1::Ed25519 {
        return Err(invalid(
            "SigningWorker Ed25519 activation identity has the wrong curve",
        ));
    }
    Ok(())
}

fn validate_recipient_key(
    identity: &CloudflareSigningWorkerLaneMaterialIdentityV1,
    runtime: &CloudflareSigningWorkerRuntimeV1,
) -> RouterAbProtocolResult<()> {
    let binding = runtime.server_output_decrypt_key();
    let configured = cloudflare_hpke_x25519_public_key_bytes_v1(&binding.public_key)?;
    let admitted_digest = decode_digest(
        "Ed25519 target SigningWorker public-key digest",
        &identity.server_recipient_key_digest_b64u,
    )?;
    let configured_digest: [u8; 32] = Sha256::digest(configured).into();
    if !constant_time_equal(&configured_digest, &admitted_digest) {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "Ed25519 lane recipient does not match the active SigningWorker key",
        ));
    }
    Ok(())
}

fn validate_holder_delivery(
    identity: &CloudflareSigningWorkerLaneMaterialIdentityV1,
    protocol: &Ed25519YaoLaneProtocolCommittedV1,
    holder: &CloudflareSigningWorkerEd25519LaneHolderDeliveryReceiptV1,
) -> RouterAbProtocolResult<()> {
    if holder.kind != "lane_holder_delivery_receipt_v1"
        || holder.operation_id != identity.operation_id
        || holder.enrollment_id != identity.enrollment_id
        || holder.target_lane_id != identity.target_lane_id
        || holder.target_lane_share_epoch != identity.target_lane_share_epoch
        || holder.target_material_activation_id != identity.target_material_activation_id
        || holder.holder_participant_binding_digest_b64u
            != identity.holder_participant_binding_digest_b64u
        || holder.holder_recipient_key_digest_b64u != identity.holder_recipient_key_digest_b64u
        || holder.holder_ciphertext_digest_set_b64u
            != protocol.target_holder_ciphertext_digest_set_b64u
        || holder.transcript_hash_b64u != identity.transcript_hash_b64u
        || holder.acknowledged_at_ms < protocol.committed_at_ms
    {
        return Err(invalid(
            "Ed25519 holder delivery does not match committed private material",
        ));
    }
    decode_digest(
        "holder_delivery.sealed_holder_record_digest_b64u",
        &holder.sealed_holder_record_digest_b64u,
    )?;
    Ok(())
}

fn validate_protocol_identity(
    identity: &CloudflareSigningWorkerLaneMaterialIdentityV1,
    protocol: &Ed25519YaoLaneProtocolCommittedV1,
) -> RouterAbProtocolResult<()> {
    protocol.validate()?;
    if protocol.operation_id != identity.operation_id
        || protocol.enrollment_id != identity.enrollment_id
        || protocol.wallet_id != identity.wallet_id
        || protocol.wallet_key_id != identity.wallet_key_id
        || protocol.target_lane_id != identity.target_lane_id
        || protocol.target_lane_share_epoch != identity.target_lane_share_epoch
        || protocol.target_material_activation_id != identity.target_material_activation_id
        || protocol.key_family != "ed25519"
        || protocol.holder_recipient_key_digest_b64u != identity.holder_recipient_key_digest_b64u
        || protocol.server_recipient_key_digest_b64u != identity.server_recipient_key_digest_b64u
        || protocol.transcript_hash_b64u != identity.transcript_hash_b64u
    {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ReplayedLocalRequest,
            "Ed25519 activation identity does not match committed protocol receipt",
        ));
    }
    Ok(())
}

fn decode_and_combine_server_packages(
    identity: &CloudflareSigningWorkerLaneMaterialIdentityV1,
    worker_package_artifact: &CloudflareSigningWorkerLaneArtifactV1,
    expected_ciphertext_digest_b64u: &str,
    private_key: &Ed25519YaoRecipientPrivateKeyV1,
) -> RouterAbProtocolResult<Zeroizing<[u8; 32]>> {
    let packages: (Ed25519YaoEncryptedPackageV1, Ed25519YaoEncryptedPackageV1) = parse_artifact(
        worker_package_artifact,
        CloudflareSigningWorkerLaneArtifactKindV1::SigningWorkerPackage,
    )?;
    let session = packages.0.session();
    let transcript = packages.0.transcript();
    let expected_transcript = decode_digest(
        "identity.transcript_hash_b64u",
        &identity.transcript_hash_b64u,
    )?;
    if packages.0.kind() != Ed25519YaoPackageKindV1::LaneSigningWorker
        || packages.1.kind() != Ed25519YaoPackageKindV1::LaneSigningWorker
        || packages.0.deriver() != Ed25519YaoDeriverRoleV1::DeriverA
        || packages.1.deriver() != Ed25519YaoDeriverRoleV1::DeriverB
        || packages.1.session() != session
        || packages.1.transcript() != transcript
        || transcript != expected_transcript
    {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ReplayedLocalRequest,
            "Ed25519 SigningWorker package binding does not match committed material",
        ));
    }
    let expected_ciphertext_digest = decode_digest(
        "protocol.target_server_ciphertext_digest_set_b64u",
        expected_ciphertext_digest_b64u,
    )?;
    let actual_ciphertext_digest: [u8; 32] = Sha256::new()
        .chain_update(b"seams/rotatable-signing-lanes/ed25519-ciphertext-set/v1")
        .chain_update(b"signing-worker")
        .chain_update([packages.0.deriver().wire_tag()])
        .chain_update([packages.0.kind().wire_tag()])
        .chain_update(packages.0.encapsulated_key())
        .chain_update(packages.0.ciphertext())
        .chain_update([packages.1.deriver().wire_tag()])
        .chain_update([packages.1.kind().wire_tag()])
        .chain_update(packages.1.encapsulated_key())
        .chain_update(packages.1.ciphertext())
        .finalize()
        .into();
    if !constant_time_equal(&actual_ciphertext_digest, &expected_ciphertext_digest) {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ReplayedLocalRequest,
            "Ed25519 SigningWorker package digest does not match the committed receipt",
        ));
    }
    let target_lane_digest = ed25519_yao_lane_target_id_digest_v1(&identity.target_lane_id)
        .map_err(|error| map_protocol_error("Ed25519 target lane identity is invalid", error))?;
    let mut a_plaintext = open_ed25519_yao_lane_recipient_package_v1(
        &packages.0,
        private_key,
        Ed25519YaoPackageKindV1::LaneSigningWorker,
        Ed25519YaoDeriverRoleV1::DeriverA,
        session,
        transcript,
        target_lane_digest,
    )
    .map_err(|error| map_protocol_error("Ed25519 Deriver A package open failed", error))?;
    let mut b_plaintext = open_ed25519_yao_lane_recipient_package_v1(
        &packages.1,
        private_key,
        Ed25519YaoPackageKindV1::LaneSigningWorker,
        Ed25519YaoDeriverRoleV1::DeriverB,
        session,
        transcript,
        target_lane_digest,
    )
    .map_err(|error| map_protocol_error("Ed25519 Deriver B package open failed", error))?;
    let a_package =
        LaneDeriverASigningWorkerPackage::from_bytes(core::mem::take(&mut *a_plaintext))
            .map_err(|_| invalid("Ed25519 Deriver A package plaintext is invalid"))?;
    let b_package =
        LaneDeriverBSigningWorkerPackage::from_bytes(core::mem::take(&mut *b_plaintext))
            .map_err(|_| invalid("Ed25519 Deriver B package plaintext is invalid"))?;
    let scalar = combine_lane_signing_worker_packages_v1(session, transcript, a_package, b_package)
        .map_err(|_| invalid("Ed25519 SigningWorker package combination failed"))?
        .into_bytes();
    Ok(Zeroizing::new(scalar))
}

/// Activates one committed Ed25519 lane using private D1 state.
pub async fn activate_cloudflare_signing_worker_ed25519_lane_v1(
    env: &Env,
    runtime: &CloudflareSigningWorkerRuntimeV1,
    request: &CloudflareSigningWorkerEd25519LaneActivateRequestV1,
    activated_at_ms: u64,
) -> RouterAbProtocolResult<CloudflareSigningWorkerEd25519LaneActivateEffectV1> {
    validate_identity(&request.identity)?;
    request.target_material_activation.validate()?;
    if request.target_material_activation.activation_id
        != request.identity.target_material_activation_id
        || request.target_material_activation.signing_worker.is_empty()
    {
        return Err(invalid(
            "Ed25519 target material activation does not match the admitted identity",
        ));
    }
    let record = load_cloudflare_signing_worker_lane_material_record_by_operation_v1(
        env,
        &request.identity.operation_id,
    )
    .await?
    .ok_or_else(|| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MissingLocalBinding,
            "SigningWorker Ed25519 lane commitment is missing",
        )
    })?;
    let expected_identity = decode_digest(
        "Ed25519 activation expected identity",
        &request.identity.digest_b64u()?,
    )?;
    let stored_identity = decode_digest(
        "Ed25519 activation stored identity",
        &record.identity.digest_b64u()?,
    )?;
    if !constant_time_equal(&expected_identity, &stored_identity)
        || record.identity != request.identity
    {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ReplayedLocalRequest,
            "Ed25519 activation identity does not match committed material",
        ));
    }
    let (_, worker_package, protocol_receipt_artifact, _) = committed_artifacts(&record)?;
    let protocol: Ed25519YaoLaneProtocolCommittedV1 = parse_artifact(
        protocol_receipt_artifact,
        CloudflareSigningWorkerLaneArtifactKindV1::ProtocolCommitReceipt,
    )?;
    validate_protocol_identity(&request.identity, &protocol)?;
    validate_holder_delivery(
        &request.identity,
        &protocol,
        &request.holder_delivery_receipt,
    )?;
    validate_recipient_key(&request.identity, runtime)?;
    let mut private_key_bytes =
        Zeroizing::new(load_cloudflare_server_output_hpke_private_key_bytes_v1(
            env,
            runtime.server_output_decrypt_key(),
        )?);
    let private_key = Ed25519YaoRecipientPrivateKeyV1::from_bytes(*private_key_bytes);
    private_key_bytes.zeroize();
    let scalar = decode_and_combine_server_packages(
        &request.identity,
        worker_package,
        &protocol.target_server_ciphertext_digest_set_b64u,
        &private_key,
    )?;
    let active = CloudflareEd25519LaneActiveServerMaterialV1::new(*scalar);
    let active_artifact = json_artifact(
        CloudflareSigningWorkerLaneArtifactKindV1::ActiveServerMaterial,
        &active,
    )?;
    let holder_receipt_artifact = json_artifact(
        CloudflareSigningWorkerLaneArtifactKindV1::HolderDeliveryReceipt,
        &request.holder_delivery_receipt,
    )?;
    let holder_command = CloudflareSigningWorkerLaneMaterialCommandV1::RecordHolderDelivery {
        identity: request.identity.clone(),
        holder_delivery: CloudflareSigningWorkerLaneHolderDeliveryV1 {
            receipt: holder_receipt_artifact.clone(),
            acknowledged_at_ms: request.holder_delivery_receipt.acknowledged_at_ms,
        },
    };
    execute_cloudflare_signing_worker_lane_material_command_v1(env, &holder_command).await?;
    let activation_receipt = CloudflareEd25519LaneServerActivationReceiptV1 {
        kind: "lane_server_activation_receipt_v1".to_owned(),
        operation_id: request.identity.operation_id.clone(),
        enrollment_id: request.identity.enrollment_id.clone(),
        target_lane_id: request.identity.target_lane_id.clone(),
        target_lane_share_epoch: request.identity.target_lane_share_epoch.clone(),
        target_material_activation: request.target_material_activation.clone(),
        signing_worker_participant_binding_digest_b64u: request
            .identity
            .signing_worker_participant_binding_digest_b64u
            .clone(),
        server_ciphertext_digest_set_b64u: protocol.target_server_ciphertext_digest_set_b64u,
        transcript_hash_b64u: request.identity.transcript_hash_b64u.clone(),
        activated_at_ms,
    };
    let activation_receipt_artifact = json_artifact(
        CloudflareSigningWorkerLaneArtifactKindV1::ServerActivationReceipt,
        &activation_receipt,
    )?;
    let command = CloudflareSigningWorkerLaneMaterialCommandV1::ActivateServerMaterial {
        identity: request.identity.clone(),
        expected_holder_delivery_receipt: holder_receipt_artifact,
        server_activation: CloudflareSigningWorkerLaneServerActivationV1 {
            active_server_material: active_artifact,
            receipt: activation_receipt_artifact,
            activated_at_ms,
        },
    };
    match execute_cloudflare_signing_worker_lane_material_command_v1(env, &command).await? {
        CloudflareSigningWorkerLaneMaterialEffectV1::ServerMaterialActivated {
            changed: true,
            ..
        } => Ok(
            CloudflareSigningWorkerEd25519LaneActivateEffectV1::Applied {
                receipt: activation_receipt,
            },
        ),
        CloudflareSigningWorkerLaneMaterialEffectV1::ServerMaterialActivated {
            changed: false,
            ..
        } => Ok(
            CloudflareSigningWorkerEd25519LaneActivateEffectV1::Replayed {
                receipt: activation_receipt,
            },
        ),
        _ => Err(invalid(
            "SigningWorker returned the wrong Ed25519 activation effect",
        )),
    }
}

fn protocol_error_response(error: RouterAbProtocolError) -> worker::Result<Response> {
    Response::error(
        format!("{:?}: {}", error.code(), error.message()),
        cloudflare_router_error_status(error.code()),
    )
}

/// Private authenticated fetch handler. Authentication is enforced by the
/// strict SigningWorker dispatcher before this body is parsed.
pub async fn handle_cloudflare_signing_worker_ed25519_lane_activate_private_fetch_v1(
    mut request: Request,
    env: &Env,
    runtime: &CloudflareSigningWorkerRuntimeV1,
) -> worker::Result<Response> {
    if request.method() != Method::Post {
        return Response::error("method not allowed", 405);
    }
    let input = match request
        .json::<CloudflareSigningWorkerEd25519LaneActivateRequestV1>()
        .await
    {
        Ok(input) => input,
        Err(_) => return Response::error("invalid Ed25519 lane activation request", 400),
    };
    let now = match cloudflare_now_unix_ms_v1() {
        Ok(now) => now,
        Err(error) => return protocol_error_response(error),
    };
    match activate_cloudflare_signing_worker_ed25519_lane_v1(env, runtime, &input, now).await {
        Ok(effect) => Response::from_json(&effect),
        Err(error) => protocol_error_response(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

    fn digest(byte: u8) -> String {
        URL_SAFE_NO_PAD.encode([byte; 32])
    }

    fn identity() -> CloudflareSigningWorkerLaneMaterialIdentityV1 {
        CloudflareSigningWorkerLaneMaterialIdentityV1 {
            operation_id: "operation".to_owned(),
            enrollment_id: "enrollment".to_owned(),
            wallet_id: "wallet".to_owned(),
            wallet_key_id: "wallet-key".to_owned(),
            target_lane_id: "target-lane".to_owned(),
            target_lane_share_epoch: "epoch".to_owned(),
            target_material_activation_id: "target-activation".to_owned(),
            key_family: CloudflareSigningWorkerLaneKeyFamilyV1::Ed25519,
            holder_participant_binding_digest_b64u: digest(1),
            signing_worker_participant_binding_digest_b64u: digest(2),
            holder_recipient_key_digest_b64u: digest(3),
            server_recipient_key_digest_b64u: digest(4),
            transcript_hash_b64u: digest(5),
            protocol_commit_receipt_digest_b64u: digest(6),
        }
    }

    #[test]
    fn active_server_material_zeroizes_on_drop_and_redacts_debug() {
        assert_zeroize_on_drop::<CloudflareEd25519LaneActiveServerMaterialV1>();
        let material = CloudflareEd25519LaneActiveServerMaterialV1::new([42; 32]);
        let debug = format!("{material:?}");

        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains(&material.signing_worker_scalar_b64u));
    }

    #[test]
    fn package_ciphertext_digest_substitution_is_rejected_before_open() {
        let session = [7; 32];
        let transcript = [8; 32];
        let deriver_a = Ed25519YaoEncryptedPackageV1::new(
            Ed25519YaoPackageKindV1::LaneSigningWorker,
            Ed25519YaoDeriverRoleV1::DeriverA,
            session,
            transcript,
            [9; 32],
            vec![10; 16],
        )
        .expect("Deriver A package");
        let deriver_b = Ed25519YaoEncryptedPackageV1::new(
            Ed25519YaoPackageKindV1::LaneSigningWorker,
            Ed25519YaoDeriverRoleV1::DeriverB,
            session,
            transcript,
            [11; 32],
            vec![12; 16],
        )
        .expect("Deriver B package");
        let artifact = CloudflareSigningWorkerLaneArtifactV1::from_bytes(
            CloudflareSigningWorkerLaneArtifactKindV1::SigningWorkerPackage,
            &serde_json::to_vec(&(deriver_a, deriver_b)).expect("package set JSON"),
        )
        .expect("package artifact");
        let private_key = Ed25519YaoRecipientPrivateKeyV1::from_bytes([13; 32]);
        let error =
            decode_and_combine_server_packages(&identity(), &artifact, &digest(99), &private_key)
                .expect_err("substituted ciphertext digest must be rejected");
        assert_eq!(
            error.code(),
            RouterAbProtocolErrorCode::ReplayedLocalRequest
        );
    }
}
