//! Exact private retirement for one Ed25519 Yao lane epoch.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use router_ab_core::{RouterAbProtocolError, RouterAbProtocolErrorCode, RouterAbProtocolResult};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use worker::{Env, Method, Request, Response};
use zeroize::Zeroizing;

use crate::{
    cloudflare_now_unix_ms_v1, cloudflare_router_error_status,
    execute_cloudflare_signing_worker_lane_material_command_v1,
    load_cloudflare_signing_worker_lane_material_record_by_operation_v1,
    CloudflareSigningWorkerLaneArtifactKindV1, CloudflareSigningWorkerLaneArtifactV1,
    CloudflareSigningWorkerLaneKeyFamilyV1, CloudflareSigningWorkerLaneMaterialCommandV1,
    CloudflareSigningWorkerLaneMaterialEffectV1, CloudflareSigningWorkerLaneMaterialIdentityV1,
    CloudflareSigningWorkerLaneMaterialLifecycleV1, CloudflareSigningWorkerLaneMaterialRecordV1,
    CloudflareSigningWorkerLaneRetirementReasonV1, CloudflareSigningWorkerLaneRetirementV1,
};

const RECEIPT_DOMAIN_V1: &str = "seams/rotatable-signing-lanes/ed25519-retirement-receipt/v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CloudflareSigningWorkerEd25519LaneRetireRequestV1 {
    pub identity: CloudflareSigningWorkerLaneMaterialIdentityV1,
    pub revocation_epoch: u64,
    pub retirement_reason: String,
    pub retirement_correlation_id: String,
    pub retirement_request_digest_b64u: String,
    pub retirement_effect_binding_digest_b64u: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Ed25519ServerRetirementReceiptV1 {
    pub kind: String,
    pub identity: CloudflareSigningWorkerLaneMaterialIdentityV1,
    pub revocation_epoch: u64,
    pub retirement_reason: String,
    pub retirement_correlation_id: String,
    pub retirement_request_digest_b64u: String,
    pub receipt_digest_b64u: String,
    pub retired_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "outcome",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum CloudflareSigningWorkerEd25519LaneRetireEffectV1 {
    Applied {
        receipt: Ed25519ServerRetirementReceiptV1,
    },
    Replayed {
        receipt: Ed25519ServerRetirementReceiptV1,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StoredEd25519RetirementV1 {
    receipt: Ed25519ServerRetirementReceiptV1,
    retirement_effect_binding_digest_b64u: String,
}

fn invalid(message: impl Into<String>) -> RouterAbProtocolError {
    RouterAbProtocolError::new(RouterAbProtocolErrorCode::MalformedWirePayload, message)
}

fn decode_digest(label: &str, value: &str) -> RouterAbProtocolResult<[u8; 32]> {
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| invalid(format!("{label} is not unpadded base64url")))?
        .try_into()
        .map_err(|_| invalid(format!("{label} must contain 32 bytes")))
}

fn constant_time_equal(left: &[u8; 32], right: &[u8; 32]) -> bool {
    let mut difference = 0_u8;
    for index in 0..32 {
        difference |= left[index] ^ right[index];
    }
    difference == 0
}

fn push_text(bytes: &mut Vec<u8>, value: &str) -> RouterAbProtocolResult<()> {
    let length = u32::try_from(value.len()).map_err(|_| invalid("receipt text is too long"))?;
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(value.as_bytes());
    Ok(())
}

fn push_digest(bytes: &mut Vec<u8>, label: &str, value: &str) -> RouterAbProtocolResult<()> {
    let digest = decode_digest(label, value)?;
    bytes.extend_from_slice(&32_u32.to_be_bytes());
    bytes.extend_from_slice(&digest);
    Ok(())
}

fn identity_family_name(value: CloudflareSigningWorkerLaneKeyFamilyV1) -> &'static str {
    match value {
        CloudflareSigningWorkerLaneKeyFamilyV1::Ed25519 => "ed25519",
        CloudflareSigningWorkerLaneKeyFamilyV1::EcdsaSecp256k1 => "ecdsa_secp256k1",
    }
}

impl Ed25519ServerRetirementReceiptV1 {
    fn canonical_payload(&self) -> RouterAbProtocolResult<Zeroizing<Vec<u8>>> {
        let mut bytes = Vec::new();
        push_text(&mut bytes, RECEIPT_DOMAIN_V1)?;
        push_text(&mut bytes, &self.kind)?;
        for value in [
            self.identity.operation_id.as_str(),
            self.identity.enrollment_id.as_str(),
            self.identity.wallet_id.as_str(),
            self.identity.wallet_key_id.as_str(),
            self.identity.target_lane_id.as_str(),
            self.identity.target_lane_share_epoch.as_str(),
            self.identity.target_material_activation_id.as_str(),
            identity_family_name(self.identity.key_family),
        ] {
            push_text(&mut bytes, value)?;
        }
        for (label, value) in [
            (
                "holder participant binding digest",
                self.identity
                    .holder_participant_binding_digest_b64u
                    .as_str(),
            ),
            (
                "SigningWorker participant binding digest",
                self.identity
                    .signing_worker_participant_binding_digest_b64u
                    .as_str(),
            ),
            (
                "holder recipient key digest",
                self.identity.holder_recipient_key_digest_b64u.as_str(),
            ),
            (
                "server recipient key digest",
                self.identity.server_recipient_key_digest_b64u.as_str(),
            ),
            (
                "transcript digest",
                self.identity.transcript_hash_b64u.as_str(),
            ),
            (
                "protocol receipt digest",
                self.identity.protocol_commit_receipt_digest_b64u.as_str(),
            ),
        ] {
            push_digest(&mut bytes, label, value)?;
        }
        bytes.extend_from_slice(&self.revocation_epoch.to_be_bytes());
        push_text(&mut bytes, &self.retirement_reason)?;
        push_text(&mut bytes, &self.retirement_correlation_id)?;
        push_digest(
            &mut bytes,
            "retirement request digest",
            &self.retirement_request_digest_b64u,
        )?;
        bytes.extend_from_slice(&self.retired_at_ms.to_be_bytes());
        Ok(Zeroizing::new(bytes))
    }

    fn digest_b64u(&self) -> RouterAbProtocolResult<String> {
        Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(self.canonical_payload()?.as_slice())))
    }
}

fn retirement_reason(
    value: &str,
) -> RouterAbProtocolResult<CloudflareSigningWorkerLaneRetirementReasonV1> {
    match value {
        "lane_revoked" => Ok(CloudflareSigningWorkerLaneRetirementReasonV1::LaneRevoked),
        "device_compromise" => Ok(CloudflareSigningWorkerLaneRetirementReasonV1::DeviceCompromise),
        "agent_compromise" => Ok(CloudflareSigningWorkerLaneRetirementReasonV1::AgentCompromise),
        "rotation" => Ok(CloudflareSigningWorkerLaneRetirementReasonV1::Rotation),
        _ => Err(invalid("Ed25519 retirement reason is invalid")),
    }
}

fn receipt_matches_request(
    receipt: &Ed25519ServerRetirementReceiptV1,
    request: &CloudflareSigningWorkerEd25519LaneRetireRequestV1,
) -> RouterAbProtocolResult<()> {
    let claimed = decode_digest(
        "Ed25519 retirement receipt digest",
        &receipt.receipt_digest_b64u,
    )?;
    let computed = decode_digest(
        "Ed25519 retirement computed digest",
        &receipt.digest_b64u()?,
    )?;
    if receipt.kind != "ed25519_server_retirement_receipt_v1"
        || receipt.identity != request.identity
        || receipt.revocation_epoch != request.revocation_epoch
        || receipt.retirement_reason != request.retirement_reason
        || receipt.retirement_correlation_id != request.retirement_correlation_id
        || receipt.retirement_request_digest_b64u != request.retirement_request_digest_b64u
        || !constant_time_equal(&claimed, &computed)
    {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ReplayedLocalRequest,
            "Ed25519 retirement receipt differs from the authorized request",
        ));
    }
    Ok(())
}

fn retirement_from_record(
    record: &CloudflareSigningWorkerLaneMaterialRecordV1,
) -> Option<&CloudflareSigningWorkerLaneRetirementV1> {
    match &record.lifecycle {
        CloudflareSigningWorkerLaneMaterialLifecycleV1::RetiredBeforeHolderDelivery {
            retirement,
            ..
        }
        | CloudflareSigningWorkerLaneMaterialLifecycleV1::RetiredAfterHolderDelivery {
            retirement,
            ..
        }
        | CloudflareSigningWorkerLaneMaterialLifecycleV1::RetiredAfterActivation {
            retirement,
            ..
        } => Some(retirement),
        _ => None,
    }
}

fn parse_stored_retirement(
    retirement: &CloudflareSigningWorkerLaneRetirementV1,
) -> RouterAbProtocolResult<StoredEd25519RetirementV1> {
    retirement
        .receipt
        .validate_kind(CloudflareSigningWorkerLaneArtifactKindV1::RetirementReceipt)?;
    let bytes = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(&retirement.receipt.payload_b64u)
            .map_err(|_| invalid("Ed25519 retirement artifact payload is invalid"))?,
    );
    serde_json::from_slice(bytes.as_slice())
        .map_err(|_| invalid("Ed25519 retirement artifact JSON is invalid"))
}

fn retirement_artifact(
    value: &StoredEd25519RetirementV1,
) -> RouterAbProtocolResult<CloudflareSigningWorkerLaneArtifactV1> {
    let bytes = Zeroizing::new(
        serde_json::to_vec(value)
            .map_err(|_| invalid("Ed25519 retirement artifact could not be serialized"))?,
    );
    CloudflareSigningWorkerLaneArtifactV1::from_bytes(
        CloudflareSigningWorkerLaneArtifactKindV1::RetirementReceipt,
        bytes.as_slice(),
    )
}

pub async fn retire_cloudflare_signing_worker_ed25519_lane_v1(
    env: &Env,
    request: &CloudflareSigningWorkerEd25519LaneRetireRequestV1,
    retired_at_ms: u64,
) -> RouterAbProtocolResult<CloudflareSigningWorkerEd25519LaneRetireEffectV1> {
    request.identity.validate()?;
    if request.identity.key_family != CloudflareSigningWorkerLaneKeyFamilyV1::Ed25519 {
        return Err(invalid(
            "Ed25519 retirement identity has the wrong key family",
        ));
    }
    decode_digest(
        "Ed25519 retirement request digest",
        &request.retirement_request_digest_b64u,
    )?;
    let requested_effect_binding = decode_digest(
        "Ed25519 retirement effect binding",
        &request.retirement_effect_binding_digest_b64u,
    )?;
    let record = load_cloudflare_signing_worker_lane_material_record_by_operation_v1(
        env,
        &request.identity.operation_id,
    )
    .await?
    .ok_or_else(|| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MissingLocalBinding,
            "SigningWorker Ed25519 lane retirement target is missing",
        )
    })?;
    let expected_identity = decode_digest(
        "Ed25519 expected identity",
        &request.identity.digest_b64u()?,
    )?;
    let stored_identity =
        decode_digest("Ed25519 stored identity", &record.identity.digest_b64u()?)?;
    if !constant_time_equal(&expected_identity, &stored_identity)
        || request.identity != record.identity
    {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ReplayedLocalRequest,
            "Ed25519 retirement identity does not match committed material",
        ));
    }
    if let Some(retirement) = retirement_from_record(&record) {
        let stored = parse_stored_retirement(retirement)?;
        let stored_effect_binding = decode_digest(
            "Ed25519 stored retirement effect binding",
            &stored.retirement_effect_binding_digest_b64u,
        )?;
        if !constant_time_equal(&requested_effect_binding, &stored_effect_binding) {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ReplayedLocalRequest,
                "Ed25519 retirement replay changed the authorized effect binding",
            ));
        }
        receipt_matches_request(&stored.receipt, request)?;
        return Ok(CloudflareSigningWorkerEd25519LaneRetireEffectV1::Replayed {
            receipt: stored.receipt,
        });
    }

    let mut receipt = Ed25519ServerRetirementReceiptV1 {
        kind: "ed25519_server_retirement_receipt_v1".to_owned(),
        identity: request.identity.clone(),
        revocation_epoch: request.revocation_epoch,
        retirement_reason: request.retirement_reason.clone(),
        retirement_correlation_id: request.retirement_correlation_id.clone(),
        retirement_request_digest_b64u: request.retirement_request_digest_b64u.clone(),
        receipt_digest_b64u: URL_SAFE_NO_PAD.encode([0_u8; 32]),
        retired_at_ms,
    };
    receipt.receipt_digest_b64u = receipt.digest_b64u()?;
    receipt_matches_request(&receipt, request)?;
    let command = CloudflareSigningWorkerLaneMaterialCommandV1::Retire {
        identity: request.identity.clone(),
        retirement: CloudflareSigningWorkerLaneRetirementV1 {
            revocation_epoch: request.revocation_epoch,
            reason: retirement_reason(&request.retirement_reason)?,
            correlation_id: request.retirement_correlation_id.clone(),
            request_digest_b64u: request.retirement_request_digest_b64u.clone(),
            receipt: retirement_artifact(&StoredEd25519RetirementV1 {
                receipt: receipt.clone(),
                retirement_effect_binding_digest_b64u: request
                    .retirement_effect_binding_digest_b64u
                    .clone(),
            })?,
            retired_at_ms,
        },
    };
    match execute_cloudflare_signing_worker_lane_material_command_v1(env, &command).await? {
        CloudflareSigningWorkerLaneMaterialEffectV1::Retired { changed: true, .. } => {
            Ok(CloudflareSigningWorkerEd25519LaneRetireEffectV1::Applied { receipt })
        }
        CloudflareSigningWorkerLaneMaterialEffectV1::Retired { changed: false, .. } => {
            Ok(CloudflareSigningWorkerEd25519LaneRetireEffectV1::Replayed { receipt })
        }
        _ => Err(invalid(
            "SigningWorker returned the wrong Ed25519 retirement effect",
        )),
    }
}

fn protocol_error_response(error: RouterAbProtocolError) -> worker::Result<Response> {
    Response::error(
        format!("{:?}: {}", error.code(), error.message()),
        cloudflare_router_error_status(error.code()),
    )
}

pub async fn handle_cloudflare_signing_worker_ed25519_lane_retire_private_fetch_v1(
    mut request: Request,
    env: &Env,
) -> worker::Result<Response> {
    if request.method() != Method::Post {
        return Response::error("method not allowed", 405);
    }
    let input = match request
        .json::<CloudflareSigningWorkerEd25519LaneRetireRequestV1>()
        .await
    {
        Ok(input) => input,
        Err(_) => return Response::error("invalid Ed25519 lane retirement request", 400),
    };
    let now = match cloudflare_now_unix_ms_v1() {
        Ok(now) => now,
        Err(error) => return protocol_error_response(error),
    };
    match retire_cloudflare_signing_worker_ed25519_lane_v1(env, &input, now).await {
        Ok(effect) => Response::from_json(&effect),
        Err(error) => protocol_error_response(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(value: u8) -> String {
        URL_SAFE_NO_PAD.encode([value; 32])
    }

    fn identity() -> CloudflareSigningWorkerLaneMaterialIdentityV1 {
        CloudflareSigningWorkerLaneMaterialIdentityV1 {
            operation_id: "operation-ed-retire".to_owned(),
            enrollment_id: "enrollment-ed-retire".to_owned(),
            wallet_id: "wallet-ed-retire".to_owned(),
            wallet_key_id: "wallet-key-ed-retire".to_owned(),
            target_lane_id: "lane-ed-retire".to_owned(),
            target_lane_share_epoch: "epoch-ed-retire".to_owned(),
            target_material_activation_id: "activation-ed-retire".to_owned(),
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
    fn retirement_receipt_digest_binds_identity_and_epoch() {
        let receipt = Ed25519ServerRetirementReceiptV1 {
            kind: "ed25519_server_retirement_receipt_v1".to_owned(),
            identity: identity(),
            revocation_epoch: 7,
            retirement_reason: "lane_revoked".to_owned(),
            retirement_correlation_id: "correlation-ed-retire".to_owned(),
            retirement_request_digest_b64u: digest(8),
            receipt_digest_b64u: digest(0),
            retired_at_ms: 9_000,
        };
        let digest = receipt.digest_b64u().expect("digest");
        assert_eq!(digest, "rEHBCD9-zcjh-AJaYGWpqHXEf0kexF32bOfXRMuMjEI");
        let mut substituted = receipt;
        substituted.revocation_epoch += 1;
        assert_ne!(
            digest,
            substituted.digest_b64u().expect("substituted digest")
        );
    }
}
