use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use router_ab_core::{RouterAbProtocolError, RouterAbProtocolErrorCode, RouterAbProtocolResult};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

const LANE_IDENTITY_DOMAIN_V1: &[u8] = b"seams/signing-worker/lane-material-identity/v1";

fn lane_error(
    code: RouterAbProtocolErrorCode,
    message: impl Into<String>,
) -> RouterAbProtocolError {
    RouterAbProtocolError::new(code, message)
}

fn require_text(field: &'static str, value: &str) -> RouterAbProtocolResult<()> {
    if value.is_empty() || value.bytes().any(|byte| !(0x21..=0x7e).contains(&byte)) {
        return Err(lane_error(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("SigningWorker lane {field} must contain visible ASCII bytes"),
        ));
    }
    Ok(())
}

fn decode_digest(field: &'static str, value: &str) -> RouterAbProtocolResult<[u8; 32]> {
    let decoded = URL_SAFE_NO_PAD.decode(value).map_err(|_| {
        lane_error(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("SigningWorker lane {field} is not unpadded base64url"),
        )
    })?;
    decoded.try_into().map_err(|_| {
        lane_error(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("SigningWorker lane {field} must be a 32-byte digest"),
        )
    })
}

fn constant_time_equal(left: &[u8; 32], right: &[u8; 32]) -> bool {
    let mut difference = 0_u8;
    for index in 0..32 {
        difference |= left[index] ^ right[index];
    }
    difference == 0
}

fn encode_text(bytes: &mut Vec<u8>, value: &str) {
    bytes.extend_from_slice(&(value.len() as u64).to_be_bytes());
    bytes.extend_from_slice(value.as_bytes());
}

/// Curve family for one private SigningWorker lane record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CloudflareSigningWorkerLaneKeyFamilyV1 {
    Ed25519,
    EcdsaSecp256k1,
}

impl CloudflareSigningWorkerLaneKeyFamilyV1 {
    fn wire_name(self) -> &'static str {
        match self {
            Self::Ed25519 => "ed25519",
            Self::EcdsaSecp256k1 => "ecdsa_secp256k1",
        }
    }
}

/// Exact public identity used by every private lane-material command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CloudflareSigningWorkerLaneMaterialIdentityV1 {
    pub operation_id: String,
    pub enrollment_id: String,
    pub wallet_id: String,
    pub wallet_key_id: String,
    pub target_lane_id: String,
    pub target_lane_share_epoch: String,
    pub target_material_activation_id: String,
    pub key_family: CloudflareSigningWorkerLaneKeyFamilyV1,
    pub holder_participant_binding_digest_b64u: String,
    pub signing_worker_participant_binding_digest_b64u: String,
    pub holder_recipient_key_digest_b64u: String,
    pub server_recipient_key_digest_b64u: String,
    pub transcript_hash_b64u: String,
    pub protocol_commit_receipt_digest_b64u: String,
}

impl CloudflareSigningWorkerLaneMaterialIdentityV1 {
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        for (field, value) in [
            ("operation_id", self.operation_id.as_str()),
            ("enrollment_id", self.enrollment_id.as_str()),
            ("wallet_id", self.wallet_id.as_str()),
            ("wallet_key_id", self.wallet_key_id.as_str()),
            ("target_lane_id", self.target_lane_id.as_str()),
            (
                "target_lane_share_epoch",
                self.target_lane_share_epoch.as_str(),
            ),
            (
                "target_material_activation_id",
                self.target_material_activation_id.as_str(),
            ),
        ] {
            require_text(field, value)?;
        }
        for (field, value) in [
            (
                "holder_participant_binding_digest_b64u",
                self.holder_participant_binding_digest_b64u.as_str(),
            ),
            (
                "signing_worker_participant_binding_digest_b64u",
                self.signing_worker_participant_binding_digest_b64u.as_str(),
            ),
            (
                "holder_recipient_key_digest_b64u",
                self.holder_recipient_key_digest_b64u.as_str(),
            ),
            (
                "server_recipient_key_digest_b64u",
                self.server_recipient_key_digest_b64u.as_str(),
            ),
            ("transcript_hash_b64u", self.transcript_hash_b64u.as_str()),
            (
                "protocol_commit_receipt_digest_b64u",
                self.protocol_commit_receipt_digest_b64u.as_str(),
            ),
        ] {
            decode_digest(field, value)?;
        }
        Ok(())
    }

    pub fn digest_b64u(&self) -> RouterAbProtocolResult<String> {
        self.validate()?;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(LANE_IDENTITY_DOMAIN_V1);
        for value in [
            self.operation_id.as_str(),
            self.enrollment_id.as_str(),
            self.wallet_id.as_str(),
            self.wallet_key_id.as_str(),
            self.target_lane_id.as_str(),
            self.target_lane_share_epoch.as_str(),
            self.target_material_activation_id.as_str(),
            self.key_family.wire_name(),
            self.holder_participant_binding_digest_b64u.as_str(),
            self.signing_worker_participant_binding_digest_b64u.as_str(),
            self.holder_recipient_key_digest_b64u.as_str(),
            self.server_recipient_key_digest_b64u.as_str(),
            self.transcript_hash_b64u.as_str(),
            self.protocol_commit_receipt_digest_b64u.as_str(),
        ] {
            encode_text(&mut bytes, value);
        }
        Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(bytes)))
    }
}

/// Semantic role of one encrypted-at-rest lane artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CloudflareSigningWorkerLaneArtifactKindV1 {
    HolderPackage,
    SigningWorkerPackage,
    ProtocolCommitReceipt,
    Transcript,
    HolderDeliveryReceipt,
    ActiveServerMaterial,
    ServerActivationReceipt,
    RetirementReceipt,
}

/// Canonical artifact bytes plus their storage-integrity digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CloudflareSigningWorkerLaneArtifactV1 {
    pub kind: CloudflareSigningWorkerLaneArtifactKindV1,
    pub payload_b64u: String,
    pub storage_digest_b64u: String,
}

impl Zeroize for CloudflareSigningWorkerLaneArtifactV1 {
    fn zeroize(&mut self) {
        self.payload_b64u.zeroize();
    }
}

impl Drop for CloudflareSigningWorkerLaneArtifactV1 {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl CloudflareSigningWorkerLaneArtifactV1 {
    pub fn from_bytes(
        kind: CloudflareSigningWorkerLaneArtifactKindV1,
        bytes: &[u8],
    ) -> RouterAbProtocolResult<Self> {
        if bytes.is_empty() {
            return Err(lane_error(
                RouterAbProtocolErrorCode::EmptyField,
                "SigningWorker lane artifact payload is empty",
            ));
        }
        Ok(Self {
            kind,
            payload_b64u: URL_SAFE_NO_PAD.encode(bytes),
            storage_digest_b64u: URL_SAFE_NO_PAD.encode(Sha256::digest(bytes)),
        })
    }

    pub fn validate_kind(
        &self,
        expected: CloudflareSigningWorkerLaneArtifactKindV1,
    ) -> RouterAbProtocolResult<()> {
        if self.kind != expected {
            return Err(lane_error(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "SigningWorker lane artifact has the wrong semantic kind",
            ));
        }
        let payload = Zeroizing::new(URL_SAFE_NO_PAD.decode(&self.payload_b64u).map_err(|_| {
            lane_error(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "SigningWorker lane artifact payload is not unpadded base64url",
            )
        })?);
        if payload.is_empty() {
            return Err(lane_error(
                RouterAbProtocolErrorCode::EmptyField,
                "SigningWorker lane artifact payload is empty",
            ));
        }
        let claimed = decode_digest("artifact.storage_digest_b64u", &self.storage_digest_b64u)?;
        let computed: [u8; 32] = Sha256::digest(payload.as_slice()).into();
        if !constant_time_equal(&claimed, &computed) {
            return Err(lane_error(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "SigningWorker lane artifact storage digest does not match its payload",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod artifact_tests {
    use super::{CloudflareSigningWorkerLaneArtifactKindV1, CloudflareSigningWorkerLaneArtifactV1};
    use zeroize::Zeroize;

    #[test]
    fn artifact_zeroize_clears_payload_and_retains_public_metadata() {
        let mut artifact = CloudflareSigningWorkerLaneArtifactV1::from_bytes(
            CloudflareSigningWorkerLaneArtifactKindV1::ActiveServerMaterial,
            b"private-share",
        )
        .expect("artifact");
        let digest = artifact.storage_digest_b64u.clone();

        artifact.zeroize();

        assert!(artifact.payload_b64u.is_empty());
        assert_eq!(
            artifact.kind,
            CloudflareSigningWorkerLaneArtifactKindV1::ActiveServerMaterial
        );
        assert_eq!(artifact.storage_digest_b64u, digest);
    }
}

/// Curve-specific committed ciphertext and transcript set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "curve",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum CloudflareSigningWorkerLaneCommittedArtifactsV1 {
    Ed25519Yao {
        holder_package: CloudflareSigningWorkerLaneArtifactV1,
        signing_worker_package: CloudflareSigningWorkerLaneArtifactV1,
        protocol_commit_receipt: CloudflareSigningWorkerLaneArtifactV1,
        transcript: CloudflareSigningWorkerLaneArtifactV1,
    },
    EcdsaAdditive {
        holder_package: CloudflareSigningWorkerLaneArtifactV1,
        signing_worker_package: CloudflareSigningWorkerLaneArtifactV1,
        protocol_commit_receipt: CloudflareSigningWorkerLaneArtifactV1,
        transcript: CloudflareSigningWorkerLaneArtifactV1,
    },
}

impl CloudflareSigningWorkerLaneCommittedArtifactsV1 {
    fn validate_for_family(
        &self,
        family: CloudflareSigningWorkerLaneKeyFamilyV1,
    ) -> RouterAbProtocolResult<()> {
        let (holder, worker, receipt, transcript, matches_family) = match self {
            Self::Ed25519Yao {
                holder_package,
                signing_worker_package,
                protocol_commit_receipt,
                transcript,
            } => (
                holder_package,
                signing_worker_package,
                protocol_commit_receipt,
                transcript,
                family == CloudflareSigningWorkerLaneKeyFamilyV1::Ed25519,
            ),
            Self::EcdsaAdditive {
                holder_package,
                signing_worker_package,
                protocol_commit_receipt,
                transcript,
            } => (
                holder_package,
                signing_worker_package,
                protocol_commit_receipt,
                transcript,
                family == CloudflareSigningWorkerLaneKeyFamilyV1::EcdsaSecp256k1,
            ),
        };
        if !matches_family {
            return Err(lane_error(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "SigningWorker lane committed artifact curve does not match its identity",
            ));
        }
        holder.validate_kind(CloudflareSigningWorkerLaneArtifactKindV1::HolderPackage)?;
        worker.validate_kind(CloudflareSigningWorkerLaneArtifactKindV1::SigningWorkerPackage)?;
        receipt.validate_kind(CloudflareSigningWorkerLaneArtifactKindV1::ProtocolCommitReceipt)?;
        transcript.validate_kind(CloudflareSigningWorkerLaneArtifactKindV1::Transcript)
    }

    fn protocol_commit_receipt(&self) -> &CloudflareSigningWorkerLaneArtifactV1 {
        match self {
            Self::Ed25519Yao {
                protocol_commit_receipt,
                ..
            }
            | Self::EcdsaAdditive {
                protocol_commit_receipt,
                ..
            } => protocol_commit_receipt,
        }
    }

    fn holder_redelivery_artifacts(
        &self,
    ) -> (
        &CloudflareSigningWorkerLaneArtifactV1,
        &CloudflareSigningWorkerLaneArtifactV1,
        &CloudflareSigningWorkerLaneArtifactV1,
    ) {
        match self {
            Self::Ed25519Yao {
                holder_package,
                protocol_commit_receipt,
                transcript,
                ..
            }
            | Self::EcdsaAdditive {
                holder_package,
                protocol_commit_receipt,
                transcript,
                ..
            } => (holder_package, protocol_commit_receipt, transcript),
        }
    }
}

/// Exact holder delivery retained for redelivery and activation replay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CloudflareSigningWorkerLaneHolderDeliveryV1 {
    pub receipt: CloudflareSigningWorkerLaneArtifactV1,
    pub acknowledged_at_ms: u64,
}

impl CloudflareSigningWorkerLaneHolderDeliveryV1 {
    fn validate(&self, committed_at_ms: u64) -> RouterAbProtocolResult<()> {
        self.receipt
            .validate_kind(CloudflareSigningWorkerLaneArtifactKindV1::HolderDeliveryReceipt)?;
        if self.acknowledged_at_ms < committed_at_ms {
            return Err(lane_error(
                RouterAbProtocolErrorCode::InvalidTimeRange,
                "SigningWorker lane holder acknowledgement predates protocol commitment",
            ));
        }
        Ok(())
    }
}

/// Exact private material and receipt created by server activation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CloudflareSigningWorkerLaneServerActivationV1 {
    pub active_server_material: CloudflareSigningWorkerLaneArtifactV1,
    pub receipt: CloudflareSigningWorkerLaneArtifactV1,
    pub activated_at_ms: u64,
}

impl CloudflareSigningWorkerLaneServerActivationV1 {
    fn validate(&self, holder_acknowledged_at_ms: u64) -> RouterAbProtocolResult<()> {
        self.active_server_material
            .validate_kind(CloudflareSigningWorkerLaneArtifactKindV1::ActiveServerMaterial)?;
        self.receipt
            .validate_kind(CloudflareSigningWorkerLaneArtifactKindV1::ServerActivationReceipt)?;
        if self.activated_at_ms < holder_acknowledged_at_ms {
            return Err(lane_error(
                RouterAbProtocolErrorCode::InvalidTimeRange,
                "SigningWorker lane server activation predates holder delivery",
            ));
        }
        Ok(())
    }
}

/// Allowed private lane retirement causes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CloudflareSigningWorkerLaneRetirementReasonV1 {
    LaneRevoked,
    DeviceCompromise,
    AgentCompromise,
    Rotation,
}

/// Exact terminal retirement effect and its receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CloudflareSigningWorkerLaneRetirementV1 {
    pub revocation_epoch: u64,
    pub reason: CloudflareSigningWorkerLaneRetirementReasonV1,
    pub correlation_id: String,
    pub request_digest_b64u: String,
    pub receipt: CloudflareSigningWorkerLaneArtifactV1,
    pub retired_at_ms: u64,
}

impl CloudflareSigningWorkerLaneRetirementV1 {
    fn validate(&self, earliest_at_ms: u64) -> RouterAbProtocolResult<()> {
        require_text("retirement.correlation_id", &self.correlation_id)?;
        decode_digest("retirement.request_digest_b64u", &self.request_digest_b64u)?;
        self.receipt
            .validate_kind(CloudflareSigningWorkerLaneArtifactKindV1::RetirementReceipt)?;
        if self.retired_at_ms < earliest_at_ms {
            return Err(lane_error(
                RouterAbProtocolErrorCode::InvalidTimeRange,
                "SigningWorker lane retirement predates retained lane state",
            ));
        }
        Ok(())
    }
}

/// Valid private lifecycle states for one committed target lane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "state",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum CloudflareSigningWorkerLaneMaterialLifecycleV1 {
    CommittedAwaitingHolderDelivery {
        committed_at_ms: u64,
    },
    AwaitingServerActivation {
        committed_at_ms: u64,
        holder_delivery: CloudflareSigningWorkerLaneHolderDeliveryV1,
    },
    Active {
        committed_at_ms: u64,
        holder_delivery: CloudflareSigningWorkerLaneHolderDeliveryV1,
        server_activation: CloudflareSigningWorkerLaneServerActivationV1,
    },
    RetiredBeforeHolderDelivery {
        committed_at_ms: u64,
        retirement: CloudflareSigningWorkerLaneRetirementV1,
    },
    RetiredAfterHolderDelivery {
        committed_at_ms: u64,
        holder_delivery: CloudflareSigningWorkerLaneHolderDeliveryV1,
        retirement: CloudflareSigningWorkerLaneRetirementV1,
    },
    RetiredAfterActivation {
        committed_at_ms: u64,
        holder_delivery: CloudflareSigningWorkerLaneHolderDeliveryV1,
        server_activation: CloudflareSigningWorkerLaneServerActivationV1,
        retirement: CloudflareSigningWorkerLaneRetirementV1,
    },
}

impl CloudflareSigningWorkerLaneMaterialLifecycleV1 {
    fn committed_at_ms(&self) -> u64 {
        match self {
            Self::CommittedAwaitingHolderDelivery { committed_at_ms }
            | Self::AwaitingServerActivation {
                committed_at_ms, ..
            }
            | Self::Active {
                committed_at_ms, ..
            }
            | Self::RetiredBeforeHolderDelivery {
                committed_at_ms, ..
            }
            | Self::RetiredAfterHolderDelivery {
                committed_at_ms, ..
            }
            | Self::RetiredAfterActivation {
                committed_at_ms, ..
            } => *committed_at_ms,
        }
    }

    fn validate(&self) -> RouterAbProtocolResult<()> {
        let committed_at_ms = self.committed_at_ms();
        if committed_at_ms == 0 {
            return Err(lane_error(
                RouterAbProtocolErrorCode::InvalidTimeRange,
                "SigningWorker lane commitment timestamp must be positive",
            ));
        }
        match self {
            Self::CommittedAwaitingHolderDelivery { .. } => Ok(()),
            Self::AwaitingServerActivation {
                holder_delivery, ..
            } => holder_delivery.validate(committed_at_ms),
            Self::Active {
                holder_delivery,
                server_activation,
                ..
            } => {
                holder_delivery.validate(committed_at_ms)?;
                server_activation.validate(holder_delivery.acknowledged_at_ms)
            }
            Self::RetiredBeforeHolderDelivery { retirement, .. } => {
                retirement.validate(committed_at_ms)
            }
            Self::RetiredAfterHolderDelivery {
                holder_delivery,
                retirement,
                ..
            } => {
                holder_delivery.validate(committed_at_ms)?;
                retirement.validate(holder_delivery.acknowledged_at_ms)
            }
            Self::RetiredAfterActivation {
                holder_delivery,
                server_activation,
                retirement,
                ..
            } => {
                holder_delivery.validate(committed_at_ms)?;
                server_activation.validate(holder_delivery.acknowledged_at_ms)?;
                retirement.validate(server_activation.activated_at_ms)
            }
        }
    }
}

/// Encrypted-at-rest SigningWorker record for one committed child operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CloudflareSigningWorkerLaneMaterialRecordV1 {
    pub identity: CloudflareSigningWorkerLaneMaterialIdentityV1,
    pub committed_artifacts: CloudflareSigningWorkerLaneCommittedArtifactsV1,
    pub lifecycle: CloudflareSigningWorkerLaneMaterialLifecycleV1,
}

impl CloudflareSigningWorkerLaneMaterialRecordV1 {
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.identity.validate()?;
        self.committed_artifacts
            .validate_for_family(self.identity.key_family)?;
        self.lifecycle.validate()
    }

    pub fn holder_redelivery(
        &self,
    ) -> RouterAbProtocolResult<CloudflareSigningWorkerLaneHolderRedeliveryV1> {
        self.validate()?;
        if matches!(
            &self.lifecycle,
            CloudflareSigningWorkerLaneMaterialLifecycleV1::RetiredBeforeHolderDelivery { .. }
                | CloudflareSigningWorkerLaneMaterialLifecycleV1::RetiredAfterHolderDelivery { .. }
                | CloudflareSigningWorkerLaneMaterialLifecycleV1::RetiredAfterActivation { .. }
        ) {
            return Err(lane_error(
                RouterAbProtocolErrorCode::MissingLocalBinding,
                "SigningWorker lane holder redelivery is retired",
            ));
        }
        let (holder_package, protocol_commit_receipt, transcript) =
            self.committed_artifacts.holder_redelivery_artifacts();
        Ok(CloudflareSigningWorkerLaneHolderRedeliveryV1 {
            identity_digest_b64u: self.identity.digest_b64u()?,
            holder_package: holder_package.clone(),
            protocol_commit_receipt: protocol_commit_receipt.clone(),
            transcript: transcript.clone(),
        })
    }

    pub fn active_server_material(
        &self,
    ) -> RouterAbProtocolResult<CloudflareSigningWorkerLaneArtifactV1> {
        self.active_server_material_with_activation()
            .map(|(material, _)| material)
    }

    pub fn active_server_material_with_activation(
        &self,
    ) -> RouterAbProtocolResult<(CloudflareSigningWorkerLaneArtifactV1, u64)> {
        self.validate()?;
        match &self.lifecycle {
            CloudflareSigningWorkerLaneMaterialLifecycleV1::Active {
                server_activation, ..
            } => Ok((
                server_activation.active_server_material.clone(),
                server_activation.activated_at_ms,
            )),
            _ => Err(lane_error(
                RouterAbProtocolErrorCode::MissingLocalBinding,
                "SigningWorker lane active server material is unavailable",
            )),
        }
    }
}

/// Holder-only redelivery projection for an authenticated recipient claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CloudflareSigningWorkerLaneHolderRedeliveryV1 {
    pub identity_digest_b64u: String,
    pub holder_package: CloudflareSigningWorkerLaneArtifactV1,
    pub protocol_commit_receipt: CloudflareSigningWorkerLaneArtifactV1,
    pub transcript: CloudflareSigningWorkerLaneArtifactV1,
}

/// Exact lane identity admitted for one ordinary signing material lookup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CloudflareSigningWorkerNormalSigningLaneMaterialLookupV1 {
    pub identity: CloudflareSigningWorkerLaneMaterialIdentityV1,
    pub admitted_lane_identity_digest_b64u: String,
}

impl CloudflareSigningWorkerNormalSigningLaneMaterialLookupV1 {
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.identity.validate()?;
        let admitted = decode_digest(
            "normal_signing.admitted_lane_identity_digest_b64u",
            &self.admitted_lane_identity_digest_b64u,
        )?;
        let computed = decode_digest(
            "normal_signing.computed_lane_identity_digest_b64u",
            &self.identity.digest_b64u()?,
        )?;
        if !constant_time_equal(&admitted, &computed) {
            return Err(lane_error(
                RouterAbProtocolErrorCode::ReplayedLocalRequest,
                "SigningWorker normal-signing lane identity does not match admission",
            ));
        }
        Ok(())
    }
}

/// One exact, idempotent mutation of private SigningWorker lane state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "command",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum CloudflareSigningWorkerLaneMaterialCommandV1 {
    Commit {
        identity: CloudflareSigningWorkerLaneMaterialIdentityV1,
        committed_artifacts: CloudflareSigningWorkerLaneCommittedArtifactsV1,
        committed_at_ms: u64,
    },
    RecordHolderDelivery {
        identity: CloudflareSigningWorkerLaneMaterialIdentityV1,
        holder_delivery: CloudflareSigningWorkerLaneHolderDeliveryV1,
    },
    ActivateServerMaterial {
        identity: CloudflareSigningWorkerLaneMaterialIdentityV1,
        expected_holder_delivery_receipt: CloudflareSigningWorkerLaneArtifactV1,
        server_activation: CloudflareSigningWorkerLaneServerActivationV1,
    },
    Retire {
        identity: CloudflareSigningWorkerLaneMaterialIdentityV1,
        retirement: CloudflareSigningWorkerLaneRetirementV1,
    },
}

impl CloudflareSigningWorkerLaneMaterialCommandV1 {
    pub fn identity(&self) -> &CloudflareSigningWorkerLaneMaterialIdentityV1 {
        match self {
            Self::Commit { identity, .. }
            | Self::RecordHolderDelivery { identity, .. }
            | Self::ActivateServerMaterial { identity, .. }
            | Self::Retire { identity, .. } => identity,
        }
    }

    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.identity().validate()?;
        match self {
            Self::Commit {
                identity,
                committed_artifacts,
                committed_at_ms,
            } => {
                committed_artifacts.validate_for_family(identity.key_family)?;
                if *committed_at_ms == 0 {
                    return Err(lane_error(
                        RouterAbProtocolErrorCode::InvalidTimeRange,
                        "SigningWorker lane commitment timestamp must be positive",
                    ));
                }
                Ok(())
            }
            Self::RecordHolderDelivery {
                holder_delivery, ..
            } => {
                holder_delivery.receipt.validate_kind(
                    CloudflareSigningWorkerLaneArtifactKindV1::HolderDeliveryReceipt,
                )?;
                if holder_delivery.acknowledged_at_ms == 0 {
                    return Err(lane_error(
                        RouterAbProtocolErrorCode::InvalidTimeRange,
                        "SigningWorker lane holder acknowledgement must be positive",
                    ));
                }
                Ok(())
            }
            Self::ActivateServerMaterial {
                expected_holder_delivery_receipt,
                server_activation,
                ..
            } => {
                expected_holder_delivery_receipt.validate_kind(
                    CloudflareSigningWorkerLaneArtifactKindV1::HolderDeliveryReceipt,
                )?;
                server_activation.active_server_material.validate_kind(
                    CloudflareSigningWorkerLaneArtifactKindV1::ActiveServerMaterial,
                )?;
                server_activation.receipt.validate_kind(
                    CloudflareSigningWorkerLaneArtifactKindV1::ServerActivationReceipt,
                )?;
                if server_activation.activated_at_ms == 0 {
                    return Err(lane_error(
                        RouterAbProtocolErrorCode::InvalidTimeRange,
                        "SigningWorker lane server activation timestamp must be positive",
                    ));
                }
                Ok(())
            }
            Self::Retire { retirement, .. } => retirement.validate(1),
        }
    }

    pub fn updated_at_ms(&self) -> u64 {
        match self {
            Self::Commit {
                committed_at_ms, ..
            } => *committed_at_ms,
            Self::RecordHolderDelivery {
                holder_delivery, ..
            } => holder_delivery.acknowledged_at_ms,
            Self::ActivateServerMaterial {
                server_activation, ..
            } => server_activation.activated_at_ms,
            Self::Retire { retirement, .. } => retirement.retired_at_ms,
        }
    }
}

/// Result of applying one lane command to its exact private record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudflareSigningWorkerLaneMaterialMutationV1 {
    pub record: CloudflareSigningWorkerLaneMaterialRecordV1,
    pub changed: bool,
}

/// Receipt-only result safe for an authenticated service boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "outcome",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum CloudflareSigningWorkerLaneMaterialEffectV1 {
    ProtocolCommitted {
        identity_digest_b64u: String,
        receipt: CloudflareSigningWorkerLaneArtifactV1,
        changed: bool,
    },
    HolderDeliveryRecorded {
        identity_digest_b64u: String,
        receipt: CloudflareSigningWorkerLaneArtifactV1,
        changed: bool,
    },
    ServerMaterialActivated {
        identity_digest_b64u: String,
        receipt: CloudflareSigningWorkerLaneArtifactV1,
        changed: bool,
    },
    Retired {
        identity_digest_b64u: String,
        receipt: CloudflareSigningWorkerLaneArtifactV1,
        changed: bool,
    },
}

fn holder_delivery_receipt(
    lifecycle: &CloudflareSigningWorkerLaneMaterialLifecycleV1,
) -> Option<&CloudflareSigningWorkerLaneArtifactV1> {
    match lifecycle {
        CloudflareSigningWorkerLaneMaterialLifecycleV1::AwaitingServerActivation {
            holder_delivery,
            ..
        }
        | CloudflareSigningWorkerLaneMaterialLifecycleV1::Active {
            holder_delivery, ..
        }
        | CloudflareSigningWorkerLaneMaterialLifecycleV1::RetiredAfterHolderDelivery {
            holder_delivery,
            ..
        }
        | CloudflareSigningWorkerLaneMaterialLifecycleV1::RetiredAfterActivation {
            holder_delivery,
            ..
        } => Some(&holder_delivery.receipt),
        CloudflareSigningWorkerLaneMaterialLifecycleV1::CommittedAwaitingHolderDelivery {
            ..
        }
        | CloudflareSigningWorkerLaneMaterialLifecycleV1::RetiredBeforeHolderDelivery { .. } => {
            None
        }
    }
}

fn server_activation_receipt(
    lifecycle: &CloudflareSigningWorkerLaneMaterialLifecycleV1,
) -> Option<&CloudflareSigningWorkerLaneArtifactV1> {
    match lifecycle {
        CloudflareSigningWorkerLaneMaterialLifecycleV1::Active {
            server_activation, ..
        }
        | CloudflareSigningWorkerLaneMaterialLifecycleV1::RetiredAfterActivation {
            server_activation,
            ..
        } => Some(&server_activation.receipt),
        _ => None,
    }
}

fn retirement_receipt(
    lifecycle: &CloudflareSigningWorkerLaneMaterialLifecycleV1,
) -> Option<&CloudflareSigningWorkerLaneArtifactV1> {
    match lifecycle {
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
        } => Some(&retirement.receipt),
        _ => None,
    }
}

/// Projects an internal mutation to the exact public receipt for its command.
pub fn project_cloudflare_signing_worker_lane_material_effect_v1(
    mutation: &CloudflareSigningWorkerLaneMaterialMutationV1,
    command: &CloudflareSigningWorkerLaneMaterialCommandV1,
) -> RouterAbProtocolResult<CloudflareSigningWorkerLaneMaterialEffectV1> {
    require_same_identity(&mutation.record, command.identity())?;
    let identity_digest_b64u = mutation.record.identity.digest_b64u()?;
    let effect = match command {
        CloudflareSigningWorkerLaneMaterialCommandV1::Commit { .. } => {
            CloudflareSigningWorkerLaneMaterialEffectV1::ProtocolCommitted {
                identity_digest_b64u,
                receipt: mutation
                    .record
                    .committed_artifacts
                    .protocol_commit_receipt()
                    .clone(),
                changed: mutation.changed,
            }
        }
        CloudflareSigningWorkerLaneMaterialCommandV1::RecordHolderDelivery { .. } => {
            let receipt = holder_delivery_receipt(&mutation.record.lifecycle).ok_or_else(|| {
                transition_conflict(
                    "SigningWorker lane holder-delivery result has no retained receipt",
                )
            })?;
            CloudflareSigningWorkerLaneMaterialEffectV1::HolderDeliveryRecorded {
                identity_digest_b64u,
                receipt: receipt.clone(),
                changed: mutation.changed,
            }
        }
        CloudflareSigningWorkerLaneMaterialCommandV1::ActivateServerMaterial { .. } => {
            let receipt =
                server_activation_receipt(&mutation.record.lifecycle).ok_or_else(|| {
                    transition_conflict(
                        "SigningWorker lane server-activation result has no retained receipt",
                    )
                })?;
            CloudflareSigningWorkerLaneMaterialEffectV1::ServerMaterialActivated {
                identity_digest_b64u,
                receipt: receipt.clone(),
                changed: mutation.changed,
            }
        }
        CloudflareSigningWorkerLaneMaterialCommandV1::Retire { .. } => {
            let receipt = retirement_receipt(&mutation.record.lifecycle).ok_or_else(|| {
                transition_conflict("SigningWorker lane retirement result has no retained receipt")
            })?;
            CloudflareSigningWorkerLaneMaterialEffectV1::Retired {
                identity_digest_b64u,
                receipt: receipt.clone(),
                changed: mutation.changed,
            }
        }
    };
    Ok(effect)
}

fn identity_conflict() -> RouterAbProtocolError {
    lane_error(
        RouterAbProtocolErrorCode::ReplayedLocalRequest,
        "SigningWorker lane operation was reused for different identity material",
    )
}

fn transition_conflict(message: &'static str) -> RouterAbProtocolError {
    lane_error(RouterAbProtocolErrorCode::ConflictingPair, message)
}

fn require_same_identity(
    record: &CloudflareSigningWorkerLaneMaterialRecordV1,
    identity: &CloudflareSigningWorkerLaneMaterialIdentityV1,
) -> RouterAbProtocolResult<()> {
    if record.identity != *identity {
        return Err(identity_conflict());
    }
    Ok(())
}

/// Pure transition reducer shared by D1 execution and focused tests.
pub fn apply_cloudflare_signing_worker_lane_material_command_v1(
    current: Option<CloudflareSigningWorkerLaneMaterialRecordV1>,
    command: CloudflareSigningWorkerLaneMaterialCommandV1,
) -> RouterAbProtocolResult<CloudflareSigningWorkerLaneMaterialMutationV1> {
    command.validate()?;
    let mutation = match (current, command) {
        (
            None,
            CloudflareSigningWorkerLaneMaterialCommandV1::Commit {
                identity,
                committed_artifacts,
                committed_at_ms,
            },
        ) => CloudflareSigningWorkerLaneMaterialMutationV1 {
            record: CloudflareSigningWorkerLaneMaterialRecordV1 {
                identity,
                committed_artifacts,
                lifecycle:
                    CloudflareSigningWorkerLaneMaterialLifecycleV1::CommittedAwaitingHolderDelivery {
                        committed_at_ms,
                    },
            },
            changed: true,
        },
        (None, _) => {
            return Err(lane_error(
                RouterAbProtocolErrorCode::MissingLocalBinding,
                "SigningWorker lane material must be committed before this command",
            ))
        }
        (
            Some(record),
            CloudflareSigningWorkerLaneMaterialCommandV1::Commit {
                identity,
                committed_artifacts,
                committed_at_ms,
            },
        ) => {
            require_same_identity(&record, &identity)?;
            if record.committed_artifacts != committed_artifacts
                || record.lifecycle.committed_at_ms() != committed_at_ms
            {
                return Err(identity_conflict());
            }
            CloudflareSigningWorkerLaneMaterialMutationV1 {
                record,
                changed: false,
            }
        }
        (
            Some(mut record),
            CloudflareSigningWorkerLaneMaterialCommandV1::RecordHolderDelivery {
                identity,
                holder_delivery,
            },
        ) => {
            require_same_identity(&record, &identity)?;
            let committed_at_ms = record.lifecycle.committed_at_ms();
            holder_delivery.validate(committed_at_ms)?;
            match &record.lifecycle {
                CloudflareSigningWorkerLaneMaterialLifecycleV1::CommittedAwaitingHolderDelivery {
                    ..
                } => {
                    record.lifecycle =
                        CloudflareSigningWorkerLaneMaterialLifecycleV1::AwaitingServerActivation {
                            committed_at_ms,
                            holder_delivery,
                        };
                    CloudflareSigningWorkerLaneMaterialMutationV1 {
                        record,
                        changed: true,
                    }
                }
                CloudflareSigningWorkerLaneMaterialLifecycleV1::AwaitingServerActivation {
                    holder_delivery: stored,
                    ..
                }
                | CloudflareSigningWorkerLaneMaterialLifecycleV1::Active {
                    holder_delivery: stored,
                    ..
                }
                | CloudflareSigningWorkerLaneMaterialLifecycleV1::RetiredAfterHolderDelivery {
                    holder_delivery: stored,
                    ..
                }
                | CloudflareSigningWorkerLaneMaterialLifecycleV1::RetiredAfterActivation {
                    holder_delivery: stored,
                    ..
                } if stored == &holder_delivery => {
                    CloudflareSigningWorkerLaneMaterialMutationV1 {
                        record,
                        changed: false,
                    }
                }
                CloudflareSigningWorkerLaneMaterialLifecycleV1::RetiredBeforeHolderDelivery {
                    ..
                } => {
                    return Err(transition_conflict(
                        "SigningWorker lane holder delivery cannot follow retirement",
                    ))
                }
                _ => return Err(identity_conflict()),
            }
        }
        (
            Some(mut record),
            CloudflareSigningWorkerLaneMaterialCommandV1::ActivateServerMaterial {
                identity,
                expected_holder_delivery_receipt,
                server_activation,
            },
        ) => {
            require_same_identity(&record, &identity)?;
            let committed_at_ms = record.lifecycle.committed_at_ms();
            match &record.lifecycle {
                CloudflareSigningWorkerLaneMaterialLifecycleV1::AwaitingServerActivation {
                    holder_delivery,
                    ..
                } => {
                    if holder_delivery.receipt != expected_holder_delivery_receipt {
                        return Err(identity_conflict());
                    }
                    server_activation.validate(holder_delivery.acknowledged_at_ms)?;
                    let holder_delivery = holder_delivery.clone();
                    record.lifecycle = CloudflareSigningWorkerLaneMaterialLifecycleV1::Active {
                        committed_at_ms,
                        holder_delivery,
                        server_activation,
                    };
                    CloudflareSigningWorkerLaneMaterialMutationV1 {
                        record,
                        changed: true,
                    }
                }
                CloudflareSigningWorkerLaneMaterialLifecycleV1::Active {
                    holder_delivery,
                    server_activation: stored,
                    ..
                }
                | CloudflareSigningWorkerLaneMaterialLifecycleV1::RetiredAfterActivation {
                    holder_delivery,
                    server_activation: stored,
                    ..
                } if holder_delivery.receipt == expected_holder_delivery_receipt
                    && stored == &server_activation =>
                {
                    CloudflareSigningWorkerLaneMaterialMutationV1 {
                        record,
                        changed: false,
                    }
                }
                CloudflareSigningWorkerLaneMaterialLifecycleV1::CommittedAwaitingHolderDelivery {
                    ..
                } => {
                    return Err(transition_conflict(
                        "SigningWorker lane server activation requires holder delivery",
                    ))
                }
                CloudflareSigningWorkerLaneMaterialLifecycleV1::RetiredBeforeHolderDelivery {
                    ..
                }
                | CloudflareSigningWorkerLaneMaterialLifecycleV1::RetiredAfterHolderDelivery {
                    ..
                } => {
                    return Err(transition_conflict(
                        "SigningWorker lane server activation cannot follow retirement",
                    ))
                }
                _ => return Err(identity_conflict()),
            }
        }
        (
            Some(mut record),
            CloudflareSigningWorkerLaneMaterialCommandV1::Retire {
                identity,
                retirement,
            },
        ) => {
            require_same_identity(&record, &identity)?;
            let committed_at_ms = record.lifecycle.committed_at_ms();
            record.lifecycle = match &record.lifecycle {
                CloudflareSigningWorkerLaneMaterialLifecycleV1::CommittedAwaitingHolderDelivery {
                    ..
                } => {
                    retirement.validate(committed_at_ms)?;
                    CloudflareSigningWorkerLaneMaterialLifecycleV1::RetiredBeforeHolderDelivery {
                        committed_at_ms,
                        retirement,
                    }
                }
                CloudflareSigningWorkerLaneMaterialLifecycleV1::AwaitingServerActivation {
                    holder_delivery,
                    ..
                } => {
                    retirement.validate(holder_delivery.acknowledged_at_ms)?;
                    CloudflareSigningWorkerLaneMaterialLifecycleV1::RetiredAfterHolderDelivery {
                        committed_at_ms,
                        holder_delivery: holder_delivery.clone(),
                        retirement,
                    }
                }
                CloudflareSigningWorkerLaneMaterialLifecycleV1::Active {
                    holder_delivery,
                    server_activation,
                    ..
                } => {
                    retirement.validate(server_activation.activated_at_ms)?;
                    CloudflareSigningWorkerLaneMaterialLifecycleV1::RetiredAfterActivation {
                        committed_at_ms,
                        holder_delivery: holder_delivery.clone(),
                        server_activation: server_activation.clone(),
                        retirement,
                    }
                }
                CloudflareSigningWorkerLaneMaterialLifecycleV1::RetiredBeforeHolderDelivery {
                    retirement: stored,
                    ..
                }
                | CloudflareSigningWorkerLaneMaterialLifecycleV1::RetiredAfterHolderDelivery {
                    retirement: stored,
                    ..
                }
                | CloudflareSigningWorkerLaneMaterialLifecycleV1::RetiredAfterActivation {
                    retirement: stored,
                    ..
                } if stored == &retirement => {
                    return Ok(CloudflareSigningWorkerLaneMaterialMutationV1 {
                        record,
                        changed: false,
                    })
                }
                _ => return Err(identity_conflict()),
            };
            CloudflareSigningWorkerLaneMaterialMutationV1 {
                record,
                changed: true,
            }
        }
    };
    mutation.record.validate()?;
    Ok(mutation)
}
