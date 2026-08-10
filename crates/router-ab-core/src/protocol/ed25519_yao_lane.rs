//! Typed Ed25519 Streaming-Yao lane provisioning and refresh records.
//!
//! The lane family is deliberately separate from activation and export.  A
//! lane job carries public bindings only; private role contributions and the
//! random lane offset are owned by the Yao adapter.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::protocol::error::{
    RouterAbProtocolError, RouterAbProtocolErrorCode, RouterAbProtocolResult,
};
use crate::protocol::lifecycle::MpcMaterialActivationRefV1;

/// Product request kind for the lane-materialization circuit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ed25519YaoLaneRequestKindV1 {
    /// Creates a new linked-device lane at its first share epoch.
    LaneProvisioning,
    /// Replaces one active lane with its next share epoch.
    LaneRefresh,
}

impl Ed25519YaoLaneRequestKindV1 {
    /// Returns the canonical wire label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LaneProvisioning => "lane_provisioning",
            Self::LaneRefresh => "lane_refresh",
        }
    }

    /// Returns the corresponding core operation.
    pub const fn operation(self) -> super::ed25519_yao::Ed25519YaoOperationV1 {
        match self {
            Self::LaneProvisioning => super::ed25519_yao::Ed25519YaoOperationV1::LaneProvisioning,
            Self::LaneRefresh => super::ed25519_yao::Ed25519YaoOperationV1::LaneRefresh,
        }
    }
}

/// Authorization binding accepted by lane creation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Ed25519YaoLaneAuthorizationV1 {
    /// Owner-approved linked-device enrollment.
    LinkedDeviceEnrollment {
        /// Authorized operation identifier.
        authorized_operation_id: String,
        /// Linked-device enrollment identifier.
        linked_device_enrollment_id: String,
        /// Permission policy digest.
        linked_device_permission_digest_b64u: String,
    },
    /// Owner-authorized refresh of an existing lane.
    OwnerLaneRefresh {
        /// Authorized operation identifier.
        authorized_operation_id: String,
        /// Owner refresh authorization digest.
        owner_lane_refresh_digest_b64u: String,
    },
}

impl Ed25519YaoLaneAuthorizationV1 {
    /// Validates branch-specific authorization identity.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        match self {
            Self::LinkedDeviceEnrollment {
                authorized_operation_id,
                linked_device_enrollment_id,
                linked_device_permission_digest_b64u,
            } => {
                require_text("authorized_operation_id", authorized_operation_id)?;
                require_text("linked_device_enrollment_id", linked_device_enrollment_id)?;
                require_digest(
                    "linked_device_permission_digest_b64u",
                    linked_device_permission_digest_b64u,
                )
            }
            Self::OwnerLaneRefresh {
                authorized_operation_id,
                owner_lane_refresh_digest_b64u,
            } => {
                require_text("authorized_operation_id", authorized_operation_id)?;
                require_digest(
                    "owner_lane_refresh_digest_b64u",
                    owner_lane_refresh_digest_b64u,
                )
            }
        }
    }

    /// Returns the operation identifier bound by this authorization.
    pub fn authorized_operation_id(&self) -> &str {
        match self {
            Self::LinkedDeviceEnrollment {
                authorized_operation_id,
                ..
            }
            | Self::OwnerLaneRefresh {
                authorized_operation_id,
                ..
            } => authorized_operation_id,
        }
    }
}

/// Target branch for one lane job.  The enum keeps creation and refresh
/// preconditions disjoint at the type boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum Ed25519YaoLaneTargetV1 {
    /// New lane target.  No prior activation is accepted on this branch.
    CreateLane {
        /// Target lane identifier.
        lane_id: String,
        /// Target lane kind; first-release creation is linked-device only.
        lane_kind: String,
        /// First share epoch for the target lane.
        lane_share_epoch: u64,
        /// Required target pre-state.
        expected_target_state: String,
    },
    /// Existing lane target.  Refresh must carry its exact prior activation.
    RefreshLane {
        /// Existing lane identifier.
        lane_id: String,
        /// Existing lane kind.
        lane_kind: String,
        /// Strictly next share epoch.
        lane_share_epoch: u64,
        /// Required target pre-state.
        expected_target_state: String,
        /// Exact activation being replaced.
        prior_material_activation: MpcMaterialActivationRefV1,
    },
}

impl Ed25519YaoLaneTargetV1 {
    /// Returns the target lane identifier.
    pub fn lane_id(&self) -> &str {
        match self {
            Self::CreateLane { lane_id, .. } | Self::RefreshLane { lane_id, .. } => lane_id,
        }
    }

    /// Returns the target share epoch.
    pub fn lane_share_epoch(&self) -> u64 {
        match self {
            Self::CreateLane {
                lane_share_epoch, ..
            }
            | Self::RefreshLane {
                lane_share_epoch, ..
            } => *lane_share_epoch,
        }
    }

    /// Returns whether this is a creation branch.
    pub const fn is_creation(&self) -> bool {
        matches!(self, Self::CreateLane { .. })
    }

    /// Returns the prior activation on a refresh branch.
    pub fn prior_material_activation(&self) -> Option<&MpcMaterialActivationRefV1> {
        match self {
            Self::CreateLane { .. } => None,
            Self::RefreshLane {
                prior_material_activation,
                ..
            } => Some(prior_material_activation),
        }
    }
}

/// Public source-lane identity pinned before any Yao work starts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ed25519YaoLaneSourceV1 {
    /// Source lane identifier.
    pub lane_id: String,
    /// Source lane share epoch.
    pub lane_share_epoch: u64,
    /// Source lane revocation epoch.
    pub revocation_epoch: u64,
    /// Source holder participant identity.
    pub holder_participant_id: String,
    /// Source SigningWorker participant identity.
    pub signing_worker_participant_id: String,
    /// Source participant-binding digest.
    pub participant_binding_digest_b64u: String,
    /// Exact source material activation.
    pub material_activation: MpcMaterialActivationRefV1,
}

impl Ed25519YaoLaneSourceV1 {
    /// Validates the source lane identity.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_text("source.lane_id", &self.lane_id)?;
        require_positive("source.lane_share_epoch", self.lane_share_epoch)?;
        require_text("source.holder_participant_id", &self.holder_participant_id)?;
        require_text(
            "source.signing_worker_participant_id",
            &self.signing_worker_participant_id,
        )?;
        require_digest(
            "source.participant_binding_digest_b64u",
            &self.participant_binding_digest_b64u,
        )?;
        self.material_activation.validate()
    }
}

/// Ed25519 lane job admitted by the Router boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ed25519YaoLaneJobV1 {
    /// Fixed wire discriminator.
    pub kind: String,
    /// Ed25519 key family discriminator.
    pub key_family: String,
    /// Operation selecting the lane-materialization functionality.
    pub yao_request_kind: Ed25519YaoLaneRequestKindV1,
    /// Operation identifier.
    pub operation_id: String,
    /// Parent enrollment identifier.
    pub enrollment_id: String,
    /// One-use idempotency key.
    pub idempotency_key: String,
    /// Wallet identity.
    pub wallet_id: String,
    /// Wallet-key identity.
    pub wallet_key_id: String,
    /// Source lane pinned at admission.
    pub source: Ed25519YaoLaneSourceV1,
    /// Target lane creation or refresh branch.
    pub target: Ed25519YaoLaneTargetV1,
    /// Lane authorization branch.
    pub authorization: Ed25519YaoLaneAuthorizationV1,
    /// Fresh target material activation id.
    pub target_material_activation_id: String,
    /// Holder participant identity.
    pub target_holder_participant_id: String,
    /// Holder participant-binding digest.
    pub target_holder_participant_binding_digest_b64u: String,
    /// Holder custody binding digest.
    pub target_holder_custody_binding_digest_b64u: String,
    /// Holder HPKE public key.
    pub target_holder_hpke_public_key_b64u: String,
    /// Holder HPKE public-key digest.
    pub target_holder_hpke_public_key_digest_b64u: String,
    /// SigningWorker participant identity.
    pub target_signing_worker_participant_id: String,
    /// SigningWorker participant-binding digest.
    pub target_signing_worker_participant_binding_digest_b64u: String,
    /// SigningWorker recipient key identifier.
    pub target_signing_worker_recipient_key_id: String,
    /// SigningWorker HPKE public key.
    pub target_signing_worker_hpke_public_key_b64u: String,
    /// SigningWorker HPKE public-key digest.
    pub target_signing_worker_hpke_public_key_digest_b64u: String,
    /// Registered Ed25519 public identity.
    pub registered_public_key_b64u: String,
    /// Immutable key-creation signer slot.
    pub key_creation_signer_slot: u32,
    /// Stable Yao context binding.
    pub stable_context_binding_b64u: String,
    /// Immutable registered Ed25519 signing-key identity.
    pub near_ed25519_signing_key_id: String,
    /// Selected Yao suite identifier.
    pub yao_suite_id: String,
    /// Distinct lane-materialization circuit digest.
    pub circuit_digest_b64u: String,
    /// Expiry timestamp.
    pub expires_at_ms: u64,
}

impl Ed25519YaoLaneJobV1 {
    /// Constructs and validates a lane job.
    pub fn new(job: Self) -> RouterAbProtocolResult<Self> {
        job.validate()?;
        Ok(job)
    }

    /// Validates the exact lane branch and all public bindings.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        if self.kind != "ed25519_yao_lane_job_v1" || self.key_family != "ed25519" {
            return Err(invalid_lane(
                "Ed25519 lane job discriminator or key family is invalid",
            ));
        }
        require_text("operation_id", &self.operation_id)?;
        require_text("enrollment_id", &self.enrollment_id)?;
        require_text("idempotency_key", &self.idempotency_key)?;
        require_text("wallet_id", &self.wallet_id)?;
        require_text("wallet_key_id", &self.wallet_key_id)?;
        self.source.validate()?;
        self.authorization.validate()?;
        require_text(
            "target_material_activation_id",
            &self.target_material_activation_id,
        )?;
        require_text(
            "target_holder_participant_id",
            &self.target_holder_participant_id,
        )?;
        require_digest(
            "target_holder_participant_binding_digest_b64u",
            &self.target_holder_participant_binding_digest_b64u,
        )?;
        require_digest(
            "target_holder_custody_binding_digest_b64u",
            &self.target_holder_custody_binding_digest_b64u,
        )?;
        require_digest(
            "target_holder_hpke_public_key_b64u",
            &self.target_holder_hpke_public_key_b64u,
        )?;
        require_digest(
            "target_holder_hpke_public_key_digest_b64u",
            &self.target_holder_hpke_public_key_digest_b64u,
        )?;
        require_text(
            "target_signing_worker_participant_id",
            &self.target_signing_worker_participant_id,
        )?;
        require_digest(
            "target_signing_worker_participant_binding_digest_b64u",
            &self.target_signing_worker_participant_binding_digest_b64u,
        )?;
        require_text(
            "target_signing_worker_recipient_key_id",
            &self.target_signing_worker_recipient_key_id,
        )?;
        require_digest(
            "target_signing_worker_hpke_public_key_b64u",
            &self.target_signing_worker_hpke_public_key_b64u,
        )?;
        require_digest(
            "target_signing_worker_hpke_public_key_digest_b64u",
            &self.target_signing_worker_hpke_public_key_digest_b64u,
        )?;
        require_digest(
            "registered_public_key_b64u",
            &self.registered_public_key_b64u,
        )?;
        require_positive(
            "key_creation_signer_slot",
            self.key_creation_signer_slot as u64,
        )?;
        require_digest(
            "stable_context_binding_b64u",
            &self.stable_context_binding_b64u,
        )?;
        require_text(
            "near_ed25519_signing_key_id",
            &self.near_ed25519_signing_key_id,
        )?;
        require_text("yao_suite_id", &self.yao_suite_id)?;
        require_digest("circuit_digest_b64u", &self.circuit_digest_b64u)?;
        require_positive("expires_at_ms", self.expires_at_ms)?;
        let expected_operation = self.yao_request_kind;
        match (&self.target, expected_operation) {
            (
                Ed25519YaoLaneTargetV1::CreateLane {
                    lane_id,
                    lane_kind,
                    lane_share_epoch,
                    expected_target_state,
                },
                Ed25519YaoLaneRequestKindV1::LaneProvisioning,
            ) => {
                require_text("target.lane_id", lane_id)?;
                if lane_kind != "linked_device" || expected_target_state != "absent" {
                    return Err(invalid_lane(
                        "lane provisioning requires a linked-device absent target",
                    ));
                }
                require_positive("target.lane_share_epoch", *lane_share_epoch)?;
                if self.source.lane_id == *lane_id {
                    return Err(invalid_lane(
                        "lane provisioning target must differ from source",
                    ));
                }
                if !matches!(
                    self.authorization,
                    Ed25519YaoLaneAuthorizationV1::LinkedDeviceEnrollment { .. }
                ) {
                    return Err(invalid_lane(
                        "lane provisioning requires linked-device authorization",
                    ));
                }
            }
            (
                Ed25519YaoLaneTargetV1::RefreshLane {
                    lane_id,
                    lane_kind,
                    lane_share_epoch,
                    expected_target_state,
                    prior_material_activation,
                },
                Ed25519YaoLaneRequestKindV1::LaneRefresh,
            ) => {
                require_text("target.lane_id", lane_id)?;
                require_text("target.lane_kind", lane_kind)?;
                if expected_target_state != "active_previous_epoch"
                    || *lane_id != self.source.lane_id
                    || *lane_share_epoch <= self.source.lane_share_epoch
                    || prior_material_activation != &self.source.material_activation
                {
                    return Err(invalid_lane(
                        "lane refresh must target the exact active source and next epoch",
                    ));
                }
                prior_material_activation.validate()?;
                if !matches!(
                    self.authorization,
                    Ed25519YaoLaneAuthorizationV1::OwnerLaneRefresh { .. }
                ) {
                    return Err(invalid_lane(
                        "lane refresh requires owner refresh authorization",
                    ));
                }
            }
            _ => {
                return Err(invalid_lane(
                    "lane request kind does not match its target branch",
                ));
            }
        }
        Ok(())
    }

    /// Returns the operation idempotency key.
    pub fn idempotency_key(&self) -> &str {
        &self.idempotency_key
    }

    /// Returns the target lane identifier.
    pub fn target_lane_id(&self) -> &str {
        self.target.lane_id()
    }

    /// Returns the target share epoch.
    pub fn target_lane_share_epoch(&self) -> u64 {
        self.target.lane_share_epoch()
    }

    /// Computes the canonical digest used for package AAD and replay checks.
    pub fn transcript_digest_v1(&self) -> RouterAbProtocolResult<[u8; 32]> {
        self.validate()?;
        let mut bytes = Vec::new();
        push_text(&mut bytes, "seams/rotatable-signing-lanes/ed25519-job/v1");
        push_text(&mut bytes, &self.kind);
        push_text(&mut bytes, self.yao_request_kind.as_str());
        push_text(&mut bytes, &self.operation_id);
        push_text(&mut bytes, &self.enrollment_id);
        push_text(&mut bytes, &self.idempotency_key);
        push_text(&mut bytes, &self.wallet_id);
        push_text(&mut bytes, &self.wallet_key_id);
        push_text(&mut bytes, &self.source.lane_id);
        push_u64(&mut bytes, self.source.lane_share_epoch);
        push_u64(&mut bytes, self.source.revocation_epoch);
        push_text(&mut bytes, self.target_lane_id());
        push_u64(&mut bytes, self.target_lane_share_epoch());
        push_text(&mut bytes, &self.target_material_activation_id);
        push_text(&mut bytes, &self.target_holder_participant_id);
        push_text(
            &mut bytes,
            &self.target_holder_participant_binding_digest_b64u,
        );
        push_text(&mut bytes, &self.target_holder_custody_binding_digest_b64u);
        push_text(&mut bytes, &self.target_holder_hpke_public_key_digest_b64u);
        push_text(&mut bytes, &self.target_signing_worker_participant_id);
        push_text(
            &mut bytes,
            &self.target_signing_worker_participant_binding_digest_b64u,
        );
        push_text(&mut bytes, &self.target_signing_worker_recipient_key_id);
        push_text(
            &mut bytes,
            &self.target_signing_worker_hpke_public_key_digest_b64u,
        );
        push_text(&mut bytes, &self.registered_public_key_b64u);
        push_u64(&mut bytes, self.key_creation_signer_slot as u64);
        push_text(&mut bytes, &self.stable_context_binding_b64u);
        push_text(&mut bytes, &self.near_ed25519_signing_key_id);
        push_text(&mut bytes, &self.yao_suite_id);
        push_text(&mut bytes, &self.circuit_digest_b64u);
        push_u64(&mut bytes, self.expires_at_ms);
        Ok(Sha256::digest(bytes).into())
    }
}

/// Terminal protocol receipt for committed lane packages.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ed25519YaoLaneProtocolCommittedV1 {
    /// Fixed wire discriminator.
    pub kind: String,
    /// Operation identifier.
    pub operation_id: String,
    /// Enrollment identifier.
    pub enrollment_id: String,
    /// Wallet identity.
    pub wallet_id: String,
    /// Wallet-key identity.
    pub wallet_key_id: String,
    /// Source lane identifier.
    pub source_lane_id: String,
    /// Source lane share epoch.
    pub source_lane_share_epoch: u64,
    /// Source revocation epoch.
    pub source_revocation_epoch: u64,
    /// Target lane identifier.
    pub target_lane_id: String,
    /// Target lane share epoch.
    pub target_lane_share_epoch: u64,
    /// Fresh target material activation id.
    pub target_material_activation_id: String,
    /// Registered public identity digest.
    pub public_identity_digest_b64u: String,
    /// Target holder public commitment.
    pub target_holder_public_commitment_b64u: String,
    /// Target SigningWorker public commitment.
    pub target_server_public_commitment_b64u: String,
    /// Holder ciphertext digest set.
    pub target_holder_ciphertext_digest_set_b64u: String,
    /// SigningWorker ciphertext digest set.
    pub target_server_ciphertext_digest_set_b64u: String,
    /// Holder recipient-key digest.
    pub holder_recipient_key_digest_b64u: String,
    /// SigningWorker recipient-key digest.
    pub server_recipient_key_digest_b64u: String,
    /// Canonical transcript hash.
    pub transcript_hash_b64u: String,
    /// Commit timestamp.
    pub committed_at_ms: u64,
}

impl Ed25519YaoLaneProtocolCommittedV1 {
    /// Creates a checked terminal receipt.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        operation_id: impl Into<String>,
        enrollment_id: impl Into<String>,
        wallet_id: impl Into<String>,
        wallet_key_id: impl Into<String>,
        source_lane_id: impl Into<String>,
        source_lane_share_epoch: u64,
        source_revocation_epoch: u64,
        target_lane_id: impl Into<String>,
        target_lane_share_epoch: u64,
        target_material_activation_id: impl Into<String>,
        public_identity_digest_b64u: impl Into<String>,
        target_holder_public_commitment_b64u: impl Into<String>,
        target_server_public_commitment_b64u: impl Into<String>,
        target_holder_ciphertext_digest_set_b64u: impl Into<String>,
        target_server_ciphertext_digest_set_b64u: impl Into<String>,
        holder_recipient_key_digest_b64u: impl Into<String>,
        server_recipient_key_digest_b64u: impl Into<String>,
        transcript_hash_b64u: impl Into<String>,
        committed_at_ms: u64,
    ) -> RouterAbProtocolResult<Self> {
        let receipt = Self {
            kind: "lane_protocol_commit_receipt_v1".to_owned(),
            operation_id: operation_id.into(),
            enrollment_id: enrollment_id.into(),
            wallet_id: wallet_id.into(),
            wallet_key_id: wallet_key_id.into(),
            source_lane_id: source_lane_id.into(),
            source_lane_share_epoch,
            source_revocation_epoch,
            target_lane_id: target_lane_id.into(),
            target_lane_share_epoch,
            target_material_activation_id: target_material_activation_id.into(),
            public_identity_digest_b64u: public_identity_digest_b64u.into(),
            target_holder_public_commitment_b64u: target_holder_public_commitment_b64u.into(),
            target_server_public_commitment_b64u: target_server_public_commitment_b64u.into(),
            target_holder_ciphertext_digest_set_b64u: target_holder_ciphertext_digest_set_b64u
                .into(),
            target_server_ciphertext_digest_set_b64u: target_server_ciphertext_digest_set_b64u
                .into(),
            holder_recipient_key_digest_b64u: holder_recipient_key_digest_b64u.into(),
            server_recipient_key_digest_b64u: server_recipient_key_digest_b64u.into(),
            transcript_hash_b64u: transcript_hash_b64u.into(),
            committed_at_ms,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    /// Validates that this receipt is immutable and complete.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        if self.kind != "lane_protocol_commit_receipt_v1" {
            return Err(invalid_lane(
                "lane protocol receipt discriminator is invalid",
            ));
        }
        for (name, value) in [
            ("operation_id", self.operation_id.as_str()),
            ("enrollment_id", self.enrollment_id.as_str()),
            ("wallet_id", self.wallet_id.as_str()),
            ("wallet_key_id", self.wallet_key_id.as_str()),
            ("source_lane_id", self.source_lane_id.as_str()),
            ("target_lane_id", self.target_lane_id.as_str()),
            (
                "target_material_activation_id",
                self.target_material_activation_id.as_str(),
            ),
        ] {
            require_text(name, value)?;
        }
        require_positive("source_lane_share_epoch", self.source_lane_share_epoch)?;
        require_positive("target_lane_share_epoch", self.target_lane_share_epoch)?;
        require_digest(
            "public_identity_digest_b64u",
            &self.public_identity_digest_b64u,
        )?;
        require_digest(
            "target_holder_public_commitment_b64u",
            &self.target_holder_public_commitment_b64u,
        )?;
        require_digest(
            "target_server_public_commitment_b64u",
            &self.target_server_public_commitment_b64u,
        )?;
        require_digest(
            "target_holder_ciphertext_digest_set_b64u",
            &self.target_holder_ciphertext_digest_set_b64u,
        )?;
        require_digest(
            "target_server_ciphertext_digest_set_b64u",
            &self.target_server_ciphertext_digest_set_b64u,
        )?;
        require_digest(
            "holder_recipient_key_digest_b64u",
            &self.holder_recipient_key_digest_b64u,
        )?;
        require_digest(
            "server_recipient_key_digest_b64u",
            &self.server_recipient_key_digest_b64u,
        )?;
        require_digest("transcript_hash_b64u", &self.transcript_hash_b64u)?;
        require_positive("committed_at_ms", self.committed_at_ms)
    }

    /// Returns true when a delivery can be redelivered under this receipt.
    pub fn accepts_redelivery(&self, operation_id: &str, transcript_hash_b64u: &str) -> bool {
        self.operation_id == operation_id && self.transcript_hash_b64u == transcript_hash_b64u
    }
}

fn require_text(field: &str, value: &str) -> RouterAbProtocolResult<()> {
    if value.is_empty() || !value.bytes().all(|byte| (0x21..=0x7e).contains(&byte)) {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("Ed25519 lane {field} must contain visible ASCII bytes"),
        ));
    }
    Ok(())
}

fn require_digest(field: &str, value: &str) -> RouterAbProtocolResult<()> {
    require_text(field, value)?;
    if value.len() < 16 {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("Ed25519 lane {field} must be a digest"),
        ));
    }
    Ok(())
}

fn require_positive(field: &str, value: u64) -> RouterAbProtocolResult<()> {
    if value == 0 {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLifecycleState,
            format!("Ed25519 lane {field} must be positive"),
        ));
    }
    Ok(())
}

fn push_text(out: &mut Vec<u8>, value: &str) {
    let bytes = value.as_bytes();
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn push_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn invalid_lane(message: &'static str) -> RouterAbProtocolError {
    RouterAbProtocolError::new(RouterAbProtocolErrorCode::MalformedWirePayload, message)
}
