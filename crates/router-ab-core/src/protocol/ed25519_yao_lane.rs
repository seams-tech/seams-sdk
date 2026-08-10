//! Typed Ed25519 Streaming-Yao lane provisioning and refresh records.
//!
//! The lane family is deliberately separate from activation and export.  A
//! lane job carries public bindings only; private role contributions and the
//! random lane offset are owned by the Yao adapter.

use base64ct::{Base64UrlUnpadded, Encoding};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::ed25519_yao::{
    Ed25519YaoDeriverRoleV1, Ed25519YaoEncryptedInputV1, Ed25519YaoEncryptedPackageV1,
    Ed25519YaoInputKindV1,
};
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
        #[serde(rename = "authorizedOperationId")]
        authorized_operation_id: String,
        /// Linked-device enrollment identifier.
        #[serde(rename = "linkedDeviceEnrollmentId")]
        linked_device_enrollment_id: String,
        /// Permission policy digest.
        #[serde(rename = "linkedDevicePermissionDigestB64u")]
        linked_device_permission_digest_b64u: String,
    },
    /// Owner-authorized refresh of an existing lane.
    OwnerLaneRefresh {
        /// Authorized operation identifier.
        #[serde(rename = "authorizedOperationId")]
        authorized_operation_id: String,
        /// Owner refresh authorization digest.
        #[serde(rename = "ownerLaneRefreshDigestB64u")]
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
        #[serde(rename = "laneId")]
        lane_id: String,
        /// Target lane kind; first-release creation is linked-device only.
        #[serde(rename = "laneKind")]
        lane_kind: String,
        /// First share epoch for the target lane.
        #[serde(rename = "laneShareEpoch")]
        lane_share_epoch: String,
        /// Required target pre-state.
        #[serde(rename = "expectedTargetState")]
        expected_target_state: String,
    },
    /// Existing lane target.  Refresh must carry its exact prior activation.
    RefreshLane {
        /// Existing lane identifier.
        #[serde(rename = "laneId")]
        lane_id: String,
        /// Existing lane kind.
        #[serde(rename = "laneKind")]
        lane_kind: String,
        /// Strictly next share epoch.
        #[serde(rename = "laneShareEpoch")]
        lane_share_epoch: String,
        /// Required target pre-state.
        #[serde(rename = "expectedTargetState")]
        expected_target_state: String,
        /// Exact activation being replaced.
        #[serde(
            rename = "priorMaterialActivation",
            with = "lane_material_activation_serde"
        )]
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
    pub fn lane_share_epoch(&self) -> &str {
        match self {
            Self::CreateLane {
                lane_share_epoch, ..
            }
            | Self::RefreshLane {
                lane_share_epoch, ..
            } => lane_share_epoch,
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
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Ed25519YaoLaneSourceV1 {
    /// Source lane identifier.
    pub lane_id: String,
    /// Source lane kind.
    pub lane_kind: String,
    /// Source lane share epoch.
    pub lane_share_epoch: String,
    /// Source lane revocation epoch.
    pub revocation_epoch: u64,
    /// Source holder participant identity.
    pub holder_participant_id: String,
    /// Source SigningWorker participant identity.
    pub signing_worker_participant_id: String,
    /// Source SigningWorker recipient key identifier.
    pub signing_worker_recipient_key_id: String,
    /// Source participant-binding digest.
    pub participant_binding_digest_b64u: String,
    /// Exact source material activation.
    #[serde(with = "lane_material_activation_serde")]
    pub material_activation: MpcMaterialActivationRefV1,
}

impl Ed25519YaoLaneSourceV1 {
    /// Validates the source lane identity.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_text("source.lane_id", &self.lane_id)?;
        require_lane_kind("source.lane_kind", &self.lane_kind)?;
        require_text("source.lane_share_epoch", &self.lane_share_epoch)?;
        require_text("source.holder_participant_id", &self.holder_participant_id)?;
        require_text(
            "source.signing_worker_participant_id",
            &self.signing_worker_participant_id,
        )?;
        require_text(
            "source.signing_worker_recipient_key_id",
            &self.signing_worker_recipient_key_id,
        )?;
        require_digest(
            "source.participant_binding_digest_b64u",
            &self.participant_binding_digest_b64u,
        )?;
        self.material_activation.validate()
    }
}

/// Public target holder recipient binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Ed25519YaoLaneTargetHolderV1 {
    /// Holder participant identity.
    pub participant_id: String,
    /// Holder participant-binding digest.
    pub participant_binding_digest_b64u: String,
    /// Exact custody binding identity receiving the holder package.
    pub custody_binding_id: String,
    /// Holder custody binding digest.
    pub custody_binding_digest_b64u: String,
    /// Holder HPKE public key.
    pub hpke_public_key_b64u: String,
    /// Holder HPKE public-key digest.
    pub hpke_public_key_digest_b64u: String,
}

impl Ed25519YaoLaneTargetHolderV1 {
    /// Validates the target holder recipient binding.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_text("targetHolder.participantId", &self.participant_id)?;
        require_digest(
            "targetHolder.participantBindingDigestB64u",
            &self.participant_binding_digest_b64u,
        )?;
        require_text("targetHolder.custodyBindingId", &self.custody_binding_id)?;
        require_digest(
            "targetHolder.custodyBindingDigestB64u",
            &self.custody_binding_digest_b64u,
        )?;
        require_digest("targetHolder.hpkePublicKeyB64u", &self.hpke_public_key_b64u)?;
        require_digest(
            "targetHolder.hpkePublicKeyDigestB64u",
            &self.hpke_public_key_digest_b64u,
        )
    }
}

/// Public target SigningWorker recipient binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Ed25519YaoLaneTargetSigningWorkerV1 {
    /// SigningWorker participant identity.
    pub participant_id: String,
    /// SigningWorker participant-binding digest.
    pub participant_binding_digest_b64u: String,
    /// SigningWorker recipient key identifier.
    pub recipient_key_id: String,
    /// SigningWorker HPKE public key.
    pub hpke_public_key_b64u: String,
    /// SigningWorker HPKE public-key digest.
    pub hpke_public_key_digest_b64u: String,
}

impl Ed25519YaoLaneTargetSigningWorkerV1 {
    /// Validates the target SigningWorker recipient binding.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_text("targetSigningWorker.participantId", &self.participant_id)?;
        require_digest(
            "targetSigningWorker.participantBindingDigestB64u",
            &self.participant_binding_digest_b64u,
        )?;
        require_text("targetSigningWorker.recipientKeyId", &self.recipient_key_id)?;
        require_digest(
            "targetSigningWorker.hpkePublicKeyB64u",
            &self.hpke_public_key_b64u,
        )?;
        require_digest(
            "targetSigningWorker.hpkePublicKeyDigestB64u",
            &self.hpke_public_key_digest_b64u,
        )
    }
}

/// Ed25519 lane job admitted by the Router boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
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
    /// Target holder recipient binding.
    pub target_holder: Ed25519YaoLaneTargetHolderV1,
    /// Target SigningWorker recipient binding.
    pub target_signing_worker: Ed25519YaoLaneTargetSigningWorkerV1,
    /// Protocol-version discriminator.
    pub protocol_version: String,
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
        if self.target_material_activation_id == self.source.material_activation.activation_id {
            return Err(invalid_lane(
                "lane target material activation must be fresh",
            ));
        }
        self.target_holder.validate()?;
        self.target_signing_worker.validate()?;
        if self.protocol_version != "rotatable_signing_lane_protocol_v1" {
            return Err(invalid_lane("Ed25519 lane protocol version is invalid"));
        }
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
                require_text("target.lane_share_epoch", lane_share_epoch)?;
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
                require_lane_kind("target.lane_kind", lane_kind)?;
                require_text("target.lane_share_epoch", lane_share_epoch)?;
                if expected_target_state != "active_previous_epoch"
                    || *lane_id != self.source.lane_id
                    || self.source.lane_share_epoch == *lane_share_epoch
                    || prior_material_activation != &self.source.material_activation
                {
                    return Err(invalid_lane(
                        "lane refresh must target the exact active source and a fresh opaque epoch",
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
    pub fn target_lane_share_epoch(&self) -> &str {
        self.target.lane_share_epoch()
    }

    /// Returns the canonical job transcript bytes used across Rust and TypeScript.
    pub fn canonical_transcript_bytes_v1(&self) -> RouterAbProtocolResult<Vec<u8>> {
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
        push_text(&mut bytes, &self.source.lane_kind);
        push_text(&mut bytes, &self.source.lane_share_epoch);
        push_u64(&mut bytes, self.source.revocation_epoch);
        push_text(&mut bytes, &self.source.holder_participant_id);
        push_text(&mut bytes, &self.source.signing_worker_participant_id);
        push_text(&mut bytes, &self.source.signing_worker_recipient_key_id);
        push_text(&mut bytes, &self.source.participant_binding_digest_b64u);
        push_activation_ref(&mut bytes, &self.source.material_activation);
        match &self.target {
            Ed25519YaoLaneTargetV1::CreateLane {
                lane_kind,
                expected_target_state,
                ..
            } => {
                push_text(&mut bytes, "create_lane");
                push_text(&mut bytes, lane_kind);
                push_text(&mut bytes, expected_target_state);
            }
            Ed25519YaoLaneTargetV1::RefreshLane {
                lane_kind,
                expected_target_state,
                prior_material_activation,
                ..
            } => {
                push_text(&mut bytes, "refresh_lane");
                push_text(&mut bytes, lane_kind);
                push_text(&mut bytes, expected_target_state);
                push_activation_ref(&mut bytes, prior_material_activation);
            }
        }
        push_text(&mut bytes, self.target_lane_id());
        push_text(&mut bytes, self.target_lane_share_epoch());
        push_text(&mut bytes, &self.target_material_activation_id);
        push_text(&mut bytes, &self.target_holder.participant_id);
        push_text(
            &mut bytes,
            &self.target_holder.participant_binding_digest_b64u,
        );
        push_text(&mut bytes, &self.target_holder.custody_binding_id);
        push_text(&mut bytes, &self.target_holder.custody_binding_digest_b64u);
        push_text(&mut bytes, &self.target_holder.hpke_public_key_b64u);
        push_text(&mut bytes, &self.target_holder.hpke_public_key_digest_b64u);
        push_text(&mut bytes, &self.target_signing_worker.participant_id);
        push_text(
            &mut bytes,
            &self.target_signing_worker.participant_binding_digest_b64u,
        );
        push_text(&mut bytes, &self.target_signing_worker.recipient_key_id);
        push_text(&mut bytes, &self.target_signing_worker.hpke_public_key_b64u);
        push_text(
            &mut bytes,
            &self.target_signing_worker.hpke_public_key_digest_b64u,
        );
        match &self.authorization {
            Ed25519YaoLaneAuthorizationV1::LinkedDeviceEnrollment {
                authorized_operation_id,
                linked_device_enrollment_id,
                linked_device_permission_digest_b64u,
            } => {
                push_text(&mut bytes, "linked_device_enrollment");
                push_text(&mut bytes, authorized_operation_id);
                push_text(&mut bytes, linked_device_enrollment_id);
                push_text(&mut bytes, linked_device_permission_digest_b64u);
            }
            Ed25519YaoLaneAuthorizationV1::OwnerLaneRefresh {
                authorized_operation_id,
                owner_lane_refresh_digest_b64u,
            } => {
                push_text(&mut bytes, "owner_lane_refresh");
                push_text(&mut bytes, authorized_operation_id);
                push_text(&mut bytes, owner_lane_refresh_digest_b64u);
            }
        }
        push_text(&mut bytes, &self.registered_public_key_b64u);
        push_u64(&mut bytes, self.key_creation_signer_slot as u64);
        push_text(&mut bytes, &self.stable_context_binding_b64u);
        push_text(&mut bytes, &self.near_ed25519_signing_key_id);
        push_text(&mut bytes, &self.yao_suite_id);
        push_text(&mut bytes, &self.circuit_digest_b64u);
        push_text(&mut bytes, &self.protocol_version);
        push_u64(&mut bytes, self.expires_at_ms);
        Ok(bytes)
    }

    /// Computes the canonical digest used for package AAD and replay checks.
    pub fn transcript_digest_v1(&self) -> RouterAbProtocolResult<[u8; 32]> {
        Ok(Sha256::digest(self.canonical_transcript_bytes_v1()?).into())
    }

    /// Decodes the stable context binding carried by the lane job.
    pub fn stable_context_binding_v1(&self) -> RouterAbProtocolResult<[u8; 32]> {
        decode_digest32(
            "stable_context_binding_b64u",
            &self.stable_context_binding_b64u,
        )
    }

    /// Derives the opaque Yao session binding from this immutable job.
    pub fn session_v1(&self) -> RouterAbProtocolResult<[u8; 32]> {
        let transcript = self.transcript_digest_v1()?;
        let mut input = b"seams/rotatable-signing-lanes/ed25519-session/v1".to_vec();
        input.extend_from_slice(&transcript);
        Ok(Sha256::digest(input).into())
    }
}

/// Opaque A/B inputs submitted for one admitted lane-provisioning or
/// same-lane refresh execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RouterAbEd25519YaoLaneExecuteRequestV1 {
    /// Immutable lane job pinned at admission.
    pub job: Ed25519YaoLaneJobV1,
    /// Deriver A's recipient-bound opaque input.
    pub deriver_a_input: Ed25519YaoEncryptedInputV1,
    /// Deriver B's recipient-bound opaque input.
    pub deriver_b_input: Ed25519YaoEncryptedInputV1,
}

impl RouterAbEd25519YaoLaneExecuteRequestV1 {
    /// Creates a checked lane execution request.
    pub fn new(
        job: Ed25519YaoLaneJobV1,
        deriver_a_input: Ed25519YaoEncryptedInputV1,
        deriver_b_input: Ed25519YaoEncryptedInputV1,
    ) -> RouterAbProtocolResult<Self> {
        job.validate()?;
        let session = job.session_v1()?;
        let stable = job.stable_context_binding_v1()?;
        validate_lane_input(
            &deriver_a_input,
            Ed25519YaoDeriverRoleV1::DeriverA,
            job.yao_request_kind.operation(),
            session,
            stable,
        )?;
        validate_lane_input(
            &deriver_b_input,
            Ed25519YaoDeriverRoleV1::DeriverB,
            job.yao_request_kind.operation(),
            session,
            stable,
        )?;
        Ok(Self {
            job,
            deriver_a_input,
            deriver_b_input,
        })
    }

    /// Returns the immutable lane job.
    pub const fn job(&self) -> &Ed25519YaoLaneJobV1 {
        &self.job
    }

    /// Returns Deriver A's opaque input.
    pub const fn deriver_a_input(&self) -> &Ed25519YaoEncryptedInputV1 {
        &self.deriver_a_input
    }

    /// Returns Deriver B's opaque input.
    pub const fn deriver_b_input(&self) -> &Ed25519YaoEncryptedInputV1 {
        &self.deriver_b_input
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawRouterAbEd25519YaoLaneExecuteRequestV1 {
    job: Ed25519YaoLaneJobV1,
    deriver_a_input: Ed25519YaoEncryptedInputV1,
    deriver_b_input: Ed25519YaoEncryptedInputV1,
}

impl<'de> Deserialize<'de> for RouterAbEd25519YaoLaneExecuteRequestV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = RawRouterAbEd25519YaoLaneExecuteRequestV1::deserialize(deserializer)?;
        Self::new(raw.job, raw.deriver_a_input, raw.deriver_b_input)
            .map_err(serde::de::Error::custom)
    }
}

/// Public metadata returned after the lane circuit has committed all four
/// recipient packages.  Ciphertexts remain opaque to the Client boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RouterAbEd25519YaoLaneResultV1 {
    /// Immutable job echoed by the Router.
    pub job: Ed25519YaoLaneJobV1,
    /// Canonical transcript hash.
    pub transcript_hash_b64u: String,
    /// Public identity digest covering the checked Ed25519 relation.
    pub public_identity_digest_b64u: String,
    /// Target-holder public commitment.
    pub target_holder_public_commitment_b64u: String,
    /// Target SigningWorker public commitment.
    pub target_server_public_commitment_b64u: String,
    /// Digest of the ordered holder ciphertext set.
    pub target_holder_ciphertext_digest_set_b64u: String,
    /// Digest of the ordered SigningWorker ciphertext set.
    pub target_server_ciphertext_digest_set_b64u: String,
    /// Target holder recipient-key digest.
    pub holder_recipient_key_digest_b64u: String,
    /// Target SigningWorker recipient-key digest.
    pub server_recipient_key_digest_b64u: String,
    /// Four immutable opaque recipient packages.
    pub deriver_a_holder_package: Ed25519YaoEncryptedPackageV1,
    /// Deriver B holder package.
    pub deriver_b_holder_package: Ed25519YaoEncryptedPackageV1,
    /// Deriver A SigningWorker package.
    pub deriver_a_signing_worker_package: Ed25519YaoEncryptedPackageV1,
    /// Deriver B SigningWorker package.
    pub deriver_b_signing_worker_package: Ed25519YaoEncryptedPackageV1,
    /// Commit timestamp.
    pub committed_at_ms: u64,
}

impl RouterAbEd25519YaoLaneResultV1 {
    /// Validates that package metadata is immutable and matches the job.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.job.validate()?;
        let session = self.job.session_v1()?;
        let transcript = decode_digest32("transcript_hash_b64u", &self.transcript_hash_b64u)?;
        if self.job.transcript_digest_v1()? != transcript {
            return Err(invalid_lane(
                "lane result transcript does not match the job",
            ));
        }
        let expected = [
            (
                &self.deriver_a_holder_package,
                Ed25519YaoDeriverRoleV1::DeriverA,
                super::ed25519_yao::Ed25519YaoPackageKindV1::LaneHolder,
            ),
            (
                &self.deriver_b_holder_package,
                Ed25519YaoDeriverRoleV1::DeriverB,
                super::ed25519_yao::Ed25519YaoPackageKindV1::LaneHolder,
            ),
            (
                &self.deriver_a_signing_worker_package,
                Ed25519YaoDeriverRoleV1::DeriverA,
                super::ed25519_yao::Ed25519YaoPackageKindV1::LaneSigningWorker,
            ),
            (
                &self.deriver_b_signing_worker_package,
                Ed25519YaoDeriverRoleV1::DeriverB,
                super::ed25519_yao::Ed25519YaoPackageKindV1::LaneSigningWorker,
            ),
        ];
        for (package, deriver, kind) in expected {
            package.validate()?;
            if package.deriver() != deriver
                || package.kind() != kind
                || package.session() != session
                || package.transcript() != transcript
            {
                return Err(invalid_lane("lane result package binding is inconsistent"));
            }
        }
        for (field, value) in [
            (
                "public_identity_digest_b64u",
                self.public_identity_digest_b64u.as_str(),
            ),
            (
                "target_holder_public_commitment_b64u",
                self.target_holder_public_commitment_b64u.as_str(),
            ),
            (
                "target_server_public_commitment_b64u",
                self.target_server_public_commitment_b64u.as_str(),
            ),
            (
                "target_holder_ciphertext_digest_set_b64u",
                self.target_holder_ciphertext_digest_set_b64u.as_str(),
            ),
            (
                "target_server_ciphertext_digest_set_b64u",
                self.target_server_ciphertext_digest_set_b64u.as_str(),
            ),
            (
                "holder_recipient_key_digest_b64u",
                self.holder_recipient_key_digest_b64u.as_str(),
            ),
            (
                "server_recipient_key_digest_b64u",
                self.server_recipient_key_digest_b64u.as_str(),
            ),
        ] {
            decode_digest32(field, value)?;
        }
        let holder_digest = decode_digest32(
            "target_holder_ciphertext_digest_set_b64u",
            &self.target_holder_ciphertext_digest_set_b64u,
        )?;
        if holder_digest
            != lane_ciphertext_digest_set(
                b"holder",
                &self.deriver_a_holder_package,
                &self.deriver_b_holder_package,
            )
        {
            return Err(invalid_lane(
                "lane holder ciphertext digest set does not match packages",
            ));
        }
        let worker_digest = decode_digest32(
            "target_server_ciphertext_digest_set_b64u",
            &self.target_server_ciphertext_digest_set_b64u,
        )?;
        if worker_digest
            != lane_ciphertext_digest_set(
                b"signing-worker",
                &self.deriver_a_signing_worker_package,
                &self.deriver_b_signing_worker_package,
            )
        {
            return Err(invalid_lane(
                "lane SigningWorker ciphertext digest set does not match packages",
            ));
        }
        if self.holder_recipient_key_digest_b64u
            != self.job.target_holder.hpke_public_key_digest_b64u
            || self.server_recipient_key_digest_b64u
                != self.job.target_signing_worker.hpke_public_key_digest_b64u
        {
            return Err(invalid_lane(
                "lane recipient-key digest does not match the admitted target",
            ));
        }
        require_positive("committed_at_ms", self.committed_at_ms)
    }
}

fn validate_lane_input(
    input: &Ed25519YaoEncryptedInputV1,
    deriver: Ed25519YaoDeriverRoleV1,
    operation: super::ed25519_yao::Ed25519YaoOperationV1,
    session: [u8; 32],
    stable: [u8; 32],
) -> RouterAbProtocolResult<()> {
    input.validate()?;
    if input.kind() != Ed25519YaoInputKindV1::LaneMaterialization
        || input.deriver() != deriver
        || input.operation() != operation
        || input.session() != session
        || input.stable_context_binding() != stable
    {
        return Err(invalid_lane("lane input metadata does not match its job"));
    }
    Ok(())
}

fn decode_digest32(field: &str, value: &str) -> RouterAbProtocolResult<[u8; 32]> {
    let mut decoded = [0_u8; 32];
    Base64UrlUnpadded::decode(value, &mut decoded).map_err(|_| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("Ed25519 lane {field} must be an unpadded base64url 32-byte digest"),
        )
    })?;
    Ok(decoded)
}

fn lane_ciphertext_digest_set(
    recipient_domain: &[u8],
    deriver_a: &Ed25519YaoEncryptedPackageV1,
    deriver_b: &Ed25519YaoEncryptedPackageV1,
) -> [u8; 32] {
    Sha256::new()
        .chain_update(b"seams/rotatable-signing-lanes/ed25519-ciphertext-set/v1")
        .chain_update(recipient_domain)
        .chain_update([deriver_a.deriver().wire_tag()])
        .chain_update([deriver_a.kind().wire_tag()])
        .chain_update(deriver_a.encapsulated_key())
        .chain_update(deriver_a.ciphertext())
        .chain_update([deriver_b.deriver().wire_tag()])
        .chain_update([deriver_b.kind().wire_tag()])
        .chain_update(deriver_b.encapsulated_key())
        .chain_update(deriver_b.ciphertext())
        .finalize()
        .into()
}

/// Terminal protocol receipt for committed lane packages.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
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
    pub source_lane_share_epoch: String,
    /// Source revocation epoch.
    pub source_revocation_epoch: u64,
    /// Exact source material activation.
    #[serde(with = "lane_material_activation_serde")]
    pub source_material_activation: MpcMaterialActivationRefV1,
    /// Target lane identifier.
    pub target_lane_id: String,
    /// Target lane share epoch.
    pub target_lane_share_epoch: String,
    /// Fresh target material activation id.
    pub target_material_activation_id: String,
    /// Curve family discriminator.
    pub key_family: String,
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
        source_lane_share_epoch: impl Into<String>,
        source_revocation_epoch: u64,
        source_material_activation: MpcMaterialActivationRefV1,
        target_lane_id: impl Into<String>,
        target_lane_share_epoch: impl Into<String>,
        target_material_activation_id: impl Into<String>,
        key_family: impl Into<String>,
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
            source_lane_share_epoch: source_lane_share_epoch.into(),
            source_revocation_epoch,
            source_material_activation,
            target_lane_id: target_lane_id.into(),
            target_lane_share_epoch: target_lane_share_epoch.into(),
            target_material_activation_id: target_material_activation_id.into(),
            key_family: key_family.into(),
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
        require_text("source_lane_share_epoch", &self.source_lane_share_epoch)?;
        require_text("target_lane_share_epoch", &self.target_lane_share_epoch)?;
        self.source_material_activation.validate()?;
        if self.key_family != "ed25519" {
            return Err(invalid_lane("lane protocol receipt key family is invalid"));
        }
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

    /// Returns the product receipt's canonical cross-language bytes.
    pub fn canonical_bytes_v1(&self) -> RouterAbProtocolResult<Vec<u8>> {
        self.validate()?;
        let mut bytes = Vec::new();
        push_text(
            &mut bytes,
            "seams/rotatable-signing-lanes/protocol-commit-receipt/v1",
        );
        push_text(&mut bytes, &self.operation_id);
        push_text(&mut bytes, &self.enrollment_id);
        push_text(&mut bytes, &self.wallet_id);
        push_text(&mut bytes, &self.wallet_key_id);
        push_text(&mut bytes, &self.source_lane_id);
        push_text(&mut bytes, &self.source_lane_share_epoch);
        push_u64(&mut bytes, self.source_revocation_epoch);
        let mut activation = Vec::new();
        push_activation_ref(&mut activation, &self.source_material_activation);
        push_bytes(&mut bytes, &activation);
        push_text(&mut bytes, &self.target_lane_id);
        push_text(&mut bytes, &self.target_lane_share_epoch);
        push_text(&mut bytes, &self.target_material_activation_id);
        push_text(&mut bytes, &self.key_family);
        push_digest(&mut bytes, &self.public_identity_digest_b64u)?;
        push_text(&mut bytes, &self.target_holder_public_commitment_b64u);
        push_text(&mut bytes, &self.target_server_public_commitment_b64u);
        push_digest(&mut bytes, &self.target_holder_ciphertext_digest_set_b64u)?;
        push_digest(&mut bytes, &self.target_server_ciphertext_digest_set_b64u)?;
        push_digest(&mut bytes, &self.holder_recipient_key_digest_b64u)?;
        push_digest(&mut bytes, &self.server_recipient_key_digest_b64u)?;
        push_digest(&mut bytes, &self.transcript_hash_b64u)?;
        push_u64(&mut bytes, self.committed_at_ms);
        Ok(bytes)
    }

    /// Computes the digest-addressed product receipt identity.
    pub fn digest_v1(&self) -> RouterAbProtocolResult<[u8; 32]> {
        Ok(Sha256::digest(self.canonical_bytes_v1()?).into())
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

fn require_lane_kind(field: &str, value: &str) -> RouterAbProtocolResult<()> {
    require_text(field, value)?;
    if !matches!(
        value,
        "owner_passkey" | "owner_email_otp" | "linked_device" | "recovery" | "break_glass"
    ) {
        return Err(invalid_lane("Ed25519 lane kind is invalid"));
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
    push_bytes(out, value.as_bytes());
}

fn push_bytes(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value);
}

fn push_digest(out: &mut Vec<u8>, value: &str) -> RouterAbProtocolResult<()> {
    push_bytes(out, &decode_digest32("canonical receipt digest", value)?);
    Ok(())
}

fn push_activation_ref(out: &mut Vec<u8>, activation: &MpcMaterialActivationRefV1) {
    push_text(out, "mpc_material_activation_ref");
    push_text(out, &activation.activation_id);
    push_text(out, &activation.capability);
    push_text(out, &activation.material_owner);
    push_text(out, &activation.key_binding);
    push_text(out, &activation.lifecycle_binding);
    push_text(out, &activation.signing_worker);
}

fn push_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn activation(id: &str) -> MpcMaterialActivationRefV1 {
        MpcMaterialActivationRefV1::new(
            id,
            "capability",
            "owner",
            "key-binding",
            "lifecycle-binding",
            "worker",
        )
        .expect("valid activation")
    }

    fn create_job() -> Ed25519YaoLaneJobV1 {
        Ed25519YaoLaneJobV1 {
            kind: "ed25519_yao_lane_job_v1".to_owned(),
            key_family: "ed25519".to_owned(),
            yao_request_kind: Ed25519YaoLaneRequestKindV1::LaneProvisioning,
            operation_id: "operation".to_owned(),
            enrollment_id: "enrollment".to_owned(),
            idempotency_key: "idempotency".to_owned(),
            wallet_id: "wallet".to_owned(),
            wallet_key_id: "wallet-key".to_owned(),
            source: Ed25519YaoLaneSourceV1 {
                lane_id: "source-lane".to_owned(),
                lane_kind: "owner_passkey".to_owned(),
                lane_share_epoch: "epoch-1".to_owned(),
                revocation_epoch: 0,
                holder_participant_id: "source-holder".to_owned(),
                signing_worker_participant_id: "source-worker".to_owned(),
                signing_worker_recipient_key_id: "source-worker-key".to_owned(),
                participant_binding_digest_b64u: DIGEST.to_owned(),
                material_activation: activation("source-activation"),
            },
            target: Ed25519YaoLaneTargetV1::CreateLane {
                lane_id: "target-lane".to_owned(),
                lane_kind: "linked_device".to_owned(),
                lane_share_epoch: "epoch-1".to_owned(),
                expected_target_state: "absent".to_owned(),
            },
            authorization: Ed25519YaoLaneAuthorizationV1::LinkedDeviceEnrollment {
                authorized_operation_id: "operation".to_owned(),
                linked_device_enrollment_id: "linked-device".to_owned(),
                linked_device_permission_digest_b64u: DIGEST.to_owned(),
            },
            target_material_activation_id: "target-activation".to_owned(),
            target_holder: Ed25519YaoLaneTargetHolderV1 {
                participant_id: "target-holder".to_owned(),
                participant_binding_digest_b64u: DIGEST.to_owned(),
                custody_binding_id: "custody-binding".to_owned(),
                custody_binding_digest_b64u: DIGEST.to_owned(),
                hpke_public_key_b64u: DIGEST.to_owned(),
                hpke_public_key_digest_b64u: DIGEST.to_owned(),
            },
            target_signing_worker: Ed25519YaoLaneTargetSigningWorkerV1 {
                participant_id: "target-worker".to_owned(),
                participant_binding_digest_b64u: DIGEST.to_owned(),
                recipient_key_id: "target-worker-key".to_owned(),
                hpke_public_key_b64u: DIGEST.to_owned(),
                hpke_public_key_digest_b64u: DIGEST.to_owned(),
            },
            protocol_version: "rotatable_signing_lane_protocol_v1".to_owned(),
            registered_public_key_b64u: DIGEST.to_owned(),
            key_creation_signer_slot: 1,
            stable_context_binding_b64u: DIGEST.to_owned(),
            near_ed25519_signing_key_id: "near-key".to_owned(),
            yao_suite_id: "yao-suite".to_owned(),
            circuit_digest_b64u: DIGEST.to_owned(),
            expires_at_ms: 1,
        }
    }

    #[test]
    fn create_allows_equal_opaque_epochs_for_distinct_lanes() {
        let job = create_job();
        job.validate().expect("distinct lanes may both use epoch-1");
        Ed25519YaoLaneProtocolCommittedV1::new(
            "operation",
            "enrollment",
            "wallet",
            "wallet-key",
            "source-lane",
            "epoch-1",
            0,
            activation("source-activation"),
            "target-lane",
            "epoch-1",
            "target-activation",
            "ed25519",
            DIGEST,
            DIGEST,
            DIGEST,
            DIGEST,
            DIGEST,
            DIGEST,
            DIGEST,
            DIGEST,
            1,
        )
        .expect("receipt preserves branch-valid equal opaque epochs");
    }

    #[test]
    fn refresh_rejects_equal_source_and_target_epoch() {
        let mut job = create_job();
        job.yao_request_kind = Ed25519YaoLaneRequestKindV1::LaneRefresh;
        job.target = Ed25519YaoLaneTargetV1::RefreshLane {
            lane_id: job.source.lane_id.clone(),
            lane_kind: job.source.lane_kind.clone(),
            lane_share_epoch: job.source.lane_share_epoch.clone(),
            expected_target_state: "active_previous_epoch".to_owned(),
            prior_material_activation: job.source.material_activation.clone(),
        };
        job.authorization = Ed25519YaoLaneAuthorizationV1::OwnerLaneRefresh {
            authorized_operation_id: job.operation_id.clone(),
            owner_lane_refresh_digest_b64u: DIGEST.to_owned(),
        };
        assert!(job.validate().is_err());
    }

    #[test]
    fn transcript_binds_custody_binding_identity() {
        let job = create_job();
        let digest = job.transcript_digest_v1().expect("original transcript");
        let mut substituted = job;
        substituted.target_holder.custody_binding_id = "different-custody-binding".to_owned();
        assert_ne!(
            substituted
                .transcript_digest_v1()
                .expect("substituted transcript"),
            digest
        );
    }
}

fn invalid_lane(message: &'static str) -> RouterAbProtocolError {
    RouterAbProtocolError::new(RouterAbProtocolErrorCode::MalformedWirePayload, message)
}

/// The shared lifecycle record predates the lane wire contract and keeps its
/// Rust field names for the existing activation protocol.  Lane jobs are
/// emitted in the public camelCase wire shape, so the nested record gets an
/// explicit boundary adapter instead of changing unrelated activation JSON.
mod lane_material_activation_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use super::MpcMaterialActivationRefV1;

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct WireActivation {
        kind: super::super::lifecycle::MpcMaterialActivationRefKindV1,
        activation_id: String,
        capability: String,
        material_owner: String,
        key_binding: String,
        lifecycle_binding: String,
        signing_worker: String,
    }

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct WireActivationRef<'a> {
        kind: super::super::lifecycle::MpcMaterialActivationRefKindV1,
        activation_id: &'a str,
        capability: &'a str,
        material_owner: &'a str,
        key_binding: &'a str,
        lifecycle_binding: &'a str,
        signing_worker: &'a str,
    }

    pub(super) fn serialize<S>(
        value: &MpcMaterialActivationRefV1,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        WireActivationRef {
            kind: value.kind,
            activation_id: &value.activation_id,
            capability: &value.capability,
            material_owner: &value.material_owner,
            key_binding: &value.key_binding,
            lifecycle_binding: &value.lifecycle_binding,
            signing_worker: &value.signing_worker,
        }
        .serialize(serializer)
    }

    pub(super) fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<MpcMaterialActivationRefV1, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = WireActivation::deserialize(deserializer)?;
        if wire.kind
            != super::super::lifecycle::MpcMaterialActivationRefKindV1::MpcMaterialActivationRef
        {
            return Err(serde::de::Error::custom(
                "lane material activation kind is invalid",
            ));
        }
        MpcMaterialActivationRefV1::new(
            wire.activation_id,
            wire.capability,
            wire.material_owner,
            wire.key_binding,
            wire.lifecycle_binding,
            wire.signing_worker,
        )
        .map_err(serde::de::Error::custom)
    }
}
