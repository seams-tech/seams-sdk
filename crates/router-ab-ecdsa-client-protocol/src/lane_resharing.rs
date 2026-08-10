//! Pure, operation-scoped ECDSA additive lane protocol records.
//!
//! The module deliberately keeps private lane material out of every public
//! record. A holder and a SigningWorker exchange only authenticated ciphertext
//! and public commitments; the transcript binds both rounds to one immutable
//! job preamble.

use base64ct::{Base64UrlUnpadded, Encoding};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::PublicKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{EcdsaClientProtocolError, EcdsaMaterialActivationRefV1};

/// Canonical transcript domain for the immutable job projection.
pub const ECDSA_ADDITIVE_LANE_PREAMBLE_DOMAIN_V1: &str =
    "seams/rotatable-signing-lanes/ecdsa-preamble/v1";
/// Canonical transcript domain for the holder round.
pub const ECDSA_ADDITIVE_LANE_HOLDER_ROUND_DOMAIN_V1: &str =
    "seams/rotatable-signing-lanes/ecdsa-holder-round/v1";
/// Canonical transcript domain for the SigningWorker round.
pub const ECDSA_ADDITIVE_LANE_SERVER_ROUND_DOMAIN_V1: &str =
    "seams/rotatable-signing-lanes/ecdsa-server-round/v1";
/// Canonical transcript domain for the complete transcript.
pub const ECDSA_ADDITIVE_LANE_TRANSCRIPT_DOMAIN_V1: &str =
    "seams/rotatable-signing-lanes/ecdsa-transcript/v1";
/// Canonical domain for lane material envelopes.
pub const ECDSA_ADDITIVE_LANE_ENVELOPE_DOMAIN_V1: &str =
    "seams/rotatable-signing-lanes/ecdsa-material-envelope/v1";
/// Canonical domain for server retirement receipts.
pub const ECDSA_SERVER_RETIREMENT_RECEIPT_DOMAIN_V1: &str =
    "seams/rotatable-signing-lanes/ecdsa-server-retirement-receipt/v1";

const ECDSA_ADDITIVE_LANE_ENVELOPE_INFO_V1: &[u8] =
    b"seams/rotatable-signing-lanes/ecdsa-material-envelope/hpke-x25519-hkdf-sha256-aes256gcm/v1";

/// One EVM or Tempo threshold-signing chain bound to a target session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EcdsaLaneChainTargetV1 {
    /// EIP-155 EVM chain.
    Evm {
        /// EIP-155 namespace marker.
        namespace: String,
        /// Numeric chain id.
        chain_id: u64,
        /// Product network slug.
        network_slug: String,
    },
    /// Tempo chain.
    Tempo {
        /// Numeric chain id.
        chain_id: u64,
        /// Product network slug.
        network_slug: String,
    },
}

/// Exact target threshold-session identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EcdsaTargetThresholdSessionBindingV1 {
    /// Chain selected by the session.
    pub chain_target: EcdsaLaneChainTargetV1,
    /// Durable threshold session identity.
    pub threshold_session_id: String,
    /// Participant binding digest.
    pub participant_binding_digest_b64u: String,
}

/// Source capability manifest identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EcdsaSourceCapabilityBindingV1 {
    /// Capability manifest id.
    pub manifest_id: String,
    /// Capability manifest revision.
    pub manifest_revision: u64,
    /// Exact active server generation.
    pub server_generation: String,
    /// ECDSA threshold key id.
    pub ecdsa_threshold_key_id: String,
    /// Relayer key id.
    pub relayer_key_id: String,
}

/// Target capability manifest identity and ordered sessions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EcdsaTargetCapabilityBindingV1 {
    /// Capability manifest id.
    pub manifest_id: String,
    /// Capability manifest revision.
    pub manifest_revision: u64,
    /// ECDSA threshold key id.
    pub ecdsa_threshold_key_id: String,
    /// Ordered, nonempty threshold session set.
    pub ordered_threshold_sessions: Vec<EcdsaTargetThresholdSessionBindingV1>,
}

/// Active source lane pinned at admission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActiveEcdsaLaneProtocolSourceV1 {
    /// Source lane id.
    pub lane_id: String,
    /// Source lane kind.
    pub lane_kind: String,
    /// Source lane share epoch.
    pub lane_share_epoch: String,
    /// Source revocation epoch.
    pub revocation_epoch: u64,
    /// Holder participant id.
    pub holder_participant_id: String,
    /// SigningWorker participant id.
    pub signing_worker_participant_id: String,
    /// SigningWorker recipient key id.
    pub signing_worker_recipient_key_id: String,
    /// Source participant binding digest.
    pub participant_binding_digest_b64u: String,
    /// Exact source material activation.
    pub material_activation: EcdsaMaterialActivationRefV1,
}

/// Target holder recipient binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EcdsaLaneTargetHolderV1 {
    /// Target holder participant id.
    pub participant_id: String,
    /// Target participant binding digest.
    pub participant_binding_digest_b64u: String,
    /// Exact custody binding identity receiving the client package.
    pub custody_binding_id: String,
    /// Target custody binding digest.
    pub custody_binding_digest_b64u: String,
    /// Target holder HPKE public key.
    pub hpke_public_key_b64u: String,
    /// Digest of the target holder HPKE key.
    pub hpke_public_key_digest_b64u: String,
}

/// Target SigningWorker recipient binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EcdsaLaneTargetSigningWorkerV1 {
    /// Target SigningWorker participant id.
    pub participant_id: String,
    /// Target participant binding digest.
    pub participant_binding_digest_b64u: String,
    /// Target recipient key id.
    pub recipient_key_id: String,
    /// Target SigningWorker HPKE public key.
    pub hpke_public_key_b64u: String,
    /// Digest of the target SigningWorker HPKE key.
    pub hpke_public_key_digest_b64u: String,
}

/// Lane creation target branch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum EcdsaLaneTargetOperationV1 {
    /// Create a new linked-device lane.
    CreateLane {
        /// New lane id.
        lane_id: String,
        /// New lane kind.
        lane_kind: String,
        /// First share epoch.
        lane_share_epoch: String,
        /// Required target pre-state.
        expected_target_state: String,
    },
    /// Refresh the existing lane in the next epoch.
    RefreshLane {
        /// Existing lane id.
        lane_id: String,
        /// Existing lane kind.
        lane_kind: String,
        /// Next share epoch.
        lane_share_epoch: String,
        /// Required target pre-state.
        expected_target_state: String,
        /// Prior active material activation.
        prior_material_activation: EcdsaMaterialActivationRefV1,
    },
}

/// Lane authorization branch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EcdsaLaneAuthorizationBindingV1 {
    /// Linked-device enrollment authority.
    LinkedDeviceEnrollment {
        /// Authorized operation id.
        authorized_operation_id: String,
        /// Parent linked-device enrollment id.
        linked_device_enrollment_id: String,
        /// Linked-device permission digest.
        linked_device_permission_digest_b64u: String,
    },
    /// Owner-authorized same-lane refresh authority.
    OwnerLaneRefresh {
        /// Authorized operation id.
        authorized_operation_id: String,
        /// Owner refresh authorization digest.
        owner_lane_refresh_digest_b64u: String,
    },
}

/// Immutable ECDSA additive lane job admitted by the product boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EcdsaAdditiveLaneJobV1 {
    /// Wire kind.
    pub kind: String,
    /// Protocol operation id.
    pub operation_id: String,
    /// Parent enrollment id.
    pub enrollment_id: String,
    /// Operation idempotency key.
    pub idempotency_key: String,
    /// Wallet id.
    pub wallet_id: String,
    /// Wallet key id.
    pub wallet_key_id: String,
    /// Pinned source lane.
    pub source: ActiveEcdsaLaneProtocolSourceV1,
    /// Target holder binding.
    pub target_holder: EcdsaLaneTargetHolderV1,
    /// Target SigningWorker binding.
    pub target_signing_worker: EcdsaLaneTargetSigningWorkerV1,
    /// Fresh target activation id.
    pub target_material_activation_id: String,
    /// Protocol version.
    pub protocol_version: String,
    /// Operation expiry.
    pub expires_at_ms: u64,
    /// Create or refresh operation branch.
    pub target: EcdsaLaneTargetOperationV1,
    /// Exactly one authorization branch.
    pub authorization: EcdsaLaneAuthorizationBindingV1,
    /// ECDSA curve branch marker.
    pub key_family: String,
    /// EVM-family signing-key slot id.
    pub evm_family_signing_key_slot_id: String,
    /// Threshold compressed public key.
    pub threshold_public_key33_b64u: String,
    /// EVM address (canonical product string).
    pub evm_address: String,
    /// Source capability manifest binding.
    pub source_capability: EcdsaSourceCapabilityBindingV1,
    /// Target capability manifest binding.
    pub target_capability: EcdsaTargetCapabilityBindingV1,
    /// Source holder verifying share.
    pub source_holder_verifying_share33_b64u: String,
    /// Source server verifying share.
    pub source_server_verifying_share33_b64u: String,
    /// Authenticated resharing channel binding digest.
    pub reshare_channel_binding_digest_b64u: String,
    /// Canonical transcript encoding marker.
    pub transcript_encoding: String,
}

impl EcdsaAdditiveLaneJobV1 {
    /// Validates branch, identity, recipient, activation, and session fields.
    pub fn validate(&self) -> Result<(), EcdsaClientProtocolError> {
        require_exact(&self.kind, "ecdsa_additive_lane_job_v1")?;
        require_exact(&self.key_family, "ecdsa_secp256k1")?;
        require_exact(&self.protocol_version, "rotatable_signing_lane_protocol_v1")?;
        require_exact(
            &self.transcript_encoding,
            "ecdsa_additive_lane_transcript_v1",
        )?;
        for value in [
            &self.operation_id,
            &self.enrollment_id,
            &self.idempotency_key,
            &self.wallet_id,
            &self.wallet_key_id,
            &self.target_material_activation_id,
            &self.evm_family_signing_key_slot_id,
            &self.evm_address,
            &self.source_holder_verifying_share33_b64u,
            &self.source_server_verifying_share33_b64u,
        ] {
            require_non_empty(value)?;
        }
        if self.expires_at_ms == 0 {
            return Err(EcdsaClientProtocolError::InvalidShape);
        }
        validate_source(&self.source)?;
        validate_holder(&self.target_holder)?;
        validate_worker(&self.target_signing_worker)?;
        validate_target(&self.target, &self.source)?;
        validate_authorization(&self.authorization, &self.target)?;
        validate_activation(&self.source.material_activation)?;
        validate_public_key_b64(&self.threshold_public_key33_b64u)?;
        validate_public_key_b64(&self.source_holder_verifying_share33_b64u)?;
        validate_public_key_b64(&self.source_server_verifying_share33_b64u)?;
        validate_digest_b64(&self.source.participant_binding_digest_b64u)?;
        validate_digest_b64(&self.target_holder.participant_binding_digest_b64u)?;
        validate_digest_b64(&self.target_holder.custody_binding_digest_b64u)?;
        validate_digest_b64(&self.target_holder.hpke_public_key_digest_b64u)?;
        validate_digest_b64(&self.target_signing_worker.participant_binding_digest_b64u)?;
        validate_digest_b64(&self.target_signing_worker.hpke_public_key_digest_b64u)?;
        validate_digest_b64(&self.reshare_channel_binding_digest_b64u)?;
        validate_target_capability(&self.target_capability)?;
        validate_source_capability(&self.source_capability)?;
        Ok(())
    }

    /// Returns the canonical preamble record bytes.
    pub fn canonical_preamble_bytes(&self) -> Result<Vec<u8>, EcdsaClientProtocolError> {
        self.validate()?;
        let mut out = Vec::new();
        text(&mut out, ECDSA_ADDITIVE_LANE_PREAMBLE_DOMAIN_V1);
        encode_job(&mut out, self)?;
        Ok(out)
    }

    /// Returns the operation-scoped preamble digest.
    pub fn preamble_hash(&self) -> Result<[u8; 32], EcdsaClientProtocolError> {
        digest32(&self.canonical_preamble_bytes()?)
    }
}

/// Public holder-round output committed after target share sampling.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EcdsaAdditiveLaneHolderRoundV1 {
    /// Preamble digest.
    pub preamble_hash_b64u: String,
    /// Target holder compressed public commitment.
    pub target_holder_public_commitment33_b64u: String,
    /// Digest of the encrypted transient delta.
    pub encrypted_delta_ciphertext_digest_b64u: String,
    /// Digest of ciphertext sealed to target holder custody.
    pub sealed_target_holder_material_digest_b64u: String,
    /// Holder attestation over the exact round.
    pub holder_attestation_b64u: String,
    /// Holder commit timestamp.
    pub holder_committed_at_ms: u64,
}

impl EcdsaAdditiveLaneHolderRoundV1 {
    /// Returns canonical holder-round bytes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, EcdsaClientProtocolError> {
        validate_holder_round(self)?;
        let mut out = Vec::new();
        text(&mut out, ECDSA_ADDITIVE_LANE_HOLDER_ROUND_DOMAIN_V1);
        digest_lp(&mut out, &self.preamble_hash_b64u)?;
        text(&mut out, &self.target_holder_public_commitment33_b64u);
        digest_lp(&mut out, &self.encrypted_delta_ciphertext_digest_b64u)?;
        digest_lp(&mut out, &self.sealed_target_holder_material_digest_b64u)?;
        text(&mut out, &self.holder_attestation_b64u);
        u64_be(&mut out, self.holder_committed_at_ms);
        Ok(out)
    }

    /// Returns the holder-round digest.
    pub fn hash(&self) -> Result<[u8; 32], EcdsaClientProtocolError> {
        digest32(&self.canonical_bytes()?)
    }
}

/// Public server-round output committed after delta verification and rebind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EcdsaAdditiveLaneServerRoundV1 {
    /// Preamble digest.
    pub preamble_hash_b64u: String,
    /// Holder-round digest.
    pub holder_round_hash_b64u: String,
    /// Target SigningWorker compressed public commitment.
    pub target_server_public_commitment33_b64u: String,
    /// Digest of ciphertext sealed to the target SigningWorker.
    pub sealed_target_server_material_digest_b64u: String,
    /// Digest of the ordered target threshold-session set.
    pub target_threshold_session_set_digest_b64u: String,
    /// Digest of the checked public identity relation.
    pub public_identity_relation_digest_b64u: String,
    /// SigningWorker attestation over the exact round.
    pub server_attestation_b64u: String,
    /// SigningWorker commit timestamp.
    pub server_committed_at_ms: u64,
}

impl EcdsaAdditiveLaneServerRoundV1 {
    /// Returns canonical server-round bytes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, EcdsaClientProtocolError> {
        validate_server_round(self)?;
        let mut out = Vec::new();
        text(&mut out, ECDSA_ADDITIVE_LANE_SERVER_ROUND_DOMAIN_V1);
        digest_lp(&mut out, &self.preamble_hash_b64u)?;
        digest_lp(&mut out, &self.holder_round_hash_b64u)?;
        text(&mut out, &self.target_server_public_commitment33_b64u);
        digest_lp(&mut out, &self.sealed_target_server_material_digest_b64u)?;
        digest_lp(&mut out, &self.target_threshold_session_set_digest_b64u)?;
        digest_lp(&mut out, &self.public_identity_relation_digest_b64u)?;
        text(&mut out, &self.server_attestation_b64u);
        u64_be(&mut out, self.server_committed_at_ms);
        Ok(out)
    }

    /// Returns the server-round digest.
    pub fn hash(&self) -> Result<[u8; 32], EcdsaClientProtocolError> {
        digest32(&self.canonical_bytes()?)
    }
}

/// Complete digest-linked ECDSA additive lane transcript.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EcdsaAdditiveLaneTranscriptV1 {
    /// Preamble digest.
    pub preamble_hash_b64u: String,
    /// Holder-round digest.
    pub holder_round_hash_b64u: String,
    /// Server-round digest.
    pub server_round_hash_b64u: String,
}

impl EcdsaAdditiveLaneTranscriptV1 {
    /// Returns canonical transcript bytes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, EcdsaClientProtocolError> {
        validate_digest_b64(&self.preamble_hash_b64u)?;
        validate_digest_b64(&self.holder_round_hash_b64u)?;
        validate_digest_b64(&self.server_round_hash_b64u)?;
        let mut out = Vec::new();
        text(&mut out, ECDSA_ADDITIVE_LANE_TRANSCRIPT_DOMAIN_V1);
        digest_lp(&mut out, &self.preamble_hash_b64u)?;
        digest_lp(&mut out, &self.holder_round_hash_b64u)?;
        digest_lp(&mut out, &self.server_round_hash_b64u)?;
        Ok(out)
    }

    /// Returns the final transcript digest.
    pub fn hash(&self) -> Result<[u8; 32], EcdsaClientProtocolError> {
        digest32(&self.canonical_bytes()?)
    }
}

/// Builds a holder round after validating all public output fields.
pub fn prepare_ecdsa_additive_lane_holder_round_v1(
    job: &EcdsaAdditiveLaneJobV1,
    target_holder_public_commitment33_b64u: String,
    encrypted_delta_ciphertext_digest_b64u: String,
    sealed_target_holder_material_digest_b64u: String,
    holder_attestation_b64u: String,
    holder_committed_at_ms: u64,
) -> Result<EcdsaAdditiveLaneHolderRoundV1, EcdsaClientProtocolError> {
    let round = EcdsaAdditiveLaneHolderRoundV1 {
        preamble_hash_b64u: b64(&job.preamble_hash()?),
        target_holder_public_commitment33_b64u,
        encrypted_delta_ciphertext_digest_b64u,
        sealed_target_holder_material_digest_b64u,
        holder_attestation_b64u,
        holder_committed_at_ms,
    };
    validate_holder_round(&round)?;
    Ok(round)
}

/// Builds a server round and checks the holder round's preamble binding.
pub fn complete_ecdsa_additive_lane_server_round_v1(
    job: &EcdsaAdditiveLaneJobV1,
    holder_round: &EcdsaAdditiveLaneHolderRoundV1,
    target_server_public_commitment33_b64u: String,
    sealed_target_server_material_digest_b64u: String,
    target_threshold_session_set_digest_b64u: String,
    public_identity_relation_digest_b64u: String,
    server_attestation_b64u: String,
    server_committed_at_ms: u64,
) -> Result<EcdsaAdditiveLaneServerRoundV1, EcdsaClientProtocolError> {
    let preamble_hash = b64(&job.preamble_hash()?);
    if holder_round.preamble_hash_b64u != preamble_hash {
        return Err(EcdsaClientProtocolError::InvalidShape);
    }
    let round = EcdsaAdditiveLaneServerRoundV1 {
        preamble_hash_b64u: preamble_hash,
        holder_round_hash_b64u: b64(&holder_round.hash()?),
        target_server_public_commitment33_b64u,
        sealed_target_server_material_digest_b64u,
        target_threshold_session_set_digest_b64u,
        public_identity_relation_digest_b64u,
        server_attestation_b64u,
        server_committed_at_ms,
    };
    validate_server_round(&round)?;
    Ok(round)
}

/// Verifies exact round hashes and transcript ordering for one immutable job.
pub fn verify_ecdsa_additive_lane_transcript_v1(
    job: &EcdsaAdditiveLaneJobV1,
    holder_round: &EcdsaAdditiveLaneHolderRoundV1,
    server_round: &EcdsaAdditiveLaneServerRoundV1,
    transcript: &EcdsaAdditiveLaneTranscriptV1,
) -> Result<[u8; 32], EcdsaClientProtocolError> {
    let preamble_hash = b64(&job.preamble_hash()?);
    let holder_hash = b64(&holder_round.hash()?);
    let server_hash = b64(&server_round.hash()?);
    if holder_round.preamble_hash_b64u != preamble_hash
        || server_round.preamble_hash_b64u != preamble_hash
        || server_round.holder_round_hash_b64u != holder_hash
        || transcript.preamble_hash_b64u != preamble_hash
        || transcript.holder_round_hash_b64u != holder_hash
        || transcript.server_round_hash_b64u != server_hash
    {
        return Err(EcdsaClientProtocolError::InvalidShape);
    }
    transcript.hash()
}

/// Exact ECDSA capability-manifest identity in a server retirement receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EcdsaLaneManifestIdentityV1 {
    /// Manifest id.
    pub manifest_id: String,
    /// Manifest revision.
    pub manifest_revision: u64,
}

/// Exact terminal retirement receipt for one lane activation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EcdsaServerRetirementReceiptV1 {
    /// Receipt kind.
    pub kind: String,
    /// Manifest identity.
    pub manifest: EcdsaLaneManifestIdentityV1,
    /// Exact material activation.
    pub material_activation: EcdsaMaterialActivationRefV1,
    /// Wallet key id.
    pub wallet_key_id: String,
    /// Lane id.
    pub lane_id: String,
    /// Lane share epoch.
    pub lane_share_epoch: String,
    /// Lane revocation epoch.
    pub revocation_epoch: u64,
    /// Retirement reason.
    pub retirement_reason: String,
    /// Retirement correlation id.
    pub retirement_correlation_id: String,
    /// Retirement request digest.
    pub retirement_request_digest_b64u: String,
    /// Exact server generation.
    pub server_generation: String,
    /// Exact lifecycle id.
    pub lifecycle_id: String,
    /// Digest of the receipt record without this field.
    pub receipt_digest_b64u: String,
    /// Retirement timestamp.
    pub retired_at_ms: u64,
}

impl EcdsaServerRetirementReceiptV1 {
    /// Canonical receipt bytes excluding the self-referential digest field.
    pub fn canonical_bytes_without_digest(&self) -> Result<Vec<u8>, EcdsaClientProtocolError> {
        require_exact(&self.kind, "ecdsa_server_retirement_receipt_v1")?;
        require_non_empty(&self.wallet_key_id)?;
        require_non_empty(&self.lane_id)?;
        require_non_empty(&self.lane_share_epoch)?;
        require_non_empty(&self.retirement_reason)?;
        require_non_empty(&self.retirement_correlation_id)?;
        require_non_empty(&self.server_generation)?;
        require_non_empty(&self.lifecycle_id)?;
        if self.retired_at_ms == 0 || self.manifest.manifest_revision == 0 {
            return Err(EcdsaClientProtocolError::InvalidShape);
        }
        if !matches!(
            self.retirement_reason.as_str(),
            "lane_revoked" | "device_compromise" | "agent_compromise" | "rotation"
        ) {
            return Err(EcdsaClientProtocolError::InvalidShape);
        }
        validate_activation(&self.material_activation)?;
        validate_digest_b64(&self.retirement_request_digest_b64u)?;
        let mut out = Vec::new();
        text(&mut out, ECDSA_SERVER_RETIREMENT_RECEIPT_DOMAIN_V1);
        text(&mut out, &self.kind);
        text(&mut out, &self.manifest.manifest_id);
        u64_be(&mut out, self.manifest.manifest_revision);
        activation_lp(&mut out, &self.material_activation)?;
        text(&mut out, &self.wallet_key_id);
        text(&mut out, &self.lane_id);
        text(&mut out, &self.lane_share_epoch);
        u64_be(&mut out, self.revocation_epoch);
        text(&mut out, &self.retirement_reason);
        text(&mut out, &self.retirement_correlation_id);
        digest_lp(&mut out, &self.retirement_request_digest_b64u)?;
        text(&mut out, &self.server_generation);
        text(&mut out, &self.lifecycle_id);
        u64_be(&mut out, self.retired_at_ms);
        Ok(out)
    }

    /// Computes the exact receipt digest.
    pub fn digest(&self) -> Result<[u8; 32], EcdsaClientProtocolError> {
        digest32(&self.canonical_bytes_without_digest()?)
    }
}

/// Verifies an exact retirement receipt against the pinned lane activation.
pub fn verify_ecdsa_server_retirement_receipt_v1(
    receipt: &EcdsaServerRetirementReceiptV1,
    expected_manifest: &EcdsaLaneManifestIdentityV1,
    expected_activation: &EcdsaMaterialActivationRefV1,
    expected_wallet_key_id: &str,
    expected_lane_id: &str,
    expected_lane_share_epoch: &str,
    expected_revocation_epoch: u64,
    expected_retirement_correlation_id: &str,
    expected_retirement_request_digest_b64u: &str,
    expected_server_generation: &str,
    expected_lifecycle_id: &str,
) -> Result<(), EcdsaClientProtocolError> {
    if receipt.manifest != *expected_manifest
        || receipt.material_activation != *expected_activation
        || receipt.wallet_key_id != expected_wallet_key_id
        || receipt.lane_id != expected_lane_id
        || receipt.lane_share_epoch != expected_lane_share_epoch
        || receipt.revocation_epoch != expected_revocation_epoch
        || receipt.retirement_correlation_id != expected_retirement_correlation_id
        || receipt.retirement_request_digest_b64u != expected_retirement_request_digest_b64u
        || receipt.server_generation != expected_server_generation
        || receipt.lifecycle_id != expected_lifecycle_id
    {
        return Err(EcdsaClientProtocolError::InvalidShape);
    }
    let digest = receipt.digest()?;
    if receipt.receipt_digest_b64u != b64(&digest) {
        return Err(EcdsaClientProtocolError::InvalidShape);
    }
    Ok(())
}

/// One HPKE envelope used for a target holder or SigningWorker material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EcdsaLaneEncryptedPayloadV1 {
    /// Wire kind.
    pub kind: String,
    /// Canonical recipient X25519 key in base64url.
    pub recipient_public_key_b64u: String,
    /// Digest of exact associated data.
    pub aad_digest_b64u: String,
    /// HPKE encapsulated key.
    pub encapped_key_b64u: String,
    /// HPKE ciphertext and authentication tag.
    pub ciphertext_b64u: String,
}

impl EcdsaLaneEncryptedPayloadV1 {
    /// Returns canonical envelope bytes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, EcdsaClientProtocolError> {
        require_exact(&self.kind, "ecdsa_additive_lane_encrypted_payload_v1")?;
        let recipient = decode_x25519_key_b64(&self.recipient_public_key_b64u)?;
        let aad = decode_fixed_digest(&self.aad_digest_b64u)?;
        let encapped = decode_fixed_bytes::<32>(&self.encapped_key_b64u)?;
        let ciphertext = decode_b64(&self.ciphertext_b64u)?;
        if ciphertext.len() <= 16 {
            return Err(EcdsaClientProtocolError::InvalidShape);
        }
        let mut out = Vec::new();
        text(&mut out, ECDSA_ADDITIVE_LANE_ENVELOPE_DOMAIN_V1);
        text(&mut out, &self.kind);
        lp(&mut out, &recipient);
        lp(&mut out, &aad);
        lp(&mut out, &encapped);
        lp(&mut out, &ciphertext);
        Ok(out)
    }

    /// Returns the envelope digest used by round records.
    pub fn digest(&self) -> Result<[u8; 32], EcdsaClientProtocolError> {
        digest32(&self.canonical_bytes()?)
    }
}

/// Seals target material to a holder or SigningWorker HPKE recipient.
#[cfg(feature = "hpke")]
pub fn seal_ecdsa_lane_payload_v1(
    recipient_public_key_b64u: &str,
    aad_digest: &[u8; 32],
    plaintext: &[u8],
    seal_seed: [u8; 32],
) -> Result<EcdsaLaneEncryptedPayloadV1, EcdsaClientProtocolError> {
    use hpke_ng::{Aes256Gcm, DhKemX25519HkdfSha256, HkdfSha256, Hpke, Kem};
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;
    if plaintext.is_empty() {
        return Err(EcdsaClientProtocolError::InvalidShape);
    }
    let recipient = decode_x25519_key_b64(recipient_public_key_b64u)?;
    let recipient_key = DhKemX25519HkdfSha256::pk_from_bytes(&recipient)
        .map_err(|_| EcdsaClientProtocolError::InvalidShape)?;
    let mut rng = ChaCha20Rng::from_seed(seal_seed);
    let (encapped, ciphertext) = Hpke::<DhKemX25519HkdfSha256, HkdfSha256, Aes256Gcm>::seal_base(
        &mut rng,
        &recipient_key,
        ECDSA_ADDITIVE_LANE_ENVELOPE_INFO_V1,
        aad_digest,
        plaintext,
    )
    .map_err(|_| EcdsaClientProtocolError::HpkeFailed)?;
    let encapped_key_b64u = b64(encapped.as_ref());
    let ciphertext_b64u = b64(&ciphertext);
    Ok(EcdsaLaneEncryptedPayloadV1 {
        kind: "ecdsa_additive_lane_encrypted_payload_v1".to_owned(),
        recipient_public_key_b64u: recipient_public_key_b64u.to_owned(),
        aad_digest_b64u: b64(aad_digest),
        encapped_key_b64u,
        ciphertext_b64u,
    })
}

/// Opens one exact target-material envelope at the private worker boundary.
#[cfg(feature = "hpke")]
pub fn open_ecdsa_lane_payload_v1(
    payload: &EcdsaLaneEncryptedPayloadV1,
    recipient_private_key32: &[u8; 32],
    expected_aad_digest: &[u8; 32],
) -> Result<Vec<u8>, EcdsaClientProtocolError> {
    use hpke_ng::{Aes256Gcm, DhKemX25519HkdfSha256, HkdfSha256, Hpke, Kem};
    if decode_fixed_digest(&payload.aad_digest_b64u)? != *expected_aad_digest {
        return Err(EcdsaClientProtocolError::InvalidShape);
    }
    let private_key = DhKemX25519HkdfSha256::sk_from_bytes(recipient_private_key32)
        .map_err(|_| EcdsaClientProtocolError::InvalidShape)?;
    let encapped = decode_fixed_bytes::<32>(&payload.encapped_key_b64u)?;
    let encapped = DhKemX25519HkdfSha256::enc_from_bytes(&encapped)
        .map_err(|_| EcdsaClientProtocolError::InvalidShape)?;
    let ciphertext = decode_b64(&payload.ciphertext_b64u)?;
    Hpke::<DhKemX25519HkdfSha256, HkdfSha256, Aes256Gcm>::open_base(
        &encapped,
        &private_key,
        ECDSA_ADDITIVE_LANE_ENVELOPE_INFO_V1,
        expected_aad_digest,
        &ciphertext,
    )
    .map_err(|_| EcdsaClientProtocolError::HpkeFailed)
}

fn encode_job(
    out: &mut Vec<u8>,
    job: &EcdsaAdditiveLaneJobV1,
) -> Result<(), EcdsaClientProtocolError> {
    text(out, &job.operation_id);
    text(out, &job.enrollment_id);
    text(out, &job.idempotency_key);
    text(out, &job.wallet_id);
    text(out, &job.wallet_key_id);
    encode_source(out, &job.source)?;
    encode_holder(out, &job.target_holder)?;
    encode_worker(out, &job.target_signing_worker)?;
    text(out, &job.target_material_activation_id);
    text(out, &job.protocol_version);
    u64_be(out, job.expires_at_ms);
    encode_target(out, &job.target)?;
    encode_authorization(out, &job.authorization)?;
    text(out, &job.kind);
    text(out, &job.key_family);
    text(out, &job.evm_family_signing_key_slot_id);
    text(out, &job.threshold_public_key33_b64u);
    text(out, &job.evm_address);
    encode_source_capability(out, &job.source_capability);
    encode_target_capability(out, &job.target_capability)?;
    text(out, &job.source_holder_verifying_share33_b64u);
    text(out, &job.source_server_verifying_share33_b64u);
    text(out, &job.reshare_channel_binding_digest_b64u);
    text(out, &job.transcript_encoding);
    Ok(())
}

fn encode_source(
    out: &mut Vec<u8>,
    source: &ActiveEcdsaLaneProtocolSourceV1,
) -> Result<(), EcdsaClientProtocolError> {
    text(out, &source.lane_id);
    text(out, &source.lane_kind);
    text(out, &source.lane_share_epoch);
    u64_be(out, source.revocation_epoch);
    text(out, &source.holder_participant_id);
    text(out, &source.signing_worker_participant_id);
    text(out, &source.signing_worker_recipient_key_id);
    text(out, &source.participant_binding_digest_b64u);
    activation_lp(out, &source.material_activation)
}

fn encode_holder(
    out: &mut Vec<u8>,
    holder: &EcdsaLaneTargetHolderV1,
) -> Result<(), EcdsaClientProtocolError> {
    text(out, &holder.participant_id);
    text(out, &holder.participant_binding_digest_b64u);
    text(out, &holder.custody_binding_id);
    digest_text(out, &holder.custody_binding_digest_b64u)?;
    text(out, &holder.hpke_public_key_b64u);
    digest_text(out, &holder.hpke_public_key_digest_b64u)
}

fn encode_worker(
    out: &mut Vec<u8>,
    worker: &EcdsaLaneTargetSigningWorkerV1,
) -> Result<(), EcdsaClientProtocolError> {
    text(out, &worker.participant_id);
    text(out, &worker.participant_binding_digest_b64u);
    text(out, &worker.recipient_key_id);
    text(out, &worker.hpke_public_key_b64u);
    digest_text(out, &worker.hpke_public_key_digest_b64u)
}

fn encode_target(
    out: &mut Vec<u8>,
    target: &EcdsaLaneTargetOperationV1,
) -> Result<(), EcdsaClientProtocolError> {
    match target {
        EcdsaLaneTargetOperationV1::CreateLane {
            lane_id,
            lane_kind,
            lane_share_epoch,
            expected_target_state,
        } => {
            text(out, "create_lane");
            text(out, lane_id);
            text(out, lane_kind);
            text(out, lane_share_epoch);
            text(out, expected_target_state);
        }
        EcdsaLaneTargetOperationV1::RefreshLane {
            lane_id,
            lane_kind,
            lane_share_epoch,
            expected_target_state,
            prior_material_activation,
        } => {
            text(out, "refresh_lane");
            text(out, lane_id);
            text(out, lane_kind);
            text(out, lane_share_epoch);
            text(out, expected_target_state);
            activation_lp(out, prior_material_activation)?;
        }
    }
    Ok(())
}

fn encode_authorization(
    out: &mut Vec<u8>,
    authorization: &EcdsaLaneAuthorizationBindingV1,
) -> Result<(), EcdsaClientProtocolError> {
    match authorization {
        EcdsaLaneAuthorizationBindingV1::LinkedDeviceEnrollment {
            authorized_operation_id,
            linked_device_enrollment_id,
            linked_device_permission_digest_b64u,
        } => {
            text(out, "linked_device_enrollment");
            text(out, authorized_operation_id);
            text(out, linked_device_enrollment_id);
            digest_text(out, linked_device_permission_digest_b64u)?;
        }
        EcdsaLaneAuthorizationBindingV1::OwnerLaneRefresh {
            authorized_operation_id,
            owner_lane_refresh_digest_b64u,
        } => {
            text(out, "owner_lane_refresh");
            text(out, authorized_operation_id);
            digest_text(out, owner_lane_refresh_digest_b64u)?;
        }
    }
    Ok(())
}

fn encode_source_capability(out: &mut Vec<u8>, capability: &EcdsaSourceCapabilityBindingV1) {
    text(out, &capability.manifest_id);
    u64_be(out, capability.manifest_revision);
    text(out, &capability.server_generation);
    text(out, &capability.ecdsa_threshold_key_id);
    text(out, &capability.relayer_key_id);
}

fn encode_target_capability(
    out: &mut Vec<u8>,
    capability: &EcdsaTargetCapabilityBindingV1,
) -> Result<(), EcdsaClientProtocolError> {
    text(out, &capability.manifest_id);
    u64_be(out, capability.manifest_revision);
    text(out, &capability.ecdsa_threshold_key_id);
    nonempty_count(out, capability.ordered_threshold_sessions.len())?;
    for session in &capability.ordered_threshold_sessions {
        encode_chain_target(out, &session.chain_target)?;
        text(out, &session.threshold_session_id);
        digest_text(out, &session.participant_binding_digest_b64u)?;
    }
    Ok(())
}

fn encode_chain_target(
    out: &mut Vec<u8>,
    target: &EcdsaLaneChainTargetV1,
) -> Result<(), EcdsaClientProtocolError> {
    match target {
        EcdsaLaneChainTargetV1::Evm {
            namespace,
            chain_id,
            network_slug,
        } => {
            text(out, "evm");
            text(out, namespace);
            u64_be(out, *chain_id);
            text(out, network_slug);
        }
        EcdsaLaneChainTargetV1::Tempo {
            chain_id,
            network_slug,
        } => {
            text(out, "tempo");
            u64_be(out, *chain_id);
            text(out, network_slug);
        }
    }
    Ok(())
}

fn validate_source(
    source: &ActiveEcdsaLaneProtocolSourceV1,
) -> Result<(), EcdsaClientProtocolError> {
    for value in [
        &source.lane_id,
        &source.lane_kind,
        &source.lane_share_epoch,
        &source.holder_participant_id,
        &source.signing_worker_participant_id,
        &source.signing_worker_recipient_key_id,
    ] {
        require_non_empty(value)?;
    }
    validate_digest_b64(&source.participant_binding_digest_b64u)
}

fn validate_holder(holder: &EcdsaLaneTargetHolderV1) -> Result<(), EcdsaClientProtocolError> {
    for value in [
        &holder.participant_id,
        &holder.custody_binding_id,
        &holder.hpke_public_key_b64u,
    ] {
        require_non_empty(value)?;
    }
    validate_digest_b64(&holder.participant_binding_digest_b64u)?;
    validate_digest_b64(&holder.custody_binding_digest_b64u)?;
    validate_digest_b64(&holder.hpke_public_key_digest_b64u)?;
    decode_x25519_key_b64(&holder.hpke_public_key_b64u).map(|_| ())
}

fn validate_worker(
    worker: &EcdsaLaneTargetSigningWorkerV1,
) -> Result<(), EcdsaClientProtocolError> {
    for value in [
        &worker.participant_id,
        &worker.recipient_key_id,
        &worker.hpke_public_key_b64u,
    ] {
        require_non_empty(value)?;
    }
    validate_digest_b64(&worker.participant_binding_digest_b64u)?;
    validate_digest_b64(&worker.hpke_public_key_digest_b64u)?;
    decode_x25519_key_b64(&worker.hpke_public_key_b64u).map(|_| ())
}

fn validate_target(
    target: &EcdsaLaneTargetOperationV1,
    source: &ActiveEcdsaLaneProtocolSourceV1,
) -> Result<(), EcdsaClientProtocolError> {
    match target {
        EcdsaLaneTargetOperationV1::CreateLane {
            lane_id,
            lane_kind,
            lane_share_epoch,
            expected_target_state,
        } => {
            require_exact(lane_kind, "linked_device")?;
            require_exact(expected_target_state, "absent")?;
            if lane_id == &source.lane_id || lane_share_epoch.is_empty() {
                return Err(EcdsaClientProtocolError::InvalidShape);
            }
        }
        EcdsaLaneTargetOperationV1::RefreshLane {
            lane_id,
            lane_kind,
            lane_share_epoch,
            expected_target_state,
            prior_material_activation,
        } => {
            require_non_empty(lane_kind)?;
            require_exact(expected_target_state, "active_previous_epoch")?;
            if lane_id != &source.lane_id
                || lane_share_epoch.is_empty()
                || prior_material_activation != &source.material_activation
            {
                return Err(EcdsaClientProtocolError::InvalidShape);
            }
        }
    }
    Ok(())
}

fn validate_authorization(
    authorization: &EcdsaLaneAuthorizationBindingV1,
    target: &EcdsaLaneTargetOperationV1,
) -> Result<(), EcdsaClientProtocolError> {
    match (target, authorization) {
        (
            EcdsaLaneTargetOperationV1::CreateLane { .. },
            EcdsaLaneAuthorizationBindingV1::LinkedDeviceEnrollment {
                authorized_operation_id,
                linked_device_enrollment_id,
                linked_device_permission_digest_b64u,
            },
        ) => {
            require_non_empty(authorized_operation_id)?;
            require_non_empty(linked_device_enrollment_id)?;
            validate_digest_b64(linked_device_permission_digest_b64u)
        }
        (
            EcdsaLaneTargetOperationV1::RefreshLane { .. },
            EcdsaLaneAuthorizationBindingV1::OwnerLaneRefresh {
                authorized_operation_id,
                owner_lane_refresh_digest_b64u,
            },
        ) => {
            require_non_empty(authorized_operation_id)?;
            validate_digest_b64(owner_lane_refresh_digest_b64u)
        }
        _ => Err(EcdsaClientProtocolError::InvalidShape),
    }
}

fn validate_source_capability(
    capability: &EcdsaSourceCapabilityBindingV1,
) -> Result<(), EcdsaClientProtocolError> {
    if capability.manifest_revision == 0 {
        return Err(EcdsaClientProtocolError::InvalidShape);
    }
    for value in [
        &capability.manifest_id,
        &capability.server_generation,
        &capability.ecdsa_threshold_key_id,
        &capability.relayer_key_id,
    ] {
        require_non_empty(value)?;
    }
    Ok(())
}

fn validate_target_capability(
    capability: &EcdsaTargetCapabilityBindingV1,
) -> Result<(), EcdsaClientProtocolError> {
    if capability.manifest_revision == 0 || capability.ordered_threshold_sessions.is_empty() {
        return Err(EcdsaClientProtocolError::InvalidShape);
    }
    require_non_empty(&capability.manifest_id)?;
    require_non_empty(&capability.ecdsa_threshold_key_id)?;
    for session in &capability.ordered_threshold_sessions {
        require_non_empty(&session.threshold_session_id)?;
        validate_digest_b64(&session.participant_binding_digest_b64u)?;
        match &session.chain_target {
            EcdsaLaneChainTargetV1::Evm {
                namespace,
                network_slug,
                ..
            } => {
                require_exact(namespace, "eip155")?;
                require_non_empty(network_slug)?;
            }
            EcdsaLaneChainTargetV1::Tempo { network_slug, .. } => require_non_empty(network_slug)?,
        }
    }
    Ok(())
}

fn validate_activation(
    activation: &EcdsaMaterialActivationRefV1,
) -> Result<(), EcdsaClientProtocolError> {
    activation.lane_validate()
}

fn validate_holder_round(
    round: &EcdsaAdditiveLaneHolderRoundV1,
) -> Result<(), EcdsaClientProtocolError> {
    validate_digest_b64(&round.preamble_hash_b64u)?;
    validate_public_key_b64(&round.target_holder_public_commitment33_b64u)?;
    validate_digest_b64(&round.encrypted_delta_ciphertext_digest_b64u)?;
    validate_digest_b64(&round.sealed_target_holder_material_digest_b64u)?;
    require_non_empty(&round.holder_attestation_b64u)?;
    if round.holder_committed_at_ms == 0 {
        return Err(EcdsaClientProtocolError::InvalidShape);
    }
    Ok(())
}

fn validate_server_round(
    round: &EcdsaAdditiveLaneServerRoundV1,
) -> Result<(), EcdsaClientProtocolError> {
    validate_digest_b64(&round.preamble_hash_b64u)?;
    validate_digest_b64(&round.holder_round_hash_b64u)?;
    validate_public_key_b64(&round.target_server_public_commitment33_b64u)?;
    validate_digest_b64(&round.sealed_target_server_material_digest_b64u)?;
    validate_digest_b64(&round.target_threshold_session_set_digest_b64u)?;
    validate_digest_b64(&round.public_identity_relation_digest_b64u)?;
    require_non_empty(&round.server_attestation_b64u)?;
    if round.server_committed_at_ms == 0 {
        return Err(EcdsaClientProtocolError::InvalidShape);
    }
    Ok(())
}

fn activation_lp(
    out: &mut Vec<u8>,
    activation: &EcdsaMaterialActivationRefV1,
) -> Result<(), EcdsaClientProtocolError> {
    let bytes = activation.lane_canonical_bytes()?;
    lp(out, &bytes);
    Ok(())
}

fn digest_text(out: &mut Vec<u8>, value: &str) -> Result<(), EcdsaClientProtocolError> {
    let bytes = decode_fixed_digest(value)?;
    lp(out, &bytes);
    Ok(())
}

fn digest_lp(out: &mut Vec<u8>, value: &str) -> Result<(), EcdsaClientProtocolError> {
    digest_text(out, value)
}

fn text(out: &mut Vec<u8>, value: &str) {
    lp(out, value.as_bytes());
}

fn lp(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn u64_be(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn nonempty_count(out: &mut Vec<u8>, count: usize) -> Result<(), EcdsaClientProtocolError> {
    if count == 0 || count > u32::MAX as usize {
        return Err(EcdsaClientProtocolError::InvalidShape);
    }
    out.extend_from_slice(&(count as u32).to_be_bytes());
    Ok(())
}

fn digest32(bytes: &[u8]) -> Result<[u8; 32], EcdsaClientProtocolError> {
    Sha256::digest(bytes)
        .as_slice()
        .try_into()
        .map_err(|_| EcdsaClientProtocolError::InvalidShape)
}

fn b64(bytes: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(bytes)
}

fn decode_b64(value: &str) -> Result<Vec<u8>, EcdsaClientProtocolError> {
    let bytes =
        Base64UrlUnpadded::decode_vec(value).map_err(|_| EcdsaClientProtocolError::InvalidShape)?;
    if Base64UrlUnpadded::encode_string(&bytes) != value {
        return Err(EcdsaClientProtocolError::InvalidShape);
    }
    Ok(bytes)
}

fn decode_fixed_bytes<const N: usize>(value: &str) -> Result<[u8; N], EcdsaClientProtocolError> {
    let bytes = decode_b64(value)?;
    if bytes.len() != N {
        return Err(EcdsaClientProtocolError::InvalidShape);
    }
    bytes
        .try_into()
        .map_err(|_| EcdsaClientProtocolError::InvalidShape)
}

fn decode_fixed_digest(value: &str) -> Result<[u8; 32], EcdsaClientProtocolError> {
    decode_fixed_bytes::<32>(value)
}

fn validate_digest_b64(value: &str) -> Result<(), EcdsaClientProtocolError> {
    decode_fixed_digest(value).map(|_| ())
}

fn validate_public_key_b64(value: &str) -> Result<(), EcdsaClientProtocolError> {
    let bytes = decode_fixed_bytes::<33>(value)?;
    let key =
        PublicKey::from_sec1_bytes(&bytes).map_err(|_| EcdsaClientProtocolError::InvalidShape)?;
    if key.to_encoded_point(true).as_bytes() != bytes {
        return Err(EcdsaClientProtocolError::InvalidShape);
    }
    Ok(())
}

fn decode_x25519_key_b64(value: &str) -> Result<[u8; 32], EcdsaClientProtocolError> {
    decode_fixed_bytes::<32>(value)
}

fn require_non_empty(value: &str) -> Result<(), EcdsaClientProtocolError> {
    if value.is_empty() || value.trim() != value {
        return Err(EcdsaClientProtocolError::InvalidShape);
    }
    Ok(())
}

fn require_exact(value: &str, expected: &str) -> Result<(), EcdsaClientProtocolError> {
    if value == expected {
        return Ok(());
    }
    Err(EcdsaClientProtocolError::InvalidShape)
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use k256::SecretKey;

    fn b64_bytes<const N: usize>(value: u8) -> String {
        b64(&[value; N])
    }

    fn public_key(value: u8) -> String {
        let key = SecretKey::from_slice(&[value; 32]).expect("valid test scalar");
        b64(key.public_key().to_encoded_point(true).as_bytes())
    }

    fn activation(id: &str) -> EcdsaMaterialActivationRefV1 {
        EcdsaMaterialActivationRefV1 {
            kind: crate::EcdsaMaterialActivationRefKindV1::MpcMaterialActivationRef,
            activation_id: id.to_owned(),
            capability: "capability-1".to_owned(),
            material_owner: "wallet-1".to_owned(),
            key_binding: "key-binding-1".to_owned(),
            lifecycle_binding: "lifecycle-binding-1".to_owned(),
            signing_worker: "worker-1".to_owned(),
        }
    }

    fn job() -> EcdsaAdditiveLaneJobV1 {
        EcdsaAdditiveLaneJobV1 {
            kind: "ecdsa_additive_lane_job_v1".to_owned(),
            operation_id: "operation-1".to_owned(),
            enrollment_id: "enrollment-1".to_owned(),
            idempotency_key: "idempotency-1".to_owned(),
            wallet_id: "wallet-1".to_owned(),
            wallet_key_id: "wallet-key-1".to_owned(),
            source: ActiveEcdsaLaneProtocolSourceV1 {
                lane_id: "owner-lane".to_owned(),
                lane_kind: "owner_passkey".to_owned(),
                lane_share_epoch: "epoch-1".to_owned(),
                revocation_epoch: 0,
                holder_participant_id: "holder-1".to_owned(),
                signing_worker_participant_id: "worker-1".to_owned(),
                signing_worker_recipient_key_id: "recipient-1".to_owned(),
                participant_binding_digest_b64u: b64_bytes::<32>(1),
                material_activation: activation("activation-1"),
            },
            target_holder: EcdsaLaneTargetHolderV1 {
                participant_id: "holder-2".to_owned(),
                participant_binding_digest_b64u: b64_bytes::<32>(2),
                custody_binding_id: "custody-2".to_owned(),
                custody_binding_digest_b64u: b64_bytes::<32>(3),
                hpke_public_key_b64u: b64_bytes::<32>(4),
                hpke_public_key_digest_b64u: b64_bytes::<32>(5),
            },
            target_signing_worker: EcdsaLaneTargetSigningWorkerV1 {
                participant_id: "worker-2".to_owned(),
                participant_binding_digest_b64u: b64_bytes::<32>(6),
                recipient_key_id: "recipient-2".to_owned(),
                hpke_public_key_b64u: b64_bytes::<32>(7),
                hpke_public_key_digest_b64u: b64_bytes::<32>(8),
            },
            target_material_activation_id: "activation-2".to_owned(),
            protocol_version: "rotatable_signing_lane_protocol_v1".to_owned(),
            expires_at_ms: 1_000,
            target: EcdsaLaneTargetOperationV1::CreateLane {
                lane_id: "linked-lane".to_owned(),
                lane_kind: "linked_device".to_owned(),
                lane_share_epoch: "epoch-1".to_owned(),
                expected_target_state: "absent".to_owned(),
            },
            authorization: EcdsaLaneAuthorizationBindingV1::LinkedDeviceEnrollment {
                authorized_operation_id: "operation-1".to_owned(),
                linked_device_enrollment_id: "linked-enrollment-1".to_owned(),
                linked_device_permission_digest_b64u: b64_bytes::<32>(9),
            },
            key_family: "ecdsa_secp256k1".to_owned(),
            evm_family_signing_key_slot_id: "evm-slot-1".to_owned(),
            threshold_public_key33_b64u: public_key(9),
            evm_address: "0x0000000000000000000000000000000000000001".to_owned(),
            source_capability: EcdsaSourceCapabilityBindingV1 {
                manifest_id: "manifest-1".to_owned(),
                manifest_revision: 1,
                server_generation: "generation-1".to_owned(),
                ecdsa_threshold_key_id: "threshold-key-1".to_owned(),
                relayer_key_id: "relayer-key-1".to_owned(),
            },
            target_capability: EcdsaTargetCapabilityBindingV1 {
                manifest_id: "manifest-2".to_owned(),
                manifest_revision: 1,
                ecdsa_threshold_key_id: "threshold-key-1".to_owned(),
                ordered_threshold_sessions: vec![EcdsaTargetThresholdSessionBindingV1 {
                    chain_target: EcdsaLaneChainTargetV1::Evm {
                        namespace: "eip155".to_owned(),
                        chain_id: 1,
                        network_slug: "mainnet".to_owned(),
                    },
                    threshold_session_id: "session-1".to_owned(),
                    participant_binding_digest_b64u: b64_bytes::<32>(10),
                }],
            },
            source_holder_verifying_share33_b64u: public_key(2),
            source_server_verifying_share33_b64u: public_key(3),
            reshare_channel_binding_digest_b64u: b64_bytes::<32>(11),
            transcript_encoding: "ecdsa_additive_lane_transcript_v1".to_owned(),
        }
    }

    fn rounds() -> (
        EcdsaAdditiveLaneJobV1,
        EcdsaAdditiveLaneHolderRoundV1,
        EcdsaAdditiveLaneServerRoundV1,
        EcdsaAdditiveLaneTranscriptV1,
    ) {
        let job = job();
        let holder = prepare_ecdsa_additive_lane_holder_round_v1(
            &job,
            public_key(12),
            b64_bytes::<32>(13),
            b64_bytes::<32>(14),
            b64_bytes::<16>(15),
            2_000,
        )
        .expect("holder round");
        let server = complete_ecdsa_additive_lane_server_round_v1(
            &job,
            &holder,
            public_key(16),
            b64_bytes::<32>(17),
            b64_bytes::<32>(18),
            b64_bytes::<32>(19),
            b64_bytes::<16>(20),
            3_000,
        )
        .expect("server round");
        let transcript = EcdsaAdditiveLaneTranscriptV1 {
            preamble_hash_b64u: b64(&job.preamble_hash().expect("preamble")),
            holder_round_hash_b64u: b64(&holder.hash().expect("holder hash")),
            server_round_hash_b64u: b64(&server.hash().expect("server hash")),
        };
        (job, holder, server, transcript)
    }

    #[test]
    fn transcript_is_digest_linked_and_rejects_substitution() {
        let (job, holder, server, transcript) = rounds();
        let hash = verify_ecdsa_additive_lane_transcript_v1(&job, &holder, &server, &transcript)
            .expect("transcript");
        assert_eq!(hash, transcript.hash().expect("transcript hash"));

        let mut altered = transcript.clone();
        altered.server_round_hash_b64u = b64_bytes::<32>(0xaa);
        assert!(
            verify_ecdsa_additive_lane_transcript_v1(&job, &holder, &server, &altered).is_err()
        );
    }

    #[test]
    fn operation_branch_binds_source_and_target_lane() {
        let mut job = job();
        let create_hash = job.preamble_hash().expect("create hash");
        job.target = EcdsaLaneTargetOperationV1::RefreshLane {
            lane_id: "owner-lane".to_owned(),
            lane_kind: "owner_passkey".to_owned(),
            lane_share_epoch: "epoch-2".to_owned(),
            expected_target_state: "active_previous_epoch".to_owned(),
            prior_material_activation: activation("activation-1"),
        };
        job.authorization = EcdsaLaneAuthorizationBindingV1::OwnerLaneRefresh {
            authorized_operation_id: "operation-1".to_owned(),
            owner_lane_refresh_digest_b64u: b64_bytes::<32>(21),
        };
        let refresh_hash = job.preamble_hash().expect("refresh hash");
        assert_ne!(create_hash, refresh_hash);
    }
}
