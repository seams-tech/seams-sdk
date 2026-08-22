use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use router_ab_core::{RouterAbProtocolError, RouterAbProtocolErrorCode, RouterAbProtocolResult};
#[cfg(feature = "workers-rs")]
use router_ab_ecdsa_client_protocol::{
    complete_ecdsa_additive_lane_server_round_v1, ecdsa_lane_public_identity_relation_digest_v1,
};
use router_ab_ecdsa_client_protocol::{
    EcdsaAdditiveLaneHolderRoundV1, EcdsaAdditiveLaneJobV1, EcdsaAdditiveLaneServerRoundV1,
    EcdsaAdditiveLaneTranscriptV1, EcdsaLaneEncryptedPayloadV1, EcdsaLaneManifestIdentityV1,
    EcdsaLaneTargetOperationV1, EcdsaMaterialActivationRefV1, EcdsaServerRetirementReceiptV1,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{
    CloudflareActiveSigningWorkerStateLookupV1, CloudflareSigningWorkerLaneMaterialIdentityV1,
    CloudflareSigningWorkerNormalSigningLaneMaterialLookupV1,
};

const ECDSA_ACTIVE_SERVER_MATERIAL_KIND_V1: &str = "ecdsa_additive_lane_active_server_material_v1";
#[cfg(feature = "workers-rs")]
const ECDSA_SERVER_ATTESTATION_DOMAIN_V1: &[u8] =
    b"seams/rotatable-signing-lanes/ecdsa-server-attestation/v1";

fn invalid(message: impl Into<String>) -> RouterAbProtocolError {
    RouterAbProtocolError::new(RouterAbProtocolErrorCode::MalformedWirePayload, message)
}

fn map_protocol_error(label: &'static str, error: impl core::fmt::Debug) -> RouterAbProtocolError {
    invalid(format!("{label}: {error:?}"))
}

#[cfg(feature = "workers-rs")]
fn bounded_json_parse_error(error: &impl core::fmt::Display) -> String {
    const MAX_DETAIL_CHARS: usize = 256;
    let detail = error.to_string();
    let mut bounded = detail.chars().take(MAX_DETAIL_CHARS).collect::<String>();
    if detail.chars().count() > MAX_DETAIL_CHARS {
        bounded.push('…');
    }
    bounded
}

fn decode_b64<const N: usize>(label: &'static str, value: &str) -> RouterAbProtocolResult<[u8; N]> {
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| invalid(format!("{label} is not unpadded base64url")))?
        .try_into()
        .map_err(|_| invalid(format!("{label} must decode to {N} bytes")))
}

fn b64(value: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(value)
}

fn ct_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0_u8;
    for (left, right) in left.iter().zip(right) {
        difference |= left ^ right;
    }
    difference == 0
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareEcdsaRegistrationSourceDerivationV1 {
    #[serde(rename = "application_binding_digest_b64u")]
    pub application_binding_digest_b64u: String,
    #[serde(rename = "client_share_retry_counter")]
    pub client_share_retry_counter: u32,
}

impl CloudflareEcdsaRegistrationSourceDerivationV1 {
    pub(crate) fn validate(&self) -> RouterAbProtocolResult<()> {
        decode_b64::<32>(
            "ECDSA registration source application binding digest",
            &self.application_binding_digest_b64u,
        )?;
        Ok(())
    }
}

/// Persistence-boundary selector for one exact active ECDSA source share.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum CloudflareEcdsaLaneSourceMaterialLookupV1 {
    LaneMaterial {
        lookup: CloudflareSigningWorkerNormalSigningLaneMaterialLookupV1,
    },
    RegistrationActivation {
        lookup: CloudflareActiveSigningWorkerStateLookupV1,
        source_derivation: CloudflareEcdsaRegistrationSourceDerivationV1,
    },
}

impl CloudflareEcdsaLaneSourceMaterialLookupV1 {
    pub fn validate_for_job(&self, job: &EcdsaAdditiveLaneJobV1) -> RouterAbProtocolResult<()> {
        match self {
            Self::LaneMaterial { lookup } => {
                lookup.validate()?;
                let identity = &lookup.identity;
                if identity.key_family
                    != super::CloudflareSigningWorkerLaneKeyFamilyV1::EcdsaSecp256k1
                    || identity.wallet_id != job.wallet_id
                    || identity.wallet_key_id != job.wallet_key_id
                    || identity.target_lane_id != job.source.lane_id()
                    || identity.target_lane_share_epoch != job.source.lane_share_epoch()
                    || identity.target_material_activation_id
                        != job.source.material_activation().activation_id
                {
                    return Err(invalid("ECDSA lane source identity does not match the job"));
                }
            }
            Self::RegistrationActivation {
                lookup,
                source_derivation,
            } => {
                lookup.validate()?;
                source_derivation.validate()?;
                if lookup.account_id != job.wallet_id
                    || lookup.material_activation_id
                        != job.source.material_activation().activation_id
                    || lookup.signing_worker_id != job.source.signing_worker_id()
                {
                    return Err(invalid(
                        "ECDSA registration source activation does not match the job",
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Exact client output admitted to private SigningWorker execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CloudflareSigningWorkerEcdsaLaneExecuteRequestV1 {
    pub job: EcdsaAdditiveLaneJobV1,
    pub holder_round: EcdsaAdditiveLaneHolderRoundV1,
    pub holder_package: EcdsaLaneEncryptedPayloadV1,
    pub encrypted_delta: EcdsaLaneEncryptedPayloadV1,
    pub source_material: CloudflareEcdsaLaneSourceMaterialLookupV1,
}

impl CloudflareSigningWorkerEcdsaLaneExecuteRequestV1 {
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.job
            .validate()
            .map_err(|error| map_protocol_error("ECDSA lane job is invalid", error))?;
        let preamble = self
            .job
            .preamble_hash()
            .map_err(|error| map_protocol_error("ECDSA lane preamble is invalid", error))?;
        if !ct_eq(
            self.holder_round.preamble_hash_b64u.as_bytes(),
            b64(&preamble).as_bytes(),
        ) {
            return Err(invalid("ECDSA holder round does not bind the admitted job"));
        }
        let holder_digest = self
            .holder_package
            .digest()
            .map_err(|error| map_protocol_error("ECDSA holder package is invalid", error))?;
        let delta_digest = self
            .encrypted_delta
            .digest()
            .map_err(|error| map_protocol_error("ECDSA delta package is invalid", error))?;
        let expected_holder = decode_b64::<32>(
            "holder_round.sealed_target_holder_material_digest_b64u",
            &self.holder_round.sealed_target_holder_material_digest_b64u,
        )?;
        let expected_delta = decode_b64::<32>(
            "holder_round.encrypted_delta_ciphertext_digest_b64u",
            &self.holder_round.encrypted_delta_ciphertext_digest_b64u,
        )?;
        if !ct_eq(&holder_digest, &expected_holder) || !ct_eq(&delta_digest, &expected_delta) {
            return Err(invalid(
                "ECDSA holder artifacts do not match the holder round",
            ));
        }
        self.source_material.validate_for_job(&self.job)
    }
}

/// Canonical receipt returned to the product lifecycle store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CloudflareEcdsaLaneProtocolCommitReceiptV1 {
    pub kind: String,
    pub operation_id: String,
    pub enrollment_id: String,
    pub wallet_id: String,
    pub wallet_key_id: String,
    pub source_lane_id: String,
    pub source_lane_share_epoch: String,
    pub source_revocation_epoch: u64,
    pub source_material_activation: EcdsaMaterialActivationRefV1,
    pub target_lane_id: String,
    pub target_lane_share_epoch: String,
    pub target_material_activation_id: String,
    pub key_family: String,
    pub public_identity_digest_b64u: String,
    pub target_holder_public_commitment_b64u: String,
    pub target_server_public_commitment_b64u: String,
    pub target_holder_ciphertext_digest_set_b64u: String,
    pub target_server_ciphertext_digest_set_b64u: String,
    pub holder_recipient_key_digest_b64u: String,
    pub server_recipient_key_digest_b64u: String,
    pub transcript_hash_b64u: String,
    pub committed_at_ms: u64,
}

impl CloudflareEcdsaLaneProtocolCommitReceiptV1 {
    pub fn validate_for_job(&self, job: &EcdsaAdditiveLaneJobV1) -> RouterAbProtocolResult<()> {
        let (target_lane_id, target_lane_share_epoch) = target_lane(job);
        if self.kind != "lane_protocol_commit_receipt_v1"
            || self.operation_id != job.operation_id
            || self.enrollment_id != job.enrollment_id
            || self.wallet_id != job.wallet_id
            || self.wallet_key_id != job.wallet_key_id
            || self.source_lane_id != job.source.lane_id()
            || self.source_lane_share_epoch != job.source.lane_share_epoch()
            || self.source_revocation_epoch != job.source.revocation_epoch()
            || self.source_material_activation != *job.source.material_activation()
            || self.target_lane_id != target_lane_id
            || self.target_lane_share_epoch != target_lane_share_epoch
            || self.target_material_activation_id != job.target_material_activation_id
            || self.key_family != "ecdsa_secp256k1"
            || self.holder_recipient_key_digest_b64u
                != job.target_holder.hpke_public_key_digest_b64u
            || self.server_recipient_key_digest_b64u
                != job.target_signing_worker.hpke_public_key_digest_b64u
            || self.committed_at_ms == 0
        {
            return Err(invalid(
                "ECDSA protocol receipt does not match the admitted job",
            ));
        }
        for digest in [
            &self.public_identity_digest_b64u,
            &self.target_holder_ciphertext_digest_set_b64u,
            &self.target_server_ciphertext_digest_set_b64u,
            &self.holder_recipient_key_digest_b64u,
            &self.server_recipient_key_digest_b64u,
            &self.transcript_hash_b64u,
        ] {
            decode_b64::<32>("ECDSA protocol receipt digest", digest)?;
        }
        Ok(())
    }

    pub fn canonical_bytes_v1(&self) -> RouterAbProtocolResult<Vec<u8>> {
        let mut bytes = Vec::new();
        canonical_text(
            &mut bytes,
            "seams/rotatable-signing-lanes/protocol-commit-receipt/v1",
        );
        for value in [
            &self.operation_id,
            &self.enrollment_id,
            &self.wallet_id,
            &self.wallet_key_id,
            &self.source_lane_id,
            &self.source_lane_share_epoch,
        ] {
            canonical_text(&mut bytes, value);
        }
        bytes.extend_from_slice(&self.source_revocation_epoch.to_be_bytes());
        let mut activation = Vec::new();
        canonical_activation(&mut activation, &self.source_material_activation);
        canonical_bytes(&mut bytes, &activation);
        for value in [
            &self.target_lane_id,
            &self.target_lane_share_epoch,
            &self.target_material_activation_id,
            &self.key_family,
        ] {
            canonical_text(&mut bytes, value);
        }
        canonical_digest(&mut bytes, &self.public_identity_digest_b64u)?;
        canonical_text(&mut bytes, &self.target_holder_public_commitment_b64u);
        canonical_text(&mut bytes, &self.target_server_public_commitment_b64u);
        for value in [
            &self.target_holder_ciphertext_digest_set_b64u,
            &self.target_server_ciphertext_digest_set_b64u,
            &self.holder_recipient_key_digest_b64u,
            &self.server_recipient_key_digest_b64u,
            &self.transcript_hash_b64u,
        ] {
            canonical_digest(&mut bytes, value)?;
        }
        bytes.extend_from_slice(&self.committed_at_ms.to_be_bytes());
        Ok(bytes)
    }

    pub fn digest_b64u_v1(&self) -> RouterAbProtocolResult<String> {
        Ok(b64(&Sha256::digest(self.canonical_bytes_v1()?)))
    }
}

fn canonical_bytes(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value);
}

fn canonical_text(out: &mut Vec<u8>, value: &str) {
    canonical_bytes(out, value.as_bytes());
}

fn canonical_digest(out: &mut Vec<u8>, value: &str) -> RouterAbProtocolResult<()> {
    canonical_bytes(out, &decode_b64::<32>("canonical receipt digest", value)?);
    Ok(())
}

fn canonical_activation(out: &mut Vec<u8>, value: &EcdsaMaterialActivationRefV1) {
    canonical_text(out, "mpc_material_activation_ref");
    for field in [
        &value.activation_id,
        &value.capability,
        &value.material_owner,
        &value.key_binding,
        &value.lifecycle_binding,
        &value.signing_worker,
    ] {
        canonical_text(out, field);
    }
}

/// Full committed transcript retained only in private D1 for exact replay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CloudflareEcdsaLaneCommittedTranscriptV1 {
    pub job: EcdsaAdditiveLaneJobV1,
    pub holder_round: EcdsaAdditiveLaneHolderRoundV1,
    pub server_round: EcdsaAdditiveLaneServerRoundV1,
    pub transcript: EcdsaAdditiveLaneTranscriptV1,
}

/// Receipt-only execution result safe for the authenticated internal transport.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "outcome",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum CloudflareSigningWorkerEcdsaLaneExecuteEffectV1 {
    Applied {
        receipt: CloudflareEcdsaLaneProtocolCommitReceiptV1,
    },
    Replayed {
        receipt: CloudflareEcdsaLaneProtocolCommitReceiptV1,
    },
}

/// Typed private active material. Serialization is confined to encrypted D1.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CloudflareEcdsaLaneActiveServerMaterialV1 {
    #[zeroize(skip)]
    pub kind: String,
    pub relayer_share32_b64u: String,
}

impl CloudflareEcdsaLaneActiveServerMaterialV1 {
    pub fn new(share: [u8; 32]) -> Self {
        Self {
            kind: ECDSA_ACTIVE_SERVER_MATERIAL_KIND_V1.to_owned(),
            relayer_share32_b64u: b64(&share),
        }
    }

    pub fn share32(&self) -> RouterAbProtocolResult<[u8; 32]> {
        if self.kind != ECDSA_ACTIVE_SERVER_MATERIAL_KIND_V1 {
            return Err(invalid("ECDSA active server material kind is invalid"));
        }
        decode_b64("ECDSA active server share", &self.relayer_share32_b64u)
    }
}

/// Holder acknowledgement passed to private activation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CloudflareEcdsaLaneHolderDeliveryReceiptV1 {
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

/// Private activation input. It carries only public receipts and identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CloudflareSigningWorkerEcdsaLaneActivateRequestV1 {
    pub identity: CloudflareSigningWorkerLaneMaterialIdentityV1,
    pub target_material_activation: EcdsaMaterialActivationRefV1,
    pub holder_delivery_receipt: CloudflareEcdsaLaneHolderDeliveryReceiptV1,
}

/// Product activation receipt returned without active material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CloudflareEcdsaLaneServerActivationReceiptV1 {
    pub kind: String,
    pub operation_id: String,
    pub enrollment_id: String,
    pub target_lane_id: String,
    pub target_lane_share_epoch: String,
    pub target_material_activation: EcdsaMaterialActivationRefV1,
    pub signing_worker_participant_binding_digest_b64u: String,
    pub server_ciphertext_digest_set_b64u: String,
    pub transcript_hash_b64u: String,
    pub activated_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "outcome",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum CloudflareSigningWorkerEcdsaLaneActivateEffectV1 {
    Applied {
        receipt: CloudflareEcdsaLaneServerActivationReceiptV1,
    },
    Replayed {
        receipt: CloudflareEcdsaLaneServerActivationReceiptV1,
    },
}

/// Exact public inputs required to retire one ECDSA server activation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CloudflareSigningWorkerEcdsaLaneRetireRequestV1 {
    pub identity: CloudflareSigningWorkerLaneMaterialIdentityV1,
    pub manifest: EcdsaLaneManifestIdentityV1,
    pub material_activation: EcdsaMaterialActivationRefV1,
    pub revocation_epoch: u64,
    pub retirement_reason: String,
    pub retirement_correlation_id: String,
    pub retirement_request_digest_b64u: String,
    pub retirement_effect_binding_digest_b64u: String,
    pub server_generation: String,
    pub lifecycle_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "outcome",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum CloudflareSigningWorkerEcdsaLaneRetireEffectV1 {
    Applied {
        receipt: EcdsaServerRetirementReceiptV1,
    },
    Replayed {
        receipt: EcdsaServerRetirementReceiptV1,
    },
}

#[cfg(feature = "workers-rs")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CloudflareEcdsaLaneStoredRetirementV1 {
    receipt: EcdsaServerRetirementReceiptV1,
    retirement_effect_binding_digest_b64u: String,
}

#[cfg(feature = "workers-rs")]
pub(crate) fn build_server_round_v1(
    job: &EcdsaAdditiveLaneJobV1,
    holder_round: &EcdsaAdditiveLaneHolderRoundV1,
    target_server_public_key33: &[u8; 33],
    sealed_server_digest: &[u8; 32],
    public_identity_digest: &[u8; 32],
    committed_at_ms: u64,
) -> RouterAbProtocolResult<EcdsaAdditiveLaneServerRoundV1> {
    let threshold_sessions = job
        .target_threshold_session_set_digest()
        .map_err(|error| map_protocol_error("ECDSA target sessions are invalid", error))?;
    let holder_hash = holder_round
        .hash()
        .map_err(|error| map_protocol_error("ECDSA holder round is invalid", error))?;
    let mut attestation = Sha256::new();
    attestation.update(ECDSA_SERVER_ATTESTATION_DOMAIN_V1);
    attestation.update(
        job.preamble_hash()
            .map_err(|error| map_protocol_error("ECDSA preamble is invalid", error))?,
    );
    attestation.update(holder_hash);
    attestation.update(target_server_public_key33);
    attestation.update(sealed_server_digest);
    complete_ecdsa_additive_lane_server_round_v1(
        job,
        holder_round,
        b64(target_server_public_key33),
        b64(sealed_server_digest),
        b64(&threshold_sessions),
        b64(public_identity_digest),
        b64(&attestation.finalize()),
        committed_at_ms,
    )
    .map_err(|error| map_protocol_error("ECDSA server round is invalid", error))
}

#[cfg(feature = "workers-rs")]
pub(crate) fn build_transcript_v1(
    job: &EcdsaAdditiveLaneJobV1,
    holder: &EcdsaAdditiveLaneHolderRoundV1,
    server: &EcdsaAdditiveLaneServerRoundV1,
) -> RouterAbProtocolResult<EcdsaAdditiveLaneTranscriptV1> {
    Ok(EcdsaAdditiveLaneTranscriptV1 {
        kind: "ecdsa_additive_lane_transcript_v1".to_owned(),
        preamble_hash_b64u: b64(&job
            .preamble_hash()
            .map_err(|error| map_protocol_error("ECDSA preamble is invalid", error))?),
        holder_round_hash_b64u: b64(&holder
            .hash()
            .map_err(|error| map_protocol_error("ECDSA holder round is invalid", error))?),
        server_round_hash_b64u: b64(&server
            .hash()
            .map_err(|error| map_protocol_error("ECDSA server round is invalid", error))?),
    })
}

#[cfg(feature = "workers-rs")]
pub(crate) fn build_receipt_v1(
    job: &EcdsaAdditiveLaneJobV1,
    holder: &EcdsaAdditiveLaneHolderRoundV1,
    server: &EcdsaAdditiveLaneServerRoundV1,
    transcript: &EcdsaAdditiveLaneTranscriptV1,
) -> RouterAbProtocolResult<CloudflareEcdsaLaneProtocolCommitReceiptV1> {
    let (target_lane_id, target_lane_share_epoch) = target_lane(job);
    let receipt = CloudflareEcdsaLaneProtocolCommitReceiptV1 {
        kind: "lane_protocol_commit_receipt_v1".to_owned(),
        operation_id: job.operation_id.clone(),
        enrollment_id: job.enrollment_id.clone(),
        wallet_id: job.wallet_id.clone(),
        wallet_key_id: job.wallet_key_id.clone(),
        source_lane_id: job.source.lane_id().to_owned(),
        source_lane_share_epoch: job.source.lane_share_epoch().to_owned(),
        source_revocation_epoch: job.source.revocation_epoch(),
        source_material_activation: job.source.material_activation().clone(),
        target_lane_id: target_lane_id.to_owned(),
        target_lane_share_epoch: target_lane_share_epoch.to_owned(),
        target_material_activation_id: job.target_material_activation_id.clone(),
        key_family: "ecdsa_secp256k1".to_owned(),
        public_identity_digest_b64u: server.public_identity_relation_digest_b64u.clone(),
        target_holder_public_commitment_b64u: holder.target_holder_public_commitment33_b64u.clone(),
        target_server_public_commitment_b64u: server.target_server_public_commitment33_b64u.clone(),
        target_holder_ciphertext_digest_set_b64u: holder
            .sealed_target_holder_material_digest_b64u
            .clone(),
        target_server_ciphertext_digest_set_b64u: server
            .sealed_target_server_material_digest_b64u
            .clone(),
        holder_recipient_key_digest_b64u: job.target_holder.hpke_public_key_digest_b64u.clone(),
        server_recipient_key_digest_b64u: job
            .target_signing_worker
            .hpke_public_key_digest_b64u
            .clone(),
        transcript_hash_b64u: b64(&transcript
            .hash()
            .map_err(|error| map_protocol_error("ECDSA transcript is invalid", error))?),
        committed_at_ms: server.server_committed_at_ms,
    };
    receipt.validate_for_job(job)?;
    Ok(receipt)
}

#[cfg(feature = "workers-rs")]
pub(crate) fn public_identity_digest_v1(
    holder_key: &[u8; 33],
    server_key: &[u8; 33],
    threshold_key: &[u8; 33],
    address: &[u8; 20],
) -> RouterAbProtocolResult<[u8; 32]> {
    ecdsa_lane_public_identity_relation_digest_v1(holder_key, server_key, threshold_key, address)
        .map_err(|error| map_protocol_error("ECDSA public identity is invalid", error))
}

pub(crate) fn target_lane(job: &EcdsaAdditiveLaneJobV1) -> (&str, &str) {
    match &job.target {
        EcdsaLaneTargetOperationV1::CreateLane {
            lane_id,
            lane_share_epoch,
            ..
        }
        | EcdsaLaneTargetOperationV1::RefreshLane {
            lane_id,
            lane_share_epoch,
            ..
        } => (lane_id, lane_share_epoch),
    }
}

#[cfg(feature = "workers-rs")]
pub(crate) fn decode_public33(
    label: &'static str,
    value: &str,
) -> RouterAbProtocolResult<[u8; 33]> {
    decode_b64(label, value)
}

#[cfg(feature = "workers-rs")]
pub(crate) fn decode_evm_address(value: &str) -> RouterAbProtocolResult<[u8; 20]> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    if value.len() != 40 {
        return Err(invalid("ECDSA job EVM address must contain 20 bytes"));
    }
    let mut bytes = [0_u8; 20];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| invalid("ECDSA job EVM address is invalid"))?;
    }
    Ok(bytes)
}

#[cfg(feature = "workers-rs")]
mod worker_execution {
    use super::*;
    use crate::hpke::cloudflare_hpke_x25519_public_key_bytes_v1;
    use crate::{
        cloudflare_now_unix_ms_v1, cloudflare_router_error_status,
        execute_cloudflare_signing_worker_lane_material_command_v1,
        load_cloudflare_server_output_hpke_private_key_bytes_v1,
        load_cloudflare_signing_worker_active_lane_material_v1,
        load_cloudflare_signing_worker_lane_material_record_by_operation_v1,
        load_cloudflare_signing_worker_registration_active_material_v1,
        CloudflareSigningWorkerLaneArtifactKindV1, CloudflareSigningWorkerLaneArtifactV1,
        CloudflareSigningWorkerLaneCommittedArtifactsV1,
        CloudflareSigningWorkerLaneHolderDeliveryV1, CloudflareSigningWorkerLaneKeyFamilyV1,
        CloudflareSigningWorkerLaneMaterialCommandV1, CloudflareSigningWorkerLaneMaterialEffectV1,
        CloudflareSigningWorkerLaneMaterialLifecycleV1,
        CloudflareSigningWorkerLaneMaterialRecordV1, CloudflareSigningWorkerLaneRetirementReasonV1,
        CloudflareSigningWorkerLaneRetirementV1, CloudflareSigningWorkerLaneServerActivationV1,
        CloudflareSigningWorkerRuntimeV1,
    };
    use router_ab_ecdsa_client_protocol::{
        open_ecdsa_lane_payload_v1, seal_ecdsa_lane_payload_v1,
        verify_ecdsa_server_retirement_receipt_v1,
    };
    use router_ab_ecdsa_derivation::{
        derive_relayer_share_for_client_public, rebind_ecdsa_lane_relayer_share_bytes_v1,
        EcdsaLaneDelta, EcdsaLanePublicIdentityBindingV1, RouterAbEcdsaDerivationStableKeyContext,
    };
    use worker::{Env, Method, Request, Response};
    use zeroize::Zeroizing;

    fn protocol_error_response(error: RouterAbProtocolError) -> worker::Result<Response> {
        Response::error(
            format!("{:?}: {}", error.code(), error.message()),
            cloudflare_router_error_status(error.code()),
        )
    }

    fn decode_artifact_bytes(
        artifact: &CloudflareSigningWorkerLaneArtifactV1,
        kind: CloudflareSigningWorkerLaneArtifactKindV1,
    ) -> RouterAbProtocolResult<Zeroizing<Vec<u8>>> {
        artifact.validate_kind(kind)?;
        URL_SAFE_NO_PAD
            .decode(&artifact.payload_b64u)
            .map(Zeroizing::new)
            .map_err(|_| invalid("SigningWorker lane artifact payload is invalid"))
    }

    fn json_artifact<T: Serialize>(
        kind: CloudflareSigningWorkerLaneArtifactKindV1,
        value: &T,
    ) -> RouterAbProtocolResult<CloudflareSigningWorkerLaneArtifactV1> {
        let bytes = serde_json::to_vec(value)
            .map_err(|_| invalid("SigningWorker ECDSA lane artifact could not be serialized"))?;
        CloudflareSigningWorkerLaneArtifactV1::from_bytes(kind, &bytes)
    }

    fn parse_artifact<T: for<'de> Deserialize<'de>>(
        artifact: &CloudflareSigningWorkerLaneArtifactV1,
        kind: CloudflareSigningWorkerLaneArtifactKindV1,
    ) -> RouterAbProtocolResult<T> {
        serde_json::from_slice(&decode_artifact_bytes(artifact, kind)?)
            .map_err(|_| invalid("SigningWorker ECDSA lane artifact has invalid JSON"))
    }

    pub(crate) async fn derive_registration_source_relayer_share_v1(
        env: &Env,
        source_activation: &EcdsaMaterialActivationRefV1,
        source_derivation: &CloudflareEcdsaRegistrationSourceDerivationV1,
        source_client_public_key33: &[u8; 33],
        source_relayer_public_key33: &[u8; 33],
    ) -> RouterAbProtocolResult<Zeroizing<[u8; 32]>> {
        source_derivation.validate()?;
        let lookup = CloudflareActiveSigningWorkerStateLookupV1::new(
            source_activation.material_owner.clone(),
            source_activation.activation_id.clone(),
            source_activation.signing_worker.clone(),
        )?;
        let material =
            load_cloudflare_signing_worker_registration_active_material_v1(env, &lookup).await?;
        let application_binding_digest = decode_b64::<32>(
            "ECDSA registration source application binding digest",
            &source_derivation.application_binding_digest_b64u,
        )?;
        let context = RouterAbEcdsaDerivationStableKeyContext::new(application_binding_digest);
        let (relayer_share, public_identity) = derive_relayer_share_for_client_public(
            &context,
            *material.output_material.as_bytes(),
            source_client_public_key33,
            source_derivation.client_share_retry_counter,
        )
        .map_err(|error| {
            map_protocol_error("ECDSA registration source share derivation failed", error)
        })?;
        if b64(&public_identity.context_binding32) != source_activation.key_binding {
            return Err(invalid(
                "ECDSA registration source context binding is inconsistent",
            ));
        }
        if !ct_eq(
            &public_identity.relayer_public_key33,
            source_relayer_public_key33,
        ) {
            return Err(invalid(
                "ECDSA registration source relayer public key is inconsistent",
            ));
        }
        Ok(Zeroizing::new(relayer_share.x_relayer32))
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
            CloudflareSigningWorkerLaneCommittedArtifactsV1::EcdsaAdditive {
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
            CloudflareSigningWorkerLaneCommittedArtifactsV1::Ed25519Yao { .. } => Err(invalid(
                "SigningWorker lane operation is committed for another curve",
            )),
        }
    }

    fn validate_record_identity_for_job(
        identity: &CloudflareSigningWorkerLaneMaterialIdentityV1,
        job: &EcdsaAdditiveLaneJobV1,
    ) -> RouterAbProtocolResult<()> {
        let (lane_id, epoch) = target_lane(job);
        if identity.operation_id != job.operation_id
            || identity.enrollment_id != job.enrollment_id
            || identity.wallet_id != job.wallet_id
            || identity.wallet_key_id != job.wallet_key_id
            || identity.target_lane_id != lane_id
            || identity.target_lane_share_epoch != epoch
            || identity.target_material_activation_id != job.target_material_activation_id
            || identity.key_family != CloudflareSigningWorkerLaneKeyFamilyV1::EcdsaSecp256k1
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ReplayedLocalRequest,
                "SigningWorker ECDSA replay identity does not match the admitted job",
            ));
        }
        Ok(())
    }

    async fn replay_before_crypto(
        env: &Env,
        request: &CloudflareSigningWorkerEcdsaLaneExecuteRequestV1,
    ) -> RouterAbProtocolResult<Option<CloudflareEcdsaLaneProtocolCommitReceiptV1>> {
        let Some(record) = load_cloudflare_signing_worker_lane_material_record_by_operation_v1(
            env,
            &request.job.operation_id,
        )
        .await?
        else {
            return Ok(None);
        };
        validate_record_identity_for_job(&record.identity, &request.job)?;
        let (holder, _, receipt, transcript) = committed_artifacts(&record)?;
        let stored_holder = decode_artifact_bytes(
            holder,
            CloudflareSigningWorkerLaneArtifactKindV1::HolderPackage,
        )?;
        let incoming_holder = serde_json::to_vec(&request.holder_package)
            .map_err(|_| invalid("ECDSA holder package could not be serialized"))?;
        if !ct_eq(
            &Sha256::digest(stored_holder),
            &Sha256::digest(incoming_holder),
        ) {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ReplayedLocalRequest,
                "ECDSA replay changed the holder package",
            ));
        }
        let committed: CloudflareEcdsaLaneCommittedTranscriptV1 = parse_artifact(
            transcript,
            CloudflareSigningWorkerLaneArtifactKindV1::Transcript,
        )?;
        if committed.job != request.job || committed.holder_round != request.holder_round {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ReplayedLocalRequest,
                "ECDSA replay changed the committed job or holder round",
            ));
        }
        let receipt: CloudflareEcdsaLaneProtocolCommitReceiptV1 = parse_artifact(
            receipt,
            CloudflareSigningWorkerLaneArtifactKindV1::ProtocolCommitReceipt,
        )?;
        receipt.validate_for_job(&request.job)?;
        Ok(Some(receipt))
    }

    async fn source_share32(
        env: &Env,
        source: &CloudflareEcdsaLaneSourceMaterialLookupV1,
        job: &EcdsaAdditiveLaneJobV1,
    ) -> RouterAbProtocolResult<Zeroizing<[u8; 32]>> {
        let share = match source {
            CloudflareEcdsaLaneSourceMaterialLookupV1::LaneMaterial { lookup } => {
                let (artifact, _) =
                    load_cloudflare_signing_worker_active_lane_material_v1(env, &lookup.identity)
                        .await?;
                let material: CloudflareEcdsaLaneActiveServerMaterialV1 = parse_artifact(
                    &artifact,
                    CloudflareSigningWorkerLaneArtifactKindV1::ActiveServerMaterial,
                )?;
                material.share32()?
            }
            CloudflareEcdsaLaneSourceMaterialLookupV1::RegistrationActivation {
                lookup: _,
                source_derivation,
            } => {
                let source_client_public = decode_public33(
                    "ECDSA source holder verifying share",
                    &job.source_holder_verifying_share33_b64u,
                )?;
                let source_relayer_public = decode_public33(
                    "ECDSA source server verifying share",
                    &job.source_server_verifying_share33_b64u,
                )?;
                let relayer_share = derive_registration_source_relayer_share_v1(
                    env,
                    job.source.material_activation(),
                    source_derivation,
                    &source_client_public,
                    &source_relayer_public,
                )
                .await?;
                *relayer_share
            }
        };
        Ok(Zeroizing::new(share))
    }

    fn validate_recipient_key(
        job: &EcdsaAdditiveLaneJobV1,
        runtime: &CloudflareSigningWorkerRuntimeV1,
    ) -> RouterAbProtocolResult<()> {
        let binding = runtime.server_output_decrypt_key();
        let configured = cloudflare_hpke_x25519_public_key_bytes_v1(&binding.public_key)?;
        let admitted = decode_b64::<32>(
            "ECDSA target SigningWorker public key",
            &job.target_signing_worker.hpke_public_key_b64u,
        )?;
        let admitted_digest = decode_b64::<32>(
            "ECDSA target SigningWorker public-key digest",
            &job.target_signing_worker.hpke_public_key_digest_b64u,
        )?;
        if binding.key_epoch != job.target_signing_worker.recipient_key_id
            || !ct_eq(&configured, &admitted)
            || !ct_eq(&Sha256::digest(admitted), &admitted_digest)
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "ECDSA lane recipient does not match the active SigningWorker key",
            ));
        }
        Ok(())
    }

    pub async fn execute_cloudflare_signing_worker_ecdsa_lane_v1(
        env: &Env,
        runtime: &CloudflareSigningWorkerRuntimeV1,
        request: &CloudflareSigningWorkerEcdsaLaneExecuteRequestV1,
        committed_at_ms: u64,
    ) -> RouterAbProtocolResult<CloudflareSigningWorkerEcdsaLaneExecuteEffectV1> {
        request.validate()?;
        if let Some(receipt) = replay_before_crypto(env, request).await? {
            return Ok(CloudflareSigningWorkerEcdsaLaneExecuteEffectV1::Replayed { receipt });
        }
        validate_recipient_key(&request.job, runtime)?;
        let preamble = request
            .job
            .preamble_hash()
            .map_err(|error| map_protocol_error("ECDSA preamble is invalid", error))?;
        let mut private_key =
            Zeroizing::new(load_cloudflare_server_output_hpke_private_key_bytes_v1(
                env,
                runtime.server_output_decrypt_key(),
            )?);
        let opened_delta = Zeroizing::new(
            open_ecdsa_lane_payload_v1(&request.encrypted_delta, &private_key, &preamble)
                .map_err(|error| map_protocol_error("ECDSA delta open failed", error))?,
        );
        private_key.zeroize();
        let delta_bytes: [u8; 32] = opened_delta
            .as_slice()
            .try_into()
            .map_err(|_| invalid("ECDSA lane delta must contain 32 bytes"))?;
        let delta = EcdsaLaneDelta::from_bytes(delta_bytes)
            .map_err(|error| map_protocol_error("ECDSA lane delta is invalid", error))?;
        let source_share = source_share32(env, &request.source_material, &request.job).await?;
        let holder_key = decode_public33(
            "ECDSA target holder public commitment",
            &request.holder_round.target_holder_public_commitment33_b64u,
        )?;
        let threshold_key = decode_public33(
            "ECDSA threshold public key",
            &request.job.threshold_public_key33_b64u,
        )?;
        let source_identity = EcdsaLanePublicIdentityBindingV1 {
            source_client_public_key33: decode_public33(
                "ECDSA source holder verifying share",
                &request.job.source_holder_verifying_share33_b64u,
            )?,
            source_relayer_public_key33: decode_public33(
                "ECDSA source server verifying share",
                &request.job.source_server_verifying_share33_b64u,
            )?,
            threshold_public_key33: threshold_key,
            threshold_ethereum_address20: decode_evm_address(&request.job.evm_address)?,
        };
        let rebind = rebind_ecdsa_lane_relayer_share_bytes_v1(
            *source_share,
            &source_identity,
            &delta,
            holder_key,
        )
        .map_err(|error| map_protocol_error("ECDSA server share rebind failed", error))?;
        let target_server_public = rebind.target_relayer_public_key33;
        let address = rebind.target_ethereum_address20;
        let mut target_share = Zeroizing::new(rebind.into_target_relayer_share32());
        let mut seal_seed = Zeroizing::new([0_u8; 32]);
        getrandom::getrandom(seal_seed.as_mut())
            .map_err(|_| invalid("SigningWorker CSPRNG failed"))?;
        let signing_worker_package = seal_ecdsa_lane_payload_v1(
            &request.job.target_signing_worker.hpke_public_key_b64u,
            &preamble,
            target_share.as_ref(),
            *seal_seed,
        )
        .map_err(|error| map_protocol_error("ECDSA target server seal failed", error))?;
        target_share.zeroize();
        seal_seed.zeroize();
        let signing_worker_digest = signing_worker_package
            .digest()
            .map_err(|error| map_protocol_error("ECDSA server package is invalid", error))?;
        let public_identity = public_identity_digest_v1(
            &holder_key,
            &target_server_public,
            &threshold_key,
            &address,
        )?;
        let server_round = build_server_round_v1(
            &request.job,
            &request.holder_round,
            &target_server_public,
            &signing_worker_digest,
            &public_identity,
            committed_at_ms,
        )?;
        let transcript = build_transcript_v1(&request.job, &request.holder_round, &server_round)?;
        let receipt = build_receipt_v1(
            &request.job,
            &request.holder_round,
            &server_round,
            &transcript,
        )?;
        let committed_transcript = CloudflareEcdsaLaneCommittedTranscriptV1 {
            job: request.job.clone(),
            holder_round: request.holder_round.clone(),
            server_round,
            transcript,
        };
        let holder_artifact = json_artifact(
            CloudflareSigningWorkerLaneArtifactKindV1::HolderPackage,
            &request.holder_package,
        )?;
        let signing_worker_artifact = json_artifact(
            CloudflareSigningWorkerLaneArtifactKindV1::SigningWorkerPackage,
            &signing_worker_package,
        )?;
        let receipt_artifact = json_artifact(
            CloudflareSigningWorkerLaneArtifactKindV1::ProtocolCommitReceipt,
            &receipt,
        )?;
        let transcript_artifact = json_artifact(
            CloudflareSigningWorkerLaneArtifactKindV1::Transcript,
            &committed_transcript,
        )?;
        let (target_lane_id, target_epoch) = target_lane(&request.job);
        let identity = CloudflareSigningWorkerLaneMaterialIdentityV1 {
            operation_id: request.job.operation_id.clone(),
            enrollment_id: request.job.enrollment_id.clone(),
            wallet_id: request.job.wallet_id.clone(),
            wallet_key_id: request.job.wallet_key_id.clone(),
            target_lane_id: target_lane_id.to_owned(),
            target_lane_share_epoch: target_epoch.to_owned(),
            target_material_activation_id: request.job.target_material_activation_id.clone(),
            key_family: CloudflareSigningWorkerLaneKeyFamilyV1::EcdsaSecp256k1,
            holder_participant_binding_digest_b64u: request
                .job
                .target_holder
                .participant_binding_digest_b64u
                .clone(),
            signing_worker_participant_binding_digest_b64u: request
                .job
                .target_signing_worker
                .participant_binding_digest_b64u
                .clone(),
            holder_recipient_key_digest_b64u: request
                .job
                .target_holder
                .hpke_public_key_digest_b64u
                .clone(),
            server_recipient_key_digest_b64u: request
                .job
                .target_signing_worker
                .hpke_public_key_digest_b64u
                .clone(),
            transcript_hash_b64u: receipt.transcript_hash_b64u.clone(),
            protocol_commit_receipt_digest_b64u: receipt.digest_b64u_v1()?,
        };
        let command = CloudflareSigningWorkerLaneMaterialCommandV1::Commit {
            identity,
            committed_artifacts: CloudflareSigningWorkerLaneCommittedArtifactsV1::EcdsaAdditive {
                holder_package: holder_artifact,
                signing_worker_package: signing_worker_artifact,
                protocol_commit_receipt: receipt_artifact,
                transcript: transcript_artifact,
            },
            committed_at_ms,
        };
        let effect =
            execute_cloudflare_signing_worker_lane_material_command_v1(env, &command).await?;
        match effect {
            CloudflareSigningWorkerLaneMaterialEffectV1::ProtocolCommitted {
                changed: true,
                ..
            } => Ok(CloudflareSigningWorkerEcdsaLaneExecuteEffectV1::Applied { receipt }),
            CloudflareSigningWorkerLaneMaterialEffectV1::ProtocolCommitted {
                changed: false,
                ..
            } => Ok(CloudflareSigningWorkerEcdsaLaneExecuteEffectV1::Replayed { receipt }),
            _ => Err(invalid(
                "SigningWorker returned the wrong ECDSA commit effect",
            )),
        }
    }

    pub async fn activate_cloudflare_signing_worker_ecdsa_lane_v1(
        env: &Env,
        runtime: &CloudflareSigningWorkerRuntimeV1,
        request: &CloudflareSigningWorkerEcdsaLaneActivateRequestV1,
        activated_at_ms: u64,
    ) -> RouterAbProtocolResult<CloudflareSigningWorkerEcdsaLaneActivateEffectV1> {
        request.identity.validate()?;
        let record = load_cloudflare_signing_worker_lane_material_record_by_operation_v1(
            env,
            &request.identity.operation_id,
        )
        .await?
        .ok_or_else(|| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MissingLocalBinding,
                "SigningWorker ECDSA lane commitment is missing",
            )
        })?;
        let expected_identity = decode_b64::<32>(
            "ECDSA activation expected identity",
            &request.identity.digest_b64u()?,
        )?;
        let stored_identity = decode_b64::<32>(
            "ECDSA activation stored identity",
            &record.identity.digest_b64u()?,
        )?;
        if !ct_eq(&expected_identity, &stored_identity) || record.identity != request.identity {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ReplayedLocalRequest,
                "ECDSA activation identity does not match committed material",
            ));
        }
        let (_, worker_package, protocol_receipt_artifact, transcript_artifact) =
            committed_artifacts(&record)?;
        let committed: CloudflareEcdsaLaneCommittedTranscriptV1 = parse_artifact(
            transcript_artifact,
            CloudflareSigningWorkerLaneArtifactKindV1::Transcript,
        )?;
        let protocol_receipt: CloudflareEcdsaLaneProtocolCommitReceiptV1 = parse_artifact(
            protocol_receipt_artifact,
            CloudflareSigningWorkerLaneArtifactKindV1::ProtocolCommitReceipt,
        )?;
        protocol_receipt.validate_for_job(&committed.job)?;
        let holder_receipt = &request.holder_delivery_receipt;
        if holder_receipt.kind != "lane_holder_delivery_receipt_v1"
            || holder_receipt.operation_id != request.identity.operation_id
            || holder_receipt.enrollment_id != request.identity.enrollment_id
            || holder_receipt.target_lane_id != request.identity.target_lane_id
            || holder_receipt.target_lane_share_epoch != request.identity.target_lane_share_epoch
            || holder_receipt.target_material_activation_id
                != request.identity.target_material_activation_id
            || holder_receipt.holder_participant_binding_digest_b64u
                != request.identity.holder_participant_binding_digest_b64u
            || holder_receipt.holder_recipient_key_digest_b64u
                != request.identity.holder_recipient_key_digest_b64u
            || holder_receipt.holder_ciphertext_digest_set_b64u
                != protocol_receipt.target_holder_ciphertext_digest_set_b64u
            || holder_receipt.transcript_hash_b64u != request.identity.transcript_hash_b64u
            || holder_receipt.acknowledged_at_ms < protocol_receipt.committed_at_ms
            || request.target_material_activation.activation_id
                != request.identity.target_material_activation_id
        {
            return Err(invalid(
                "ECDSA holder delivery does not match committed private material",
            ));
        }
        let package: EcdsaLaneEncryptedPayloadV1 = parse_artifact(
            worker_package,
            CloudflareSigningWorkerLaneArtifactKindV1::SigningWorkerPackage,
        )?;
        validate_recipient_key(&committed.job, runtime)?;
        let preamble = committed
            .job
            .preamble_hash()
            .map_err(|error| map_protocol_error("ECDSA activation preamble is invalid", error))?;
        let mut private_key =
            Zeroizing::new(load_cloudflare_server_output_hpke_private_key_bytes_v1(
                env,
                runtime.server_output_decrypt_key(),
            )?);
        let opened = Zeroizing::new(
            open_ecdsa_lane_payload_v1(&package, &private_key, &preamble)
                .map_err(|error| map_protocol_error("ECDSA server package open failed", error))?,
        );
        private_key.zeroize();
        let share: [u8; 32] = opened
            .as_slice()
            .try_into()
            .map_err(|_| invalid("ECDSA active server material must contain 32 bytes"))?;
        let active = CloudflareEcdsaLaneActiveServerMaterialV1::new(share);
        let active_artifact = json_artifact(
            CloudflareSigningWorkerLaneArtifactKindV1::ActiveServerMaterial,
            &active,
        )?;
        let holder_receipt = json_artifact(
            CloudflareSigningWorkerLaneArtifactKindV1::HolderDeliveryReceipt,
            &request.holder_delivery_receipt,
        )?;
        let holder_command = CloudflareSigningWorkerLaneMaterialCommandV1::RecordHolderDelivery {
            identity: request.identity.clone(),
            holder_delivery: CloudflareSigningWorkerLaneHolderDeliveryV1 {
                receipt: holder_receipt.clone(),
                acknowledged_at_ms: request.holder_delivery_receipt.acknowledged_at_ms,
            },
        };
        execute_cloudflare_signing_worker_lane_material_command_v1(env, &holder_command).await?;
        let activation_receipt = CloudflareEcdsaLaneServerActivationReceiptV1 {
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
            server_ciphertext_digest_set_b64u: protocol_receipt
                .target_server_ciphertext_digest_set_b64u
                .clone(),
            transcript_hash_b64u: request.identity.transcript_hash_b64u.clone(),
            activated_at_ms,
        };
        let activation_receipt_artifact = json_artifact(
            CloudflareSigningWorkerLaneArtifactKindV1::ServerActivationReceipt,
            &activation_receipt,
        )?;
        let command = CloudflareSigningWorkerLaneMaterialCommandV1::ActivateServerMaterial {
            identity: request.identity.clone(),
            expected_holder_delivery_receipt: holder_receipt,
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
            } => Ok(CloudflareSigningWorkerEcdsaLaneActivateEffectV1::Applied {
                receipt: activation_receipt,
            }),
            CloudflareSigningWorkerLaneMaterialEffectV1::ServerMaterialActivated {
                changed: false,
                ..
            } => Ok(CloudflareSigningWorkerEcdsaLaneActivateEffectV1::Replayed {
                receipt: activation_receipt,
            }),
            _ => Err(invalid(
                "SigningWorker returned the wrong ECDSA activation effect",
            )),
        }
    }

    fn retirement_reason(
        value: &str,
    ) -> RouterAbProtocolResult<CloudflareSigningWorkerLaneRetirementReasonV1> {
        match value {
            "lane_revoked" => Ok(CloudflareSigningWorkerLaneRetirementReasonV1::LaneRevoked),
            "device_compromise" => {
                Ok(CloudflareSigningWorkerLaneRetirementReasonV1::DeviceCompromise)
            }
            "agent_compromise" => {
                Ok(CloudflareSigningWorkerLaneRetirementReasonV1::AgentCompromise)
            }
            "rotation" => Ok(CloudflareSigningWorkerLaneRetirementReasonV1::Rotation),
            _ => Err(invalid("ECDSA retirement reason is invalid")),
        }
    }

    fn retired_receipt(
        record: &CloudflareSigningWorkerLaneMaterialRecordV1,
    ) -> RouterAbProtocolResult<Option<CloudflareEcdsaLaneStoredRetirementV1>> {
        let retirement = match &record.lifecycle {
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
            } => retirement,
            _ => return Ok(None),
        };
        parse_artifact(
            &retirement.receipt,
            CloudflareSigningWorkerLaneArtifactKindV1::RetirementReceipt,
        )
        .map(Some)
    }

    fn verify_retirement_request(
        request: &CloudflareSigningWorkerEcdsaLaneRetireRequestV1,
        receipt: &EcdsaServerRetirementReceiptV1,
    ) -> RouterAbProtocolResult<()> {
        if request.identity.key_family != CloudflareSigningWorkerLaneKeyFamilyV1::EcdsaSecp256k1
            || request.identity.wallet_key_id != receipt.wallet_key_id
            || request.identity.target_lane_id != receipt.lane_id
            || request.identity.target_lane_share_epoch != receipt.lane_share_epoch
            || request.identity.target_material_activation_id
                != receipt.material_activation.activation_id
            || request.retirement_reason != receipt.retirement_reason
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ReplayedLocalRequest,
                "ECDSA retirement receipt does not match the private lane identity",
            ));
        }
        verify_ecdsa_server_retirement_receipt_v1(
            receipt,
            &request.manifest,
            &request.material_activation,
            &request.identity.wallet_key_id,
            &request.identity.target_lane_id,
            &request.identity.target_lane_share_epoch,
            request.revocation_epoch,
            &request.retirement_correlation_id,
            &request.retirement_request_digest_b64u,
            &request.server_generation,
            &request.lifecycle_id,
        )
        .map_err(|error| map_protocol_error("ECDSA retirement receipt is invalid", error))
    }

    pub async fn retire_cloudflare_signing_worker_ecdsa_lane_v1(
        env: &Env,
        request: &CloudflareSigningWorkerEcdsaLaneRetireRequestV1,
        retired_at_ms: u64,
    ) -> RouterAbProtocolResult<CloudflareSigningWorkerEcdsaLaneRetireEffectV1> {
        request.identity.validate()?;
        decode_b64::<32>(
            "ECDSA retirement request digest",
            &request.retirement_request_digest_b64u,
        )?;
        let record = load_cloudflare_signing_worker_lane_material_record_by_operation_v1(
            env,
            &request.identity.operation_id,
        )
        .await?
        .ok_or_else(|| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MissingLocalBinding,
                "SigningWorker ECDSA lane retirement target is missing",
            )
        })?;
        let expected_identity = decode_b64::<32>(
            "ECDSA retirement expected identity",
            &request.identity.digest_b64u()?,
        )?;
        let stored_identity = decode_b64::<32>(
            "ECDSA retirement stored identity",
            &record.identity.digest_b64u()?,
        )?;
        if !ct_eq(&expected_identity, &stored_identity) || request.identity != record.identity {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ReplayedLocalRequest,
                "ECDSA retirement identity does not match committed material",
            ));
        }
        if let Some(stored) = retired_receipt(&record)? {
            let effect_binding = decode_b64::<32>(
                "ECDSA stored retirement effect binding",
                &stored.retirement_effect_binding_digest_b64u,
            )?;
            let requested_effect_binding = decode_b64::<32>(
                "ECDSA requested retirement effect binding",
                &request.retirement_effect_binding_digest_b64u,
            )?;
            if !ct_eq(&effect_binding, &requested_effect_binding) {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::ReplayedLocalRequest,
                    "ECDSA retirement replay changed the authorized effect binding",
                ));
            }
            verify_retirement_request(request, &stored.receipt)?;
            return Ok(CloudflareSigningWorkerEcdsaLaneRetireEffectV1::Replayed {
                receipt: stored.receipt,
            });
        }
        let retired_at =
            worker::js_sys::Date::new(&wasm_bindgen::JsValue::from_f64(retired_at_ms as f64))
                .to_iso_string()
                .as_string()
                .ok_or_else(|| {
                    invalid("SigningWorker could not format the retirement timestamp")
                })?;
        let mut receipt = EcdsaServerRetirementReceiptV1 {
            kind: "ecdsa_server_retirement_receipt_v1".to_owned(),
            manifest: request.manifest.clone(),
            material_activation: request.material_activation.clone(),
            wallet_key_id: request.identity.wallet_key_id.clone(),
            lane_id: request.identity.target_lane_id.clone(),
            lane_share_epoch: request.identity.target_lane_share_epoch.clone(),
            revocation_epoch: request.revocation_epoch,
            retirement_reason: request.retirement_reason.clone(),
            retirement_correlation_id: request.retirement_correlation_id.clone(),
            retirement_request_digest_b64u: request.retirement_request_digest_b64u.clone(),
            server_generation: request.server_generation.clone(),
            lifecycle_id: request.lifecycle_id.clone(),
            receipt_digest_b64u: b64(&[0_u8; 32]),
            retired_at,
        };
        receipt.receipt_digest_b64u = b64(&receipt
            .digest()
            .map_err(|error| map_protocol_error("ECDSA retirement receipt is invalid", error))?);
        verify_retirement_request(request, &receipt)?;
        decode_b64::<32>(
            "ECDSA retirement effect binding",
            &request.retirement_effect_binding_digest_b64u,
        )?;
        let receipt_artifact = json_artifact(
            CloudflareSigningWorkerLaneArtifactKindV1::RetirementReceipt,
            &CloudflareEcdsaLaneStoredRetirementV1 {
                receipt: receipt.clone(),
                retirement_effect_binding_digest_b64u: request
                    .retirement_effect_binding_digest_b64u
                    .clone(),
            },
        )?;
        let command = CloudflareSigningWorkerLaneMaterialCommandV1::Retire {
            identity: request.identity.clone(),
            retirement: CloudflareSigningWorkerLaneRetirementV1 {
                revocation_epoch: request.revocation_epoch,
                reason: retirement_reason(&request.retirement_reason)?,
                correlation_id: request.retirement_correlation_id.clone(),
                request_digest_b64u: request.retirement_request_digest_b64u.clone(),
                receipt: receipt_artifact,
                retired_at_ms,
            },
        };
        match execute_cloudflare_signing_worker_lane_material_command_v1(env, &command).await? {
            CloudflareSigningWorkerLaneMaterialEffectV1::Retired { changed: true, .. } => {
                Ok(CloudflareSigningWorkerEcdsaLaneRetireEffectV1::Applied { receipt })
            }
            CloudflareSigningWorkerLaneMaterialEffectV1::Retired { changed: false, .. } => {
                Ok(CloudflareSigningWorkerEcdsaLaneRetireEffectV1::Replayed { receipt })
            }
            _ => Err(invalid(
                "SigningWorker returned the wrong ECDSA retirement effect",
            )),
        }
    }

    pub async fn handle_cloudflare_signing_worker_ecdsa_lane_execute_private_fetch_v1(
        mut request: Request,
        env: &Env,
        runtime: &CloudflareSigningWorkerRuntimeV1,
    ) -> worker::Result<Response> {
        if request.method() != Method::Post {
            return Response::error("method not allowed", 405);
        }
        let input = match request
            .json::<CloudflareSigningWorkerEcdsaLaneExecuteRequestV1>()
            .await
        {
            Ok(input) => input,
            Err(error) => {
                return Response::error(
                    format!(
                        "invalid ECDSA lane request: {}",
                        bounded_json_parse_error(&error)
                    ),
                    400,
                )
            }
        };
        let now = match cloudflare_now_unix_ms_v1() {
            Ok(now) => now,
            Err(error) => return protocol_error_response(error),
        };
        match execute_cloudflare_signing_worker_ecdsa_lane_v1(env, runtime, &input, now).await {
            Ok(effect) => Response::from_json(&effect),
            Err(error) => protocol_error_response(error),
        }
    }

    pub async fn handle_cloudflare_signing_worker_ecdsa_lane_activate_private_fetch_v1(
        mut request: Request,
        env: &Env,
        runtime: &CloudflareSigningWorkerRuntimeV1,
    ) -> worker::Result<Response> {
        if request.method() != Method::Post {
            return Response::error("method not allowed", 405);
        }
        let input = match request
            .json::<CloudflareSigningWorkerEcdsaLaneActivateRequestV1>()
            .await
        {
            Ok(input) => input,
            Err(_) => return Response::error("invalid ECDSA lane activation request", 400),
        };
        let now = match cloudflare_now_unix_ms_v1() {
            Ok(now) => now,
            Err(error) => return protocol_error_response(error),
        };
        match activate_cloudflare_signing_worker_ecdsa_lane_v1(env, runtime, &input, now).await {
            Ok(effect) => Response::from_json(&effect),
            Err(error) => protocol_error_response(error),
        }
    }

    pub async fn handle_cloudflare_signing_worker_ecdsa_lane_retire_private_fetch_v1(
        mut request: Request,
        env: &Env,
    ) -> worker::Result<Response> {
        if request.method() != Method::Post {
            return Response::error("method not allowed", 405);
        }
        let input = match request
            .json::<CloudflareSigningWorkerEcdsaLaneRetireRequestV1>()
            .await
        {
            Ok(input) => input,
            Err(_) => return Response::error("invalid ECDSA lane retirement request", 400),
        };
        let now = match cloudflare_now_unix_ms_v1() {
            Ok(now) => now,
            Err(error) => return protocol_error_response(error),
        };
        match retire_cloudflare_signing_worker_ecdsa_lane_v1(env, &input, now).await {
            Ok(effect) => Response::from_json(&effect),
            Err(error) => protocol_error_response(error),
        }
    }
}

#[cfg(feature = "workers-rs")]
pub use worker_execution::*;

#[cfg(test)]
mod tests {
    use super::*;
    use router_ab_ecdsa_client_protocol::{
        ActiveEcdsaLaneProtocolSourceV1, EcdsaLaneAuthorizationBindingV1, EcdsaLaneChainTargetV1,
        EcdsaLaneTargetHolderV1, EcdsaLaneTargetSigningWorkerV1, EcdsaMaterialActivationRefKindV1,
        EcdsaSourceCapabilityBindingV1, EcdsaTargetCapabilityBindingV1,
        EcdsaTargetThresholdSessionBindingV1,
    };

    const SECP256K1_GENERATOR_B64U: &str = "Anm-Zn753LusVaBilc6HCwcCm_zbLc4o2VnygVsW-BeY";

    fn bytes<const N: usize>(value: u8) -> String {
        b64(&[value; N])
    }

    fn activation(id: &str) -> EcdsaMaterialActivationRefV1 {
        EcdsaMaterialActivationRefV1 {
            kind: EcdsaMaterialActivationRefKindV1::MpcMaterialActivationRef,
            activation_id: id.to_owned(),
            capability: "capability-1".to_owned(),
            material_owner: "wallet-1".to_owned(),
            key_binding: "key-binding-1".to_owned(),
            lifecycle_binding: "lifecycle-1".to_owned(),
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
                source_kind:
                    router_ab_ecdsa_client_protocol::EcdsaLaneSourceKindV1::OwnerRegistration {
                        owner_participant_continuity:
                            router_ab_ecdsa_client_protocol::OwnerLaneParticipantContinuityV1 {
                                kind: "owner_lane_participant_continuity_v1".to_owned(),
                                signer_id: "signer-1".to_owned(),
                                participant_ids: [1, 2],
                                signing_worker_id: "worker-1".to_owned(),
                                custody_key_manifest_digest_b64u: b64(&[1; 32]),
                                source_identity_digest_b64u: b64(&[2; 32]),
                            },
                    },
                participant_binding_digest_b64u: bytes::<32>(1),
                material_activation: activation("activation-1"),
            },
            target_holder: EcdsaLaneTargetHolderV1 {
                participant_id: "holder-2".to_owned(),
                participant_binding_digest_b64u: bytes::<32>(2),
                custody_binding_id: "custody-2".to_owned(),
                custody_binding_digest_b64u: bytes::<32>(3),
                hpke_public_key_b64u: bytes::<32>(4),
                hpke_public_key_digest_b64u: bytes::<32>(5),
            },
            target_signing_worker: EcdsaLaneTargetSigningWorkerV1 {
                participant_id: "worker-2".to_owned(),
                participant_binding_digest_b64u: bytes::<32>(6),
                recipient_key_id: "recipient-2".to_owned(),
                hpke_public_key_b64u: bytes::<32>(7),
                hpke_public_key_digest_b64u: bytes::<32>(8),
            },
            target_material_activation_id: "activation-2".to_owned(),
            protocol_version: "rotatable_signing_lane_protocol_v1".to_owned(),
            expires_at_ms: 10_000,
            target: EcdsaLaneTargetOperationV1::CreateLane {
                lane_id: "linked-lane".to_owned(),
                lane_kind: "linked_device".to_owned(),
                lane_share_epoch: "epoch-1".to_owned(),
                expected_target_state: "absent".to_owned(),
            },
            authorization: EcdsaLaneAuthorizationBindingV1::LinkedDeviceEnrollment {
                authorized_operation_id: "authorized-1".to_owned(),
                linked_device_enrollment_id: "linked-enrollment-1".to_owned(),
                linked_device_permission_digest_b64u: bytes::<32>(9),
            },
            key_family: "ecdsa_secp256k1".to_owned(),
            evm_family_signing_key_slot_id: "evm-slot-1".to_owned(),
            threshold_public_key33_b64u: SECP256K1_GENERATOR_B64U.to_owned(),
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
                    participant_binding_digest_b64u: bytes::<32>(10),
                }],
            },
            source_holder_verifying_share33_b64u: SECP256K1_GENERATOR_B64U.to_owned(),
            source_server_verifying_share33_b64u: SECP256K1_GENERATOR_B64U.to_owned(),
            reshare_channel_binding_digest_b64u: bytes::<32>(11),
            transcript_encoding: "ecdsa_additive_lane_transcript_v1".to_owned(),
        }
    }

    fn envelope(value: u8) -> EcdsaLaneEncryptedPayloadV1 {
        EcdsaLaneEncryptedPayloadV1 {
            kind: "ecdsa_additive_lane_encrypted_payload_v1".to_owned(),
            recipient_public_key_b64u: bytes::<32>(value),
            aad_digest_b64u: bytes::<32>(value.wrapping_add(1)),
            encapped_key_b64u: bytes::<32>(value.wrapping_add(2)),
            ciphertext_b64u: bytes::<24>(value.wrapping_add(3)),
        }
    }

    fn request() -> CloudflareSigningWorkerEcdsaLaneExecuteRequestV1 {
        let job = job();
        let holder_package = envelope(20);
        let encrypted_delta = envelope(40);
        let holder_round = EcdsaAdditiveLaneHolderRoundV1 {
            kind: "ecdsa_additive_lane_holder_round_v1".to_owned(),
            preamble_hash_b64u: b64(&job.preamble_hash().expect("preamble")),
            target_holder_public_commitment33_b64u: SECP256K1_GENERATOR_B64U.to_owned(),
            encrypted_delta_ciphertext_digest_b64u: b64(&encrypted_delta
                .digest()
                .expect("delta digest")),
            sealed_target_holder_material_digest_b64u: b64(&holder_package
                .digest()
                .expect("holder digest")),
            holder_attestation_b64u: bytes::<16>(60),
            holder_committed_at_ms: 2_000,
        };
        CloudflareSigningWorkerEcdsaLaneExecuteRequestV1 {
            job,
            holder_round,
            holder_package,
            encrypted_delta,
            source_material: CloudflareEcdsaLaneSourceMaterialLookupV1::RegistrationActivation {
                lookup: CloudflareActiveSigningWorkerStateLookupV1 {
                    account_id: "wallet-1".to_owned(),
                    material_activation_id: "activation-1".to_owned(),
                    signing_worker_id: "worker-1".to_owned(),
                },
                source_derivation: CloudflareEcdsaRegistrationSourceDerivationV1 {
                    application_binding_digest_b64u: bytes::<32>(12),
                    client_share_retry_counter: 0,
                },
            },
        }
    }

    #[test]
    fn execute_request_rejects_holder_delta_digest_swap() {
        let request = request();
        request.validate().expect("request");
        let mut swapped = request.clone();
        core::mem::swap(&mut swapped.holder_package, &mut swapped.encrypted_delta);
        assert!(swapped.validate().is_err());
    }

    #[test]
    fn source_lookup_rejects_activation_substitution() {
        let mut request = request();
        request.source_material =
            CloudflareEcdsaLaneSourceMaterialLookupV1::RegistrationActivation {
                lookup: CloudflareActiveSigningWorkerStateLookupV1 {
                    account_id: "wallet-1".to_owned(),
                    material_activation_id: "activation-substitution".to_owned(),
                    signing_worker_id: "worker-1".to_owned(),
                },
                source_derivation: CloudflareEcdsaRegistrationSourceDerivationV1 {
                    application_binding_digest_b64u: bytes::<32>(12),
                    client_share_retry_counter: 0,
                },
            };
        assert!(request.validate().is_err());
    }

    #[test]
    fn registration_source_derivation_uses_snake_case_wire_fields() {
        let source_material = request().source_material;
        let value = serde_json::to_value(&source_material).expect("source material JSON");
        assert_eq!(
            value
                .get("sourceDerivation")
                .and_then(|entry| entry.get("application_binding_digest_b64u")),
            Some(&serde_json::Value::String(bytes::<32>(12))),
        );
        assert!(serde_json::from_value::<CloudflareEcdsaLaneSourceMaterialLookupV1>(value).is_ok());
    }

    #[test]
    fn protocol_receipt_rejects_recipient_digest_substitution() {
        let job = job();
        let mut receipt = CloudflareEcdsaLaneProtocolCommitReceiptV1 {
            kind: "lane_protocol_commit_receipt_v1".to_owned(),
            operation_id: job.operation_id.clone(),
            enrollment_id: job.enrollment_id.clone(),
            wallet_id: job.wallet_id.clone(),
            wallet_key_id: job.wallet_key_id.clone(),
            source_lane_id: job.source.lane_id().to_owned(),
            source_lane_share_epoch: job.source.lane_share_epoch().to_owned(),
            source_revocation_epoch: job.source.revocation_epoch(),
            source_material_activation: job.source.material_activation().clone(),
            target_lane_id: "linked-lane".to_owned(),
            target_lane_share_epoch: "epoch-1".to_owned(),
            target_material_activation_id: job.target_material_activation_id.clone(),
            key_family: "ecdsa_secp256k1".to_owned(),
            public_identity_digest_b64u: bytes::<32>(70),
            target_holder_public_commitment_b64u: SECP256K1_GENERATOR_B64U.to_owned(),
            target_server_public_commitment_b64u: SECP256K1_GENERATOR_B64U.to_owned(),
            target_holder_ciphertext_digest_set_b64u: bytes::<32>(71),
            target_server_ciphertext_digest_set_b64u: bytes::<32>(72),
            holder_recipient_key_digest_b64u: job.target_holder.hpke_public_key_digest_b64u.clone(),
            server_recipient_key_digest_b64u: job
                .target_signing_worker
                .hpke_public_key_digest_b64u
                .clone(),
            transcript_hash_b64u: bytes::<32>(73),
            committed_at_ms: 3_000,
        };
        receipt.validate_for_job(&job).expect("receipt");
        receipt.server_recipient_key_digest_b64u = bytes::<32>(99);
        assert!(receipt.validate_for_job(&job).is_err());
    }
}
