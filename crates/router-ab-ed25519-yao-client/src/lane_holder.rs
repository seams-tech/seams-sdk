use base64ct::{Base64UrlUnpadded, Encoding};
use core::fmt::Write as _;
use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT, edwards::CompressedEdwardsY, scalar::Scalar,
    traits::IsIdentity,
};
use hpke_ng::{DhKemX25519HkdfSha256, Kem};
use k256::{
    elliptic_curve::{sec1::ToEncodedPoint, PrimeField},
    ProjectivePoint, PublicKey, Scalar as K256Scalar, SecretKey,
};
use router_ab_core::{
    Ed25519YaoDeriverRoleV1, Ed25519YaoEncryptedPackageV1, Ed25519YaoLaneJobV1,
    Ed25519YaoPackageKindV1, MpcMaterialActivationRefV1,
};
use router_ab_ecdsa_client_protocol::{
    ecdsa_lane_public_identity_relation_digest_v1, open_ecdsa_lane_payload_v1,
    open_ecdsa_signing_worker_export_share_v1, EcdsaAdditiveLaneJobV1, EcdsaLaneEncryptedPayloadV1,
    EcdsaLaneTargetOperationV1, EcdsaMaterialActivationRefV1,
    EcdsaSigningWorkerExportShareBindingV1, EcdsaSigningWorkerExportShareEnvelopeV1,
};
use router_ab_ed25519_yao_protocol::{
    combine_lane_holder_packages_v1, ed25519_yao_lane_recipient_package_aad_v1,
    LaneDeriverAHolderPackage, LaneDeriverBHolderPackage,
    ED25519_YAO_LANE_RECIPIENT_PACKAGE_HPKE_INFO_V1,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use signer_core::passkey_custody::{
    open_verified_passkey_custody_secret_v1, seal_passkey_custody_secret_v1,
    PasskeyCustodyEnvelopeBindingV1, PasskeyCustodySecretBindingV1, WalletCustodyEnvelopeFactorV1,
    PASSKEY_CUSTODY_NONCE_LEN,
};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{derive_recipient_key_pair, ClientActivationError, RecipientHpkeV1};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LaneHolderError {
    InvalidShape,
    BindingMismatch,
    HpkeFailed,
    InvalidShare,
    UnsupportedFactor,
    AlreadyConsumed,
}

impl core::fmt::Display for LaneHolderError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidShape => "lane holder input is invalid",
            Self::BindingMismatch => "lane holder input changed its admitted binding",
            Self::HpkeFailed => "lane holder package could not be opened",
            Self::InvalidShare => "lane holder share does not match its public commitment",
            Self::UnsupportedFactor => "lane holder custody factor is unsupported",
            Self::AlreadyConsumed => "lane holder recipient was already consumed",
        })
    }
}

impl std::error::Error for LaneHolderError {}

/// Exact linked-lane facts required to redeem one ECDSA export share.
///
/// The record is public identity only. The holder and SigningWorker scalars
/// remain in this crate until the explicit export artifact is serialized.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct EcdsaLaneExportPublicFactsV1 {
    wallet_id: String,
    wallet_key_id: String,
    enrollment_id: String,
    operation_id: String,
    lane_id: String,
    lane_share_epoch: String,
    target_material_activation_id: String,
    ecdsa_threshold_key_id: String,
    threshold_public_key33_b64u: String,
    evm_address: String,
    target_holder_public_commitment33_b64u: String,
    target_server_public_commitment33_b64u: String,
    public_identity_digest_b64u: String,
}

impl EcdsaLaneExportPublicFactsV1 {
    fn from_job_and_receipt(
        job: &EcdsaAdditiveLaneJobV1,
        receipt: &LaneProtocolCommitReceiptWireV1,
    ) -> Self {
        Self {
            wallet_id: job.wallet_id.clone(),
            wallet_key_id: job.wallet_key_id.clone(),
            enrollment_id: job.enrollment_id.clone(),
            operation_id: job.operation_id.clone(),
            lane_id: ecdsa_target_lane_id(job).to_owned(),
            lane_share_epoch: ecdsa_target_lane_share_epoch(job).to_owned(),
            target_material_activation_id: job.target_material_activation_id.clone(),
            ecdsa_threshold_key_id: job.target_capability.ecdsa_threshold_key_id.clone(),
            threshold_public_key33_b64u: job.threshold_public_key33_b64u.clone(),
            evm_address: job.evm_address.clone(),
            target_holder_public_commitment33_b64u: receipt
                .target_holder_public_commitment_b64u
                .clone(),
            target_server_public_commitment33_b64u: receipt
                .target_server_public_commitment_b64u
                .clone(),
            public_identity_digest_b64u: receipt.public_identity_digest_b64u.clone(),
        }
    }

    fn validate(&self) -> Result<(), LaneHolderError> {
        for value in [
            &self.wallet_id,
            &self.wallet_key_id,
            &self.enrollment_id,
            &self.operation_id,
            &self.lane_id,
            &self.lane_share_epoch,
            &self.target_material_activation_id,
            &self.ecdsa_threshold_key_id,
            &self.evm_address,
        ] {
            if value.is_empty() || value.trim() != value {
                return Err(LaneHolderError::InvalidShape);
            }
        }
        decode_33(&self.threshold_public_key33_b64u)?;
        decode_evm_address20(&self.evm_address)?;
        decode_33(&self.target_holder_public_commitment33_b64u)?;
        decode_33(&self.target_server_public_commitment33_b64u)?;
        decode_32(&self.public_identity_digest_b64u)?;
        Ok(())
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct EcdsaLaneExportArtifactV1 {
    pub(crate) public_key33: [u8; 33],
    pub(crate) private_key32: [u8; 32],
    pub(crate) ethereum_address20: [u8; 20],
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct LaneCustodySealV1 {
    factor_secret: Zeroizing<[u8; 32]>,
    #[zeroize(skip)]
    binding: PasskeyCustodyEnvelopeBindingV1,
    #[zeroize(skip)]
    custody_binding_id: String,
    #[zeroize(skip)]
    custody_binding_digest_b64u: String,
}

impl LaneCustodySealV1 {
    pub(crate) fn from_factor(
        factor_kind: &str,
        factor_secret: [u8; 32],
        binding: PasskeyCustodyEnvelopeBindingV1,
        custody_binding_id: String,
        custody_binding_digest_b64u: String,
    ) -> Result<Self, LaneHolderError> {
        let factor_secret = Zeroizing::new(factor_secret);
        let factor_matches = matches!(
            (factor_kind, &binding.factor),
            ("passkey", WalletCustodyEnvelopeFactorV1::Passkey { .. })
                | ("email_otp", WalletCustodyEnvelopeFactorV1::EmailOtp { .. })
        );
        if !factor_matches
            || custody_binding_id.is_empty()
            || binding.envelope_id != custody_binding_id
        {
            return Err(LaneHolderError::UnsupportedFactor);
        }
        decode_32(&custody_binding_digest_b64u)?;
        Ok(Self {
            factor_secret,
            binding,
            custody_binding_id,
            custody_binding_digest_b64u,
        })
    }

    fn validate_ed_job(&self, job: &Ed25519YaoLaneJobV1) -> Result<(), LaneHolderError> {
        let PasskeyCustodySecretBindingV1::Ed25519LaneHolderShare {
            lane,
            near_ed25519_signing_key_id,
            registered_public_key_b64u,
            participant_binding_digest_b64u,
        } = &self.binding.binding
        else {
            return Err(LaneHolderError::BindingMismatch);
        };
        let valid = self.binding.wallet_id == job.wallet_id
            && lane.wallet_key_id == job.wallet_key_id
            && lane.lane_id == job.target_lane_id()
            && lane.lane_share_epoch == job.target_lane_share_epoch()
            && near_ed25519_signing_key_id == &job.near_ed25519_signing_key_id
            && registered_public_key_b64u == &job.registered_public_key_b64u
            && participant_binding_digest_b64u
                == &job.target_holder.participant_binding_digest_b64u
            && self.custody_binding_id == job.target_holder.custody_binding_id
            && self.custody_binding_digest_b64u == job.target_holder.custody_binding_digest_b64u;
        if valid {
            Ok(())
        } else {
            Err(LaneHolderError::BindingMismatch)
        }
    }

    fn validate_ecdsa_job(&self, job: &EcdsaAdditiveLaneJobV1) -> Result<(), LaneHolderError> {
        let PasskeyCustodySecretBindingV1::EcdsaLaneHolderShare {
            lane,
            evm_family_signing_key_slot_id,
            threshold_session_id,
            threshold_public_key33_b64u,
        } = &self.binding.binding
        else {
            return Err(LaneHolderError::BindingMismatch);
        };
        let target_session_matches = job
            .target_capability
            .ordered_threshold_sessions
            .iter()
            .any(|session| &session.threshold_session_id == threshold_session_id);
        let valid = self.binding.wallet_id == job.wallet_id
            && lane.wallet_key_id == job.wallet_key_id
            && lane.lane_id == ecdsa_target_lane_id(job)
            && lane.lane_share_epoch == ecdsa_target_lane_share_epoch(job)
            && evm_family_signing_key_slot_id == &job.evm_family_signing_key_slot_id
            && threshold_public_key33_b64u == &job.threshold_public_key33_b64u
            && target_session_matches
            && self.custody_binding_id == job.target_holder.custody_binding_id
            && self.custody_binding_digest_b64u == job.target_holder.custody_binding_digest_b64u;
        if valid {
            Ok(())
        } else {
            Err(LaneHolderError::BindingMismatch)
        }
    }

    fn seal(
        &self,
        share: &[u8; 32],
        nonce: &[u8],
        verified_digest: [u8; 32],
    ) -> Result<LaneHolderSealedOutputV1, LaneHolderError> {
        if nonce.len() != PASSKEY_CUSTODY_NONCE_LEN {
            return Err(LaneHolderError::InvalidShape);
        }
        let sealed =
            seal_passkey_custody_secret_v1(&*self.factor_secret, &self.binding, nonce, share)
                .map_err(|_| LaneHolderError::InvalidShape)?;
        let record = LaneHolderSealedRecordV1 {
            kind: "lane_holder_sealed_custody_envelope_v1",
            custody_binding_id: &self.custody_binding_id,
            custody_binding_digest_b64u: &self.custody_binding_digest_b64u,
            envelope_binding: &self.binding,
            nonce_b64u: Base64UrlUnpadded::encode_string(nonce),
            sealed_custody_secret_b64u: sealed.ciphertext_b64u(),
            aad_hash_b64u: sealed.aad_hash_b64u(),
            ciphertext_digest_b64u: sealed.ciphertext_digest_b64u(),
        };
        let encoded = serde_json::to_vec(&record).map_err(|_| LaneHolderError::InvalidShape)?;
        Ok(LaneHolderSealedOutputV1 {
            sealed_holder_material_b64u: Base64UrlUnpadded::encode_string(&encoded),
            sealed_holder_record_digest_b64u: b64(Sha256::digest(&encoded).into()),
            verified_holder_ciphertext_digest_set_b64u: b64(verified_digest),
        })
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LaneHolderSealedRecordV1<'a> {
    kind: &'static str,
    custody_binding_id: &'a str,
    custody_binding_digest_b64u: &'a str,
    envelope_binding: &'a PasskeyCustodyEnvelopeBindingV1,
    nonce_b64u: String,
    sealed_custody_secret_b64u: String,
    aad_hash_b64u: String,
    ciphertext_digest_b64u: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OpenableLaneHolderSealedRecordV1 {
    kind: String,
    custody_binding_id: String,
    custody_binding_digest_b64u: String,
    envelope_binding: PasskeyCustodyEnvelopeBindingV1,
    nonce_b64u: String,
    sealed_custody_secret_b64u: String,
    aad_hash_b64u: String,
    ciphertext_digest_b64u: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LaneHolderSealedOutputV1 {
    sealed_holder_material_b64u: String,
    sealed_holder_record_digest_b64u: String,
    verified_holder_ciphertext_digest_set_b64u: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LaneHolderVerifiedOutputV1 {
    verified_holder_ciphertext_digest_set_b64u: String,
}

pub(crate) enum LaneHolderSigningMaterialV1 {
    Ed25519 {
        share: Zeroizing<[u8; 32]>,
        registered_public_key: [u8; 32],
    },
    Ecdsa {
        share: Zeroizing<[u8; 32]>,
        export_facts: EcdsaLaneExportPublicFactsV1,
    },
    Destroyed,
}

impl LaneHolderSigningMaterialV1 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn open(
        factor_secret: &[u8],
        sealed_holder_material_b64u: &str,
        expected_record_digest_b64u: &str,
        expected_holder_ciphertext_digest_set_b64u: &str,
        job_json: &str,
        receipt_json: &str,
    ) -> Result<Self, LaneHolderError> {
        let (record, share) = open_sealed_holder_secret(
            factor_secret,
            sealed_holder_material_b64u,
            expected_record_digest_b64u,
        )?;
        let receipt = parse_receipt(receipt_json)?;
        require_same_digest(
            expected_holder_ciphertext_digest_set_b64u,
            &receipt.target_holder_ciphertext_digest_set_b64u,
        )?;
        let factor_kind = record.envelope_binding.factor.kind_str();
        let factor_secret: [u8; 32] = factor_secret
            .try_into()
            .map_err(|_| LaneHolderError::InvalidShape)?;
        let custody = LaneCustodySealV1::from_factor(
            factor_kind,
            factor_secret,
            record.envelope_binding,
            record.custody_binding_id,
            record.custody_binding_digest_b64u,
        )?;
        if let Ok(job) = serde_json::from_str::<Ed25519YaoLaneJobV1>(job_json) {
            job.validate().map_err(|_| LaneHolderError::InvalidShape)?;
            custody.validate_ed_job(&job)?;
            validate_ed_receipt(&job, &receipt)?;
            let scalar_option = Scalar::from_canonical_bytes(*share);
            let scalar = scalar_option.unwrap_or(Scalar::ZERO);
            let commitment = (ED25519_BASEPOINT_POINT * scalar).compress().to_bytes();
            let expected_commitment = decode_32(&receipt.target_holder_public_commitment_b64u)?;
            let valid = scalar_option.is_some()
                & !scalar.ct_eq(&Scalar::ZERO)
                & commitment.ct_eq(&expected_commitment);
            if !bool::from(valid) {
                return Err(LaneHolderError::InvalidShare);
            }
            return Ok(Self::Ed25519 {
                share,
                registered_public_key: decode_32(&job.registered_public_key_b64u)?,
            });
        }
        let job = serde_json::from_str::<EcdsaAdditiveLaneJobV1>(job_json)
            .map_err(|_| LaneHolderError::InvalidShape)?;
        job.validate().map_err(|_| LaneHolderError::InvalidShape)?;
        custody.validate_ecdsa_job(&job)?;
        validate_ecdsa_receipt(&job, &receipt)?;
        let secret =
            SecretKey::from_slice(share.as_ref()).map_err(|_| LaneHolderError::InvalidShare)?;
        let commitment = secret.public_key().to_encoded_point(true);
        let expected_commitment = decode_33(&receipt.target_holder_public_commitment_b64u)?;
        if !bool::from(commitment.as_bytes().ct_eq(&expected_commitment)) {
            return Err(LaneHolderError::InvalidShare);
        }
        Ok(Self::Ecdsa {
            share,
            export_facts: EcdsaLaneExportPublicFactsV1::from_job_and_receipt(&job, &receipt),
        })
    }

    pub(crate) fn kind(&self) -> Result<&'static str, LaneHolderError> {
        match self {
            Self::Ed25519 { .. } => Ok("ed25519"),
            Self::Ecdsa { .. } => Ok("ecdsa_secp256k1"),
            Self::Destroyed => Err(LaneHolderError::AlreadyConsumed),
        }
    }

    pub(crate) fn ed25519_material(&self) -> Result<(&[u8; 32], &[u8; 32]), LaneHolderError> {
        match self {
            Self::Ed25519 {
                share,
                registered_public_key,
            } => Ok((share, registered_public_key)),
            Self::Ecdsa { .. } | Self::Destroyed => Err(LaneHolderError::BindingMismatch),
        }
    }

    pub(crate) fn ecdsa_material(&self) -> Result<&[u8; 32], LaneHolderError> {
        match self {
            Self::Ecdsa { share, .. } => Ok(share),
            Self::Ed25519 { .. } | Self::Destroyed => Err(LaneHolderError::BindingMismatch),
        }
    }

    fn ecdsa_export_facts(&self) -> Result<&EcdsaLaneExportPublicFactsV1, LaneHolderError> {
        match self {
            Self::Ecdsa { export_facts, .. } => Ok(export_facts),
            Self::Ed25519 { .. } | Self::Destroyed => Err(LaneHolderError::BindingMismatch),
        }
    }

    pub(crate) fn destroy(&mut self) {
        *self = Self::Destroyed;
    }
}

fn open_sealed_holder_secret(
    factor_secret: &[u8],
    sealed_holder_material_b64u: &str,
    expected_record_digest_b64u: &str,
) -> Result<(OpenableLaneHolderSealedRecordV1, Zeroizing<[u8; 32]>), LaneHolderError> {
    if factor_secret.len() != 32 {
        return Err(LaneHolderError::InvalidShape);
    }
    let encoded = decode_b64u(sealed_holder_material_b64u)?;
    require_digest_match(expected_record_digest_b64u, Sha256::digest(&encoded).into())?;
    let record = serde_json::from_slice::<OpenableLaneHolderSealedRecordV1>(&encoded)
        .map_err(|_| LaneHolderError::InvalidShape)?;
    if record.kind != "lane_holder_sealed_custody_envelope_v1"
        || record.custody_binding_id != record.envelope_binding.envelope_id
    {
        return Err(LaneHolderError::BindingMismatch);
    }
    decode_32(&record.custody_binding_digest_b64u)?;
    let nonce = decode_b64u(&record.nonce_b64u)?;
    let ciphertext = decode_b64u(&record.sealed_custody_secret_b64u)?;
    let aad_hash = decode_32(&record.aad_hash_b64u)?;
    let ciphertext_digest = decode_32(&record.ciphertext_digest_b64u)?;
    let mut opened = open_verified_passkey_custody_secret_v1(
        factor_secret,
        &record.envelope_binding,
        &nonce,
        &ciphertext,
        &aad_hash,
        &ciphertext_digest,
    )
    .map_err(|_| LaneHolderError::HpkeFailed)?;
    let share: [u8; 32] = opened
        .as_slice()
        .try_into()
        .map_err(|_| LaneHolderError::InvalidShare)?;
    opened.zeroize();
    Ok((record, Zeroizing::new(share)))
}

pub(crate) struct LaneHolderRecipientV1 {
    operation_id: String,
    recipient_private_key: Option<Zeroizing<[u8; 32]>>,
    recipient_public_key_b64u: String,
    recipient_public_key_digest_b64u: String,
}

impl LaneHolderRecipientV1 {
    pub(crate) fn new(
        operation_id: String,
        key_material: [u8; 32],
    ) -> Result<Self, LaneHolderError> {
        let key_material = Zeroizing::new(key_material);
        if operation_id.is_empty() {
            return Err(LaneHolderError::InvalidShape);
        }
        let (private_key, public_key) =
            derive_recipient_key_pair(&key_material).map_err(map_activation_error)?;
        Ok(Self {
            operation_id,
            recipient_private_key: Some(Zeroizing::new(private_key)),
            recipient_public_key_b64u: b64(public_key),
            recipient_public_key_digest_b64u: b64(Sha256::digest(public_key).into()),
        })
    }

    pub(crate) fn public_key_b64u(&self) -> &str {
        &self.recipient_public_key_b64u
    }

    pub(crate) fn public_key_digest_b64u(&self) -> &str {
        &self.recipient_public_key_digest_b64u
    }

    pub(crate) fn destroy(&mut self) {
        self.recipient_private_key = None;
    }

    pub(crate) fn open_and_seal(
        &mut self,
        custody: &LaneCustodySealV1,
        job_json: &str,
        receipt_json: &str,
        holder_package_json: &str,
        nonce: &[u8],
    ) -> Result<LaneHolderSealedOutputV1, LaneHolderError> {
        let private_key = self
            .recipient_private_key
            .take()
            .ok_or(LaneHolderError::AlreadyConsumed)?;
        let mut opened = open_holder_share(
            &self.operation_id,
            &self.recipient_public_key_b64u,
            &self.recipient_public_key_digest_b64u,
            &private_key,
            custody,
            job_json,
            receipt_json,
            holder_package_json,
        )?;
        let result = custody.seal(&opened.share, nonce, opened.verified_digest);
        opened.zeroize();
        result
    }

    pub(crate) fn finalize_ecdsa_export(
        &mut self,
        holder_material: &LaneHolderSigningMaterialV1,
        signing_worker_export_json: &str,
        expected_binding_json: &str,
        expected_public_facts_json: &str,
    ) -> Result<EcdsaLaneExportArtifactV1, LaneHolderError> {
        let expected_binding =
            serde_json::from_str::<EcdsaSigningWorkerExportShareBindingV1>(expected_binding_json)
                .map_err(|_| LaneHolderError::InvalidShape)?;
        let expected_facts =
            serde_json::from_str::<EcdsaLaneExportPublicFactsV1>(expected_public_facts_json)
                .map_err(|_| LaneHolderError::InvalidShape)?;
        expected_facts.validate()?;
        let recipient_public_key = x25519_protocol_key(&self.recipient_public_key_b64u)?;
        if self.operation_id != expected_binding.recipient_identity
            || recipient_public_key != expected_binding.recipient_public_key
        {
            return Err(LaneHolderError::BindingMismatch);
        }

        let holder_facts = holder_material.ecdsa_export_facts()?;
        if holder_facts != &expected_facts {
            return Err(LaneHolderError::BindingMismatch);
        }
        if expected_binding.wallet_id != expected_facts.wallet_id
            || expected_binding.ecdsa_threshold_key_id != expected_facts.ecdsa_threshold_key_id
            || expected_binding.threshold_public_key33_b64u
                != expected_facts.threshold_public_key33_b64u
            || expected_binding.material_activation.activation_id
                != expected_facts.target_material_activation_id
            || expected_binding.material_activation.material_owner != expected_facts.wallet_id
        {
            return Err(LaneHolderError::BindingMismatch);
        }

        let recipient_private_key = self
            .recipient_private_key
            .take()
            .ok_or(LaneHolderError::AlreadyConsumed)?;
        let envelope = serde_json::from_str::<EcdsaSigningWorkerExportShareEnvelopeV1>(
            signing_worker_export_json,
        )
        .map_err(|_| LaneHolderError::InvalidShape)?;
        let mut server_share = open_ecdsa_signing_worker_export_share_v1(
            &envelope,
            &expected_binding,
            &recipient_private_key,
        )
        .map_err(|_| LaneHolderError::HpkeFailed)?;
        let result = combine_ecdsa_export_shares(holder_material, &server_share, &expected_facts);
        server_share.zeroize();
        result
    }
}

fn x25519_protocol_key(recipient_public_key_b64u: &str) -> Result<String, LaneHolderError> {
    let recipient_public_key = decode_32(recipient_public_key_b64u)?;
    let mut encoded = String::with_capacity("x25519:".len() + recipient_public_key.len() * 2);
    encoded.push_str("x25519:");
    for byte in recipient_public_key {
        write!(&mut encoded, "{byte:02x}").map_err(|_| LaneHolderError::InvalidShape)?;
    }
    Ok(encoded)
}

fn combine_ecdsa_export_shares(
    holder_material: &LaneHolderSigningMaterialV1,
    server_share: &[u8; 32],
    facts: &EcdsaLaneExportPublicFactsV1,
) -> Result<EcdsaLaneExportArtifactV1, LaneHolderError> {
    let holder_share = holder_material.ecdsa_material()?;
    let holder_secret =
        SecretKey::from_slice(holder_share).map_err(|_| LaneHolderError::InvalidShare)?;
    let server_secret =
        SecretKey::from_slice(server_share).map_err(|_| LaneHolderError::InvalidShare)?;
    let holder_commitment = holder_secret.public_key().to_encoded_point(true);
    let server_commitment = server_secret.public_key().to_encoded_point(true);
    let expected_holder_commitment = decode_33(&facts.target_holder_public_commitment33_b64u)?;
    let expected_server_commitment = decode_33(&facts.target_server_public_commitment33_b64u)?;
    if !bool::from(
        holder_commitment
            .as_bytes()
            .ct_eq(&expected_holder_commitment),
    ) || !bool::from(
        server_commitment
            .as_bytes()
            .ct_eq(&expected_server_commitment),
    ) {
        return Err(LaneHolderError::InvalidShare);
    }
    verify_ecdsa_public_identity_facts(
        &facts.target_holder_public_commitment33_b64u,
        &facts.target_server_public_commitment33_b64u,
        &facts.threshold_public_key33_b64u,
        &facts.evm_address,
        &facts.public_identity_digest_b64u,
    )?;

    let holder_scalar = Option::<K256Scalar>::from(K256Scalar::from_repr((*holder_share).into()))
        .ok_or(LaneHolderError::InvalidShare)?;
    let server_scalar = Option::<K256Scalar>::from(K256Scalar::from_repr((*server_share).into()))
        .ok_or(LaneHolderError::InvalidShare)?;
    let private_key32 = holder_scalar + server_scalar;
    let private_key = SecretKey::from_slice(&private_key32.to_bytes())
        .map_err(|_| LaneHolderError::InvalidShare)?;
    let public_key33: [u8; 33] = private_key
        .public_key()
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .map_err(|_| LaneHolderError::InvalidShare)?;
    let expected_public_key33 = decode_33(&facts.threshold_public_key33_b64u)?;
    if !bool::from(public_key33.ct_eq(&expected_public_key33)) {
        return Err(LaneHolderError::InvalidShare);
    }
    let ethereum_address20 = ethereum_address_from_public_key33(&public_key33)?;
    let expected_ethereum_address20 = decode_evm_address20(&facts.evm_address)?;
    if !bool::from(ethereum_address20.ct_eq(&expected_ethereum_address20)) {
        return Err(LaneHolderError::InvalidShare);
    }
    Ok(EcdsaLaneExportArtifactV1 {
        public_key33,
        private_key32: private_key32.to_bytes().into(),
        ethereum_address20,
    })
}

fn ethereum_address_from_public_key33(
    public_key33: &[u8; 33],
) -> Result<[u8; 20], LaneHolderError> {
    let address =
        signer_core::secp256k1::secp256k1_public_key_33_to_ethereum_address_20(public_key33)
            .map_err(|_| LaneHolderError::InvalidShape)?;
    address
        .try_into()
        .map_err(|_| LaneHolderError::InvalidShape)
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct OpenedHolderShareV1 {
    share: [u8; 32],
    #[zeroize(skip)]
    verified_digest: [u8; 32],
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LaneProtocolCommitReceiptWireV1 {
    kind: String,
    operation_id: String,
    enrollment_id: String,
    wallet_id: String,
    wallet_key_id: String,
    source_lane_id: String,
    source_lane_share_epoch: String,
    source_revocation_epoch: u64,
    source_material_activation: LaneMaterialActivationWireV1,
    target_lane_id: String,
    target_lane_share_epoch: String,
    target_material_activation_id: String,
    key_family: String,
    public_identity_digest_b64u: String,
    target_holder_public_commitment_b64u: String,
    target_server_public_commitment_b64u: String,
    target_holder_ciphertext_digest_set_b64u: String,
    target_server_ciphertext_digest_set_b64u: String,
    holder_recipient_key_digest_b64u: String,
    server_recipient_key_digest_b64u: String,
    transcript_hash_b64u: String,
    committed_at_ms: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LaneMaterialActivationWireV1 {
    kind: String,
    activation_id: String,
    capability: String,
    material_owner: String,
    key_binding: String,
    lifecycle_binding: String,
    signing_worker: String,
}

impl LaneMaterialActivationWireV1 {
    fn matches_ed25519(&self, activation: &MpcMaterialActivationRefV1) -> bool {
        self.kind == "mpc_material_activation_ref"
            && self.activation_id == activation.activation_id
            && self.capability == activation.capability
            && self.material_owner == activation.material_owner
            && self.key_binding == activation.key_binding
            && self.lifecycle_binding == activation.lifecycle_binding
            && self.signing_worker == activation.signing_worker
    }

    fn matches_ecdsa(&self, activation: &EcdsaMaterialActivationRefV1) -> bool {
        self.kind == "mpc_material_activation_ref"
            && self.activation_id == activation.activation_id
            && self.capability == activation.capability
            && self.material_owner == activation.material_owner
            && self.key_binding == activation.key_binding
            && self.lifecycle_binding == activation.lifecycle_binding
            && self.signing_worker == activation.signing_worker
    }
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum HolderPackageWireV1 {
    Ed25519YaoLaneHolderPackageSetV1 {
        #[serde(rename = "deriverAEncryptedPackageJson")]
        deriver_a_encrypted_package_json: String,
        #[serde(rename = "deriverBEncryptedPackageJson")]
        deriver_b_encrypted_package_json: String,
    },
    EcdsaAdditiveLaneHolderPackageV1 {
        #[serde(rename = "ecdsaEncryptedMaterialEnvelopeJson")]
        ecdsa_encrypted_material_envelope_json: String,
    },
}

pub(crate) fn verify_holder_package(
    job_json: &str,
    receipt_json: &str,
    holder_package_json: &str,
) -> Result<LaneHolderVerifiedOutputV1, LaneHolderError> {
    let receipt = parse_receipt(receipt_json)?;
    let package = serde_json::from_str::<HolderPackageWireV1>(holder_package_json)
        .map_err(|_| LaneHolderError::InvalidShape)?;
    let digest = if let Ok(job) = serde_json::from_str::<Ed25519YaoLaneJobV1>(job_json) {
        job.validate().map_err(|_| LaneHolderError::InvalidShape)?;
        validate_ed_receipt(&job, &receipt)?;
        let HolderPackageWireV1::Ed25519YaoLaneHolderPackageSetV1 {
            deriver_a_encrypted_package_json,
            deriver_b_encrypted_package_json,
        } = package
        else {
            return Err(LaneHolderError::BindingMismatch);
        };
        let package_a = parse_ed_package(&deriver_a_encrypted_package_json)?;
        let package_b = parse_ed_package(&deriver_b_encrypted_package_json)?;
        validate_ed_package_metadata(&job, &receipt, &package_a, &package_b)?;
        ed_holder_ciphertext_digest(&package_a, &package_b)
    } else {
        let job = serde_json::from_str::<EcdsaAdditiveLaneJobV1>(job_json)
            .map_err(|_| LaneHolderError::InvalidShape)?;
        job.validate().map_err(|_| LaneHolderError::InvalidShape)?;
        validate_ecdsa_receipt(&job, &receipt)?;
        let HolderPackageWireV1::EcdsaAdditiveLaneHolderPackageV1 {
            ecdsa_encrypted_material_envelope_json,
        } = package
        else {
            return Err(LaneHolderError::BindingMismatch);
        };
        let payload = parse_ecdsa_payload(&ecdsa_encrypted_material_envelope_json)?;
        validate_ecdsa_package_metadata(&job, &receipt, &payload)?;
        payload
            .digest()
            .map_err(|_| LaneHolderError::InvalidShape)?
    };
    require_digest_match(&receipt.target_holder_ciphertext_digest_set_b64u, digest)?;
    Ok(LaneHolderVerifiedOutputV1 {
        verified_holder_ciphertext_digest_set_b64u: b64(digest),
    })
}

#[allow(clippy::too_many_arguments)]
fn open_holder_share(
    operation_id: &str,
    recipient_public_key_b64u: &str,
    recipient_public_key_digest_b64u: &str,
    recipient_private_key: &[u8; 32],
    custody: &LaneCustodySealV1,
    job_json: &str,
    receipt_json: &str,
    holder_package_json: &str,
) -> Result<OpenedHolderShareV1, LaneHolderError> {
    let receipt = parse_receipt(receipt_json)?;
    let package = serde_json::from_str::<HolderPackageWireV1>(holder_package_json)
        .map_err(|_| LaneHolderError::InvalidShape)?;
    if let Ok(job) = serde_json::from_str::<Ed25519YaoLaneJobV1>(job_json) {
        job.validate().map_err(|_| LaneHolderError::InvalidShape)?;
        validate_recipient_identity(
            operation_id,
            recipient_public_key_b64u,
            recipient_public_key_digest_b64u,
            &job.operation_id,
            &job.target_holder.hpke_public_key_b64u,
            &job.target_holder.hpke_public_key_digest_b64u,
        )?;
        custody.validate_ed_job(&job)?;
        validate_ed_receipt(&job, &receipt)?;
        let HolderPackageWireV1::Ed25519YaoLaneHolderPackageSetV1 {
            deriver_a_encrypted_package_json,
            deriver_b_encrypted_package_json,
        } = package
        else {
            return Err(LaneHolderError::BindingMismatch);
        };
        return open_ed_share(
            &job,
            &receipt,
            recipient_private_key,
            &deriver_a_encrypted_package_json,
            &deriver_b_encrypted_package_json,
        );
    }
    let job = serde_json::from_str::<EcdsaAdditiveLaneJobV1>(job_json)
        .map_err(|_| LaneHolderError::InvalidShape)?;
    job.validate().map_err(|_| LaneHolderError::InvalidShape)?;
    validate_recipient_identity(
        operation_id,
        recipient_public_key_b64u,
        recipient_public_key_digest_b64u,
        &job.operation_id,
        &job.target_holder.hpke_public_key_b64u,
        &job.target_holder.hpke_public_key_digest_b64u,
    )?;
    custody.validate_ecdsa_job(&job)?;
    validate_ecdsa_receipt(&job, &receipt)?;
    let HolderPackageWireV1::EcdsaAdditiveLaneHolderPackageV1 {
        ecdsa_encrypted_material_envelope_json,
    } = package
    else {
        return Err(LaneHolderError::BindingMismatch);
    };
    open_ecdsa_share(
        &job,
        &receipt,
        recipient_private_key,
        &ecdsa_encrypted_material_envelope_json,
    )
}

fn open_ed_share(
    job: &Ed25519YaoLaneJobV1,
    receipt: &LaneProtocolCommitReceiptWireV1,
    recipient_private_key: &[u8; 32],
    package_a_json: &str,
    package_b_json: &str,
) -> Result<OpenedHolderShareV1, LaneHolderError> {
    let package_a = parse_ed_package(package_a_json)?;
    let package_b = parse_ed_package(package_b_json)?;
    validate_ed_package_metadata(job, receipt, &package_a, &package_b)?;
    let target_lane_digest = Sha256::digest(job.target_lane_id().as_bytes()).into();
    let plaintext_a = open_ed_package(
        &package_a,
        recipient_private_key,
        target_lane_digest,
        Ed25519YaoDeriverRoleV1::DeriverA,
    )?;
    let plaintext_b = open_ed_package(
        &package_b,
        recipient_private_key,
        target_lane_digest,
        Ed25519YaoDeriverRoleV1::DeriverB,
    )?;
    let share = combine_lane_holder_packages_v1(
        job.session_v1()
            .map_err(|_| LaneHolderError::InvalidShape)?,
        decode_32(&receipt.transcript_hash_b64u)?,
        LaneDeriverAHolderPackage::from_bytes(plaintext_a)
            .map_err(|_| LaneHolderError::InvalidShare)?,
        LaneDeriverBHolderPackage::from_bytes(plaintext_b)
            .map_err(|_| LaneHolderError::InvalidShare)?,
    )
    .map_err(|_| LaneHolderError::InvalidShare)?
    .into_bytes();
    let scalar_option = Scalar::from_canonical_bytes(share);
    let scalar = scalar_option.unwrap_or(Scalar::ZERO);
    let commitment = (ED25519_BASEPOINT_POINT * scalar).compress().to_bytes();
    let expected = decode_32(&receipt.target_holder_public_commitment_b64u)?;
    let valid = scalar_option.is_some() & commitment.ct_eq(&expected);
    if !bool::from(valid) {
        return Err(LaneHolderError::InvalidShare);
    }
    let verified_digest = ed_holder_ciphertext_digest(&package_a, &package_b);
    require_digest_match(
        &receipt.target_holder_ciphertext_digest_set_b64u,
        verified_digest,
    )?;
    Ok(OpenedHolderShareV1 {
        share,
        verified_digest,
    })
}

fn open_ecdsa_share(
    job: &EcdsaAdditiveLaneJobV1,
    receipt: &LaneProtocolCommitReceiptWireV1,
    recipient_private_key: &[u8; 32],
    payload_json: &str,
) -> Result<OpenedHolderShareV1, LaneHolderError> {
    let payload = parse_ecdsa_payload(payload_json)?;
    validate_ecdsa_package_metadata(job, receipt, &payload)?;
    let mut plaintext = Zeroizing::new(
        open_ecdsa_lane_payload_v1(
            &payload,
            recipient_private_key,
            &job.preamble_hash()
                .map_err(|_| LaneHolderError::InvalidShape)?,
        )
        .map_err(|_| LaneHolderError::HpkeFailed)?,
    );
    let share: [u8; 32] = plaintext
        .as_slice()
        .try_into()
        .map_err(|_| LaneHolderError::InvalidShare)?;
    plaintext.zeroize();
    let secret = SecretKey::from_slice(&share).map_err(|_| LaneHolderError::InvalidShare)?;
    let commitment = secret.public_key().to_encoded_point(true);
    let expected = decode_33(&receipt.target_holder_public_commitment_b64u)?;
    if !bool::from(commitment.as_bytes().ct_eq(&expected)) {
        return Err(LaneHolderError::InvalidShare);
    }
    let verified_digest = payload
        .digest()
        .map_err(|_| LaneHolderError::InvalidShape)?;
    require_digest_match(
        &receipt.target_holder_ciphertext_digest_set_b64u,
        verified_digest,
    )?;
    Ok(OpenedHolderShareV1 {
        share,
        verified_digest,
    })
}

fn open_ed_package(
    package: &Ed25519YaoEncryptedPackageV1,
    private_key: &[u8; 32],
    target_lane_digest: [u8; 32],
    expected_deriver: Ed25519YaoDeriverRoleV1,
) -> Result<Vec<u8>, LaneHolderError> {
    if package.kind() != Ed25519YaoPackageKindV1::LaneHolder
        || package.deriver() != expected_deriver
    {
        return Err(LaneHolderError::BindingMismatch);
    }
    let encapped = DhKemX25519HkdfSha256::enc_from_bytes(package.encapsulated_key())
        .map_err(|_| LaneHolderError::HpkeFailed)?;
    let private_key = DhKemX25519HkdfSha256::sk_from_bytes(private_key)
        .map_err(|_| LaneHolderError::HpkeFailed)?;
    let aad = ed25519_yao_lane_recipient_package_aad_v1(
        package.kind(),
        package.deriver(),
        package.session(),
        package.transcript(),
        target_lane_digest,
    );
    RecipientHpkeV1::open_base(
        &encapped,
        &private_key,
        ED25519_YAO_LANE_RECIPIENT_PACKAGE_HPKE_INFO_V1,
        &aad,
        package.ciphertext(),
    )
    .map_err(|_| LaneHolderError::HpkeFailed)
}

fn validate_recipient_identity(
    operation_id: &str,
    public_key_b64u: &str,
    public_key_digest_b64u: &str,
    job_operation_id: &str,
    job_public_key_b64u: &str,
    job_public_key_digest_b64u: &str,
) -> Result<(), LaneHolderError> {
    if operation_id == job_operation_id
        && public_key_b64u == job_public_key_b64u
        && public_key_digest_b64u == job_public_key_digest_b64u
    {
        Ok(())
    } else {
        Err(LaneHolderError::BindingMismatch)
    }
}

fn parse_receipt(value: &str) -> Result<LaneProtocolCommitReceiptWireV1, LaneHolderError> {
    let receipt = serde_json::from_str::<LaneProtocolCommitReceiptWireV1>(value)
        .map_err(|_| LaneHolderError::InvalidShape)?;
    if receipt.kind != "lane_protocol_commit_receipt_v1" || receipt.committed_at_ms == 0 {
        return Err(LaneHolderError::InvalidShape);
    }
    for digest in [
        &receipt.public_identity_digest_b64u,
        &receipt.target_holder_ciphertext_digest_set_b64u,
        &receipt.target_server_ciphertext_digest_set_b64u,
        &receipt.holder_recipient_key_digest_b64u,
        &receipt.server_recipient_key_digest_b64u,
        &receipt.transcript_hash_b64u,
    ] {
        decode_32(digest)?;
    }
    match receipt.key_family.as_str() {
        "ed25519" => {
            decode_32(&receipt.target_holder_public_commitment_b64u)?;
            decode_32(&receipt.target_server_public_commitment_b64u)?;
        }
        "ecdsa_secp256k1" => {
            decode_33(&receipt.target_holder_public_commitment_b64u)?;
            decode_33(&receipt.target_server_public_commitment_b64u)?;
        }
        _ => return Err(LaneHolderError::InvalidShape),
    }
    Ok(receipt)
}

fn validate_ed_receipt(
    job: &Ed25519YaoLaneJobV1,
    receipt: &LaneProtocolCommitReceiptWireV1,
) -> Result<(), LaneHolderError> {
    let valid = receipt.operation_id == job.operation_id
        && receipt.enrollment_id == job.enrollment_id
        && receipt.wallet_id == job.wallet_id
        && receipt.wallet_key_id == job.wallet_key_id
        && receipt.source_lane_id == job.source.lane_id()
        && receipt.source_lane_share_epoch == job.source.lane_share_epoch()
        && receipt.source_revocation_epoch == job.source.revocation_epoch()
        && receipt
            .source_material_activation
            .matches_ed25519(job.source.material_activation())
        && receipt.target_lane_id == job.target_lane_id()
        && receipt.target_lane_share_epoch == job.target_lane_share_epoch()
        && receipt.target_material_activation_id == job.target_material_activation_id
        && receipt.key_family == "ed25519";
    verify_recipient_digests(
        &receipt.holder_recipient_key_digest_b64u,
        &receipt.server_recipient_key_digest_b64u,
        &job.target_holder.hpke_public_key_digest_b64u,
        &job.target_signing_worker.hpke_public_key_digest_b64u,
    )?;
    verify_ed_public_identity(job, receipt)?;
    if valid {
        Ok(())
    } else {
        Err(LaneHolderError::BindingMismatch)
    }
}

fn validate_ecdsa_receipt(
    job: &EcdsaAdditiveLaneJobV1,
    receipt: &LaneProtocolCommitReceiptWireV1,
) -> Result<(), LaneHolderError> {
    let valid = receipt.operation_id == job.operation_id
        && receipt.enrollment_id == job.enrollment_id
        && receipt.wallet_id == job.wallet_id
        && receipt.wallet_key_id == job.wallet_key_id
        && receipt.source_lane_id == job.source.lane_id()
        && receipt.source_lane_share_epoch == job.source.lane_share_epoch()
        && receipt.source_revocation_epoch == job.source.revocation_epoch()
        && receipt
            .source_material_activation
            .matches_ecdsa(job.source.material_activation())
        && receipt.target_lane_id == ecdsa_target_lane_id(job)
        && receipt.target_lane_share_epoch == ecdsa_target_lane_share_epoch(job)
        && receipt.target_material_activation_id == job.target_material_activation_id
        && receipt.key_family == "ecdsa_secp256k1";
    verify_recipient_digests(
        &receipt.holder_recipient_key_digest_b64u,
        &receipt.server_recipient_key_digest_b64u,
        &job.target_holder.hpke_public_key_digest_b64u,
        &job.target_signing_worker.hpke_public_key_digest_b64u,
    )?;
    verify_ecdsa_public_identity(job, receipt)?;
    if valid {
        Ok(())
    } else {
        Err(LaneHolderError::BindingMismatch)
    }
}

fn verify_ed_public_identity(
    job: &Ed25519YaoLaneJobV1,
    receipt: &LaneProtocolCommitReceiptWireV1,
) -> Result<(), LaneHolderError> {
    verify_ed_public_identity_facts(
        &receipt.transcript_hash_b64u,
        &receipt.target_holder_public_commitment_b64u,
        &receipt.target_server_public_commitment_b64u,
        &job.registered_public_key_b64u,
        &receipt.public_identity_digest_b64u,
    )
}

fn verify_ed_public_identity_facts(
    transcript_hash_b64u: &str,
    holder_commitment_b64u: &str,
    server_commitment_b64u: &str,
    registered_public_key_b64u: &str,
    public_identity_digest_b64u: &str,
) -> Result<(), LaneHolderError> {
    let holder_bytes = decode_32(holder_commitment_b64u)?;
    let server_bytes = decode_32(server_commitment_b64u)?;
    let registered_bytes = decode_32(registered_public_key_b64u)?;
    let holder = canonical_ed_point(holder_bytes)?;
    let server = canonical_ed_point(server_bytes)?;
    let registered = canonical_ed_point(registered_bytes)?;
    if holder.is_identity() || server.is_identity() || holder + holder - server != registered {
        return Err(LaneHolderError::InvalidShare);
    }
    let digest: [u8; 32] = Sha256::new()
        .chain_update(b"seams/rotatable-signing-lanes/ed25519-public-relation/v1")
        .chain_update(decode_32(transcript_hash_b64u)?)
        .chain_update(holder_bytes)
        .chain_update(server_bytes)
        .chain_update(registered_bytes)
        .finalize()
        .into();
    require_digest_match(public_identity_digest_b64u, digest)
}

fn canonical_ed_point(
    bytes: [u8; 32],
) -> Result<curve25519_dalek::edwards::EdwardsPoint, LaneHolderError> {
    let point = CompressedEdwardsY(bytes)
        .decompress()
        .ok_or(LaneHolderError::InvalidShape)?;
    if point.is_small_order() || !point.is_torsion_free() || point.compress().to_bytes() != bytes {
        return Err(LaneHolderError::InvalidShape);
    }
    Ok(point)
}

fn verify_ecdsa_public_identity(
    job: &EcdsaAdditiveLaneJobV1,
    receipt: &LaneProtocolCommitReceiptWireV1,
) -> Result<(), LaneHolderError> {
    verify_ecdsa_public_identity_facts(
        &receipt.target_holder_public_commitment_b64u,
        &receipt.target_server_public_commitment_b64u,
        &job.threshold_public_key33_b64u,
        &job.evm_address,
        &receipt.public_identity_digest_b64u,
    )
}

fn verify_ecdsa_public_identity_facts(
    holder_commitment_b64u: &str,
    server_commitment_b64u: &str,
    threshold_public_key33_b64u: &str,
    evm_address: &str,
    public_identity_digest_b64u: &str,
) -> Result<(), LaneHolderError> {
    let holder_bytes = decode_33(holder_commitment_b64u)?;
    let server_bytes = decode_33(server_commitment_b64u)?;
    let threshold_bytes = decode_33(threshold_public_key33_b64u)?;
    let holder =
        PublicKey::from_sec1_bytes(&holder_bytes).map_err(|_| LaneHolderError::InvalidShape)?;
    let server =
        PublicKey::from_sec1_bytes(&server_bytes).map_err(|_| LaneHolderError::InvalidShape)?;
    let threshold =
        PublicKey::from_sec1_bytes(&threshold_bytes).map_err(|_| LaneHolderError::InvalidShape)?;
    let joined =
        ProjectivePoint::from(*holder.as_affine()) + ProjectivePoint::from(*server.as_affine());
    if joined != ProjectivePoint::from(*threshold.as_affine()) {
        return Err(LaneHolderError::InvalidShare);
    }
    let address = decode_evm_address20(evm_address)?;
    let digest = ecdsa_lane_public_identity_relation_digest_v1(
        &holder_bytes,
        &server_bytes,
        &threshold_bytes,
        &address,
    )
    .map_err(|_| LaneHolderError::InvalidShape)?;
    require_digest_match(public_identity_digest_b64u, digest)
}

fn verify_recipient_digests(
    holder_actual: &str,
    server_actual: &str,
    holder_expected: &str,
    server_expected: &str,
) -> Result<(), LaneHolderError> {
    let holder_matches = decode_32(holder_actual)?.ct_eq(&decode_32(holder_expected)?);
    let server_matches = decode_32(server_actual)?.ct_eq(&decode_32(server_expected)?);
    if bool::from(holder_matches & server_matches) {
        Ok(())
    } else {
        Err(LaneHolderError::BindingMismatch)
    }
}

fn decode_evm_address20(value: &str) -> Result<[u8; 20], LaneHolderError> {
    let encoded = value
        .strip_prefix("0x")
        .ok_or(LaneHolderError::InvalidShape)?;
    if encoded.len() != 40 {
        return Err(LaneHolderError::InvalidShape);
    }
    hex::decode(encoded)
        .map_err(|_| LaneHolderError::InvalidShape)?
        .try_into()
        .map_err(|_| LaneHolderError::InvalidShape)
}

fn parse_ed_package(value: &str) -> Result<Ed25519YaoEncryptedPackageV1, LaneHolderError> {
    serde_json::from_str(value).map_err(|_| LaneHolderError::InvalidShape)
}

fn parse_ecdsa_payload(value: &str) -> Result<EcdsaLaneEncryptedPayloadV1, LaneHolderError> {
    serde_json::from_str(value).map_err(|_| LaneHolderError::InvalidShape)
}

fn validate_ed_package_metadata(
    job: &Ed25519YaoLaneJobV1,
    receipt: &LaneProtocolCommitReceiptWireV1,
    package_a: &Ed25519YaoEncryptedPackageV1,
    package_b: &Ed25519YaoEncryptedPackageV1,
) -> Result<(), LaneHolderError> {
    let session = job
        .session_v1()
        .map_err(|_| LaneHolderError::InvalidShape)?;
    let transcript = decode_32(&receipt.transcript_hash_b64u)?;
    let valid = package_a.kind() == Ed25519YaoPackageKindV1::LaneHolder
        && package_b.kind() == Ed25519YaoPackageKindV1::LaneHolder
        && package_a.deriver() == Ed25519YaoDeriverRoleV1::DeriverA
        && package_b.deriver() == Ed25519YaoDeriverRoleV1::DeriverB
        && package_a.session() == session
        && package_b.session() == session
        && package_a.transcript() == transcript
        && package_b.transcript() == transcript;
    if valid {
        Ok(())
    } else {
        Err(LaneHolderError::BindingMismatch)
    }
}

fn validate_ecdsa_package_metadata(
    job: &EcdsaAdditiveLaneJobV1,
    receipt: &LaneProtocolCommitReceiptWireV1,
    package: &EcdsaLaneEncryptedPayloadV1,
) -> Result<(), LaneHolderError> {
    package
        .canonical_bytes()
        .map_err(|_| LaneHolderError::InvalidShape)?;
    let valid = package.recipient_public_key_b64u == job.target_holder.hpke_public_key_b64u
        && package.aad_digest_b64u
            == b64(job
                .preamble_hash()
                .map_err(|_| LaneHolderError::InvalidShape)?)
        && receipt.holder_recipient_key_digest_b64u
            == job.target_holder.hpke_public_key_digest_b64u;
    if valid {
        Ok(())
    } else {
        Err(LaneHolderError::BindingMismatch)
    }
}

fn ed_holder_ciphertext_digest(
    package_a: &Ed25519YaoEncryptedPackageV1,
    package_b: &Ed25519YaoEncryptedPackageV1,
) -> [u8; 32] {
    Sha256::new()
        .chain_update(b"seams/rotatable-signing-lanes/ed25519-ciphertext-set/v1")
        .chain_update(b"holder")
        .chain_update([package_a.deriver().wire_tag()])
        .chain_update([package_a.kind().wire_tag()])
        .chain_update(package_a.encapsulated_key())
        .chain_update(package_a.ciphertext())
        .chain_update([package_b.deriver().wire_tag()])
        .chain_update([package_b.kind().wire_tag()])
        .chain_update(package_b.encapsulated_key())
        .chain_update(package_b.ciphertext())
        .finalize()
        .into()
}

fn require_digest_match(value: &str, expected: [u8; 32]) -> Result<(), LaneHolderError> {
    if bool::from(decode_32(value)?.ct_eq(&expected)) {
        Ok(())
    } else {
        Err(LaneHolderError::BindingMismatch)
    }
}

fn require_same_digest(left: &str, right: &str) -> Result<(), LaneHolderError> {
    if bool::from(decode_32(left)?.ct_eq(&decode_32(right)?)) {
        Ok(())
    } else {
        Err(LaneHolderError::BindingMismatch)
    }
}

fn decode_b64u(value: &str) -> Result<Vec<u8>, LaneHolderError> {
    Base64UrlUnpadded::decode_vec(value).map_err(|_| LaneHolderError::InvalidShape)
}

fn decode_32(value: &str) -> Result<[u8; 32], LaneHolderError> {
    Base64UrlUnpadded::decode_vec(value)
        .map_err(|_| LaneHolderError::InvalidShape)?
        .try_into()
        .map_err(|_| LaneHolderError::InvalidShape)
}

fn decode_33(value: &str) -> Result<[u8; 33], LaneHolderError> {
    Base64UrlUnpadded::decode_vec(value)
        .map_err(|_| LaneHolderError::InvalidShape)?
        .try_into()
        .map_err(|_| LaneHolderError::InvalidShape)
}

fn b64<const N: usize>(value: [u8; N]) -> String {
    Base64UrlUnpadded::encode_string(&value)
}

fn ecdsa_target_lane_id(job: &EcdsaAdditiveLaneJobV1) -> &str {
    match &job.target {
        EcdsaLaneTargetOperationV1::CreateLane { lane_id, .. }
        | EcdsaLaneTargetOperationV1::RefreshLane { lane_id, .. } => lane_id,
    }
}

fn ecdsa_target_lane_share_epoch(job: &EcdsaAdditiveLaneJobV1) -> &str {
    match &job.target {
        EcdsaLaneTargetOperationV1::CreateLane {
            lane_share_epoch, ..
        }
        | EcdsaLaneTargetOperationV1::RefreshLane {
            lane_share_epoch, ..
        } => lane_share_epoch,
    }
}

fn map_activation_error(_: ClientActivationError) -> LaneHolderError {
    LaneHolderError::HpkeFailed
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, scalar::Scalar};
    use k256::{
        elliptic_curve::sec1::ToEncodedPoint, ProjectivePoint, Scalar as K256Scalar, SecretKey,
    };
    use sha2::{Digest, Sha256};
    use zeroize::Zeroizing;

    use super::{
        b64, combine_ecdsa_export_shares, ethereum_address_from_public_key33,
        open_sealed_holder_secret, verify_ecdsa_public_identity_facts,
        verify_ed_public_identity_facts, verify_recipient_digests, EcdsaLaneExportPublicFactsV1,
        LaneCustodySealV1, LaneHolderSigningMaterialV1,
    };
    use signer_core::passkey_custody::{
        PasskeyCustodyEnvelopeBindingV1, PasskeyCustodyEnvelopeOwnershipV1,
        PasskeyCustodySecretBindingV1, WalletCustodyEnvelopeFactorV1,
    };

    #[test]
    fn custody_seal_rejects_unsupported_factor_before_retaining_secret() {
        let binding = PasskeyCustodyEnvelopeBindingV1 {
            wallet_id: "wallet-1".to_owned(),
            envelope_id: "custody-1".to_owned(),
            factor: WalletCustodyEnvelopeFactorV1::Passkey {
                rp_id: "example.test".to_owned(),
                credential_id_b64u: "credential".to_owned(),
                kek_version: "passkey_prf_kek_hkdf_sha256_v1".to_owned(),
            },
            envelope_revision: 1,
            binding: PasskeyCustodySecretBindingV1::WalletCustodySeed {
                derivation_scheme: "wallet_seed_parallel_hkdf_sha256_v1".to_owned(),
            },
            ownership: PasskeyCustodyEnvelopeOwnershipV1::MethodBound {
                wallet_auth_method_id: "wallet-auth-method-1".to_owned(),
            },
        };
        assert!(LaneCustodySealV1::from_factor(
            "future_factor",
            [7_u8; 32],
            binding,
            "custody-1".to_owned(),
            b64([1_u8; 32]),
        )
        .is_err());
    }

    #[test]
    fn sealed_holder_secret_reopens_only_with_exact_record_digest_and_factor() {
        let factor_secret = [7_u8; 32];
        let custody_binding_id = "custody-1".to_owned();
        let custody_binding_digest_b64u = b64([8_u8; 32]);
        let binding = PasskeyCustodyEnvelopeBindingV1 {
            wallet_id: "wallet-1".to_owned(),
            envelope_id: custody_binding_id.clone(),
            factor: WalletCustodyEnvelopeFactorV1::Passkey {
                rp_id: "example.test".to_owned(),
                credential_id_b64u: "credential".to_owned(),
                kek_version: "passkey_prf_kek_hkdf_sha256_v1".to_owned(),
            },
            envelope_revision: 1,
            binding: PasskeyCustodySecretBindingV1::Ed25519LaneHolderShare {
                lane: signer_core::passkey_custody::PasskeyCustodyLaneScopeV1 {
                    wallet_key_id: "wallet-key-1".to_owned(),
                    lane_id: "lane-1".to_owned(),
                    lane_share_epoch: "lane-share-epoch-1".to_owned(),
                },
                near_ed25519_signing_key_id: "near-key-1".to_owned(),
                registered_public_key_b64u: b64([9_u8; 32]),
                participant_binding_digest_b64u: b64([10_u8; 32]),
            },
            ownership: PasskeyCustodyEnvelopeOwnershipV1::MethodBound {
                wallet_auth_method_id: "wallet-auth-method-1".to_owned(),
            },
        };
        let custody = LaneCustodySealV1::from_factor(
            "passkey",
            factor_secret,
            binding,
            custody_binding_id,
            custody_binding_digest_b64u,
        )
        .expect("valid lane custody");
        let share = Scalar::from(5_u64).to_bytes();
        let sealed = custody
            .seal(&share, &[11_u8; 12], [12_u8; 32])
            .expect("sealed holder share");

        let (_, opened) = open_sealed_holder_secret(
            &factor_secret,
            &sealed.sealed_holder_material_b64u,
            &sealed.sealed_holder_record_digest_b64u,
        )
        .expect("exact holder record reopens");
        assert_eq!(*opened, share);
        assert!(open_sealed_holder_secret(
            &[13_u8; 32],
            &sealed.sealed_holder_material_b64u,
            &sealed.sealed_holder_record_digest_b64u,
        )
        .is_err());
        assert!(open_sealed_holder_secret(
            &factor_secret,
            &sealed.sealed_holder_material_b64u,
            &b64([14_u8; 32]),
        )
        .is_err());
    }

    #[test]
    fn ed_relation_rejects_server_commitment_and_digest_tampering() {
        let transcript = [9_u8; 32];
        let holder = (ED25519_BASEPOINT_POINT * Scalar::from(5_u64))
            .compress()
            .to_bytes();
        let server = (ED25519_BASEPOINT_POINT * Scalar::from(3_u64))
            .compress()
            .to_bytes();
        let registered = (ED25519_BASEPOINT_POINT * Scalar::from(7_u64))
            .compress()
            .to_bytes();
        let digest: [u8; 32] = Sha256::new()
            .chain_update(b"seams/rotatable-signing-lanes/ed25519-public-relation/v1")
            .chain_update(transcript)
            .chain_update(holder)
            .chain_update(server)
            .chain_update(registered)
            .finalize()
            .into();
        verify_ed_public_identity_facts(
            &b64(transcript),
            &b64(holder),
            &b64(server),
            &b64(registered),
            &b64(digest),
        )
        .expect("valid Ed lane public relation");

        let tampered_server = (ED25519_BASEPOINT_POINT * Scalar::from(4_u64))
            .compress()
            .to_bytes();
        assert!(verify_ed_public_identity_facts(
            &b64(transcript),
            &b64(holder),
            &b64(tampered_server),
            &b64(registered),
            &b64(digest),
        )
        .is_err());
        assert!(verify_ed_public_identity_facts(
            &b64(transcript),
            &b64(holder),
            &b64(server),
            &b64(registered),
            &b64([1_u8; 32]),
        )
        .is_err());
    }

    #[test]
    fn ecdsa_relation_rejects_server_commitment_and_digest_tampering() {
        let holder = (ProjectivePoint::GENERATOR * K256Scalar::from(2_u64))
            .to_affine()
            .to_encoded_point(true);
        let server = (ProjectivePoint::GENERATOR * K256Scalar::from(3_u64))
            .to_affine()
            .to_encoded_point(true);
        let threshold = (ProjectivePoint::GENERATOR * K256Scalar::from(5_u64))
            .to_affine()
            .to_encoded_point(true);
        let holder: [u8; 33] = holder.as_bytes().try_into().expect("holder key");
        let server: [u8; 33] = server.as_bytes().try_into().expect("server key");
        let threshold: [u8; 33] = threshold.as_bytes().try_into().expect("threshold key");
        let address = [7_u8; 20];
        let digest =
            router_ab_ecdsa_client_protocol::ecdsa_lane_public_identity_relation_digest_v1(
                &holder, &server, &threshold, &address,
            )
            .expect("relation digest");
        let address_hex = format!("0x{}", hex::encode(address));
        verify_ecdsa_public_identity_facts(
            &b64(holder),
            &b64(server),
            &b64(threshold),
            &address_hex,
            &b64(digest),
        )
        .expect("valid ECDSA lane public relation");

        let tampered_server = (ProjectivePoint::GENERATOR * K256Scalar::from(4_u64))
            .to_affine()
            .to_encoded_point(true);
        let tampered_server: [u8; 33] = tampered_server
            .as_bytes()
            .try_into()
            .expect("tampered server key");
        assert!(verify_ecdsa_public_identity_facts(
            &b64(holder),
            &b64(tampered_server),
            &b64(threshold),
            &address_hex,
            &b64(digest),
        )
        .is_err());
        assert!(verify_ecdsa_public_identity_facts(
            &b64(holder),
            &b64(server),
            &b64(threshold),
            &address_hex,
            &b64([2_u8; 32]),
        )
        .is_err());
    }

    #[test]
    fn ecdsa_export_combines_and_verifies_exact_lane_shares() {
        let holder_scalar = K256Scalar::from(2_u64);
        let server_scalar = K256Scalar::from(3_u64);
        let holder_share: [u8; 32] = holder_scalar.to_bytes().into();
        let server_share: [u8; 32] = server_scalar.to_bytes().into();
        let holder_secret = SecretKey::from_slice(&holder_share).expect("holder scalar");
        let server_secret = SecretKey::from_slice(&server_share).expect("server scalar");
        let holder_public: [u8; 33] = holder_secret
            .public_key()
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .expect("holder public key");
        let server_public: [u8; 33] = server_secret
            .public_key()
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .expect("server public key");
        let threshold_public: [u8; 33] = (ProjectivePoint::GENERATOR * K256Scalar::from(5_u64))
            .to_affine()
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .expect("threshold public key");
        let ethereum_address20 = ethereum_address_from_public_key33(&threshold_public)
            .expect("threshold Ethereum address");
        let public_identity_digest =
            router_ab_ecdsa_client_protocol::ecdsa_lane_public_identity_relation_digest_v1(
                &holder_public,
                &server_public,
                &threshold_public,
                &ethereum_address20,
            )
            .expect("public identity digest");
        let facts = EcdsaLaneExportPublicFactsV1 {
            wallet_id: "wallet-1".to_owned(),
            wallet_key_id: "wallet-key-1".to_owned(),
            enrollment_id: "enrollment-1".to_owned(),
            operation_id: "operation-1".to_owned(),
            lane_id: "lane-1".to_owned(),
            lane_share_epoch: "epoch-1".to_owned(),
            target_material_activation_id: "activation-1".to_owned(),
            ecdsa_threshold_key_id: "threshold-1".to_owned(),
            threshold_public_key33_b64u: b64(threshold_public),
            evm_address: format!("0x{}", hex::encode(ethereum_address20)),
            target_holder_public_commitment33_b64u: b64(holder_public),
            target_server_public_commitment33_b64u: b64(server_public),
            public_identity_digest_b64u: b64(public_identity_digest),
        };
        let holder_material = LaneHolderSigningMaterialV1::Ecdsa {
            share: Zeroizing::new(holder_share),
            export_facts: facts.clone(),
        };

        let artifact = combine_ecdsa_export_shares(&holder_material, &server_share, &facts)
            .expect("exact ECDSA shares combine");
        let expected_private_key: [u8; 32] = K256Scalar::from(5_u64).to_bytes().into();
        assert_eq!(artifact.private_key32, expected_private_key);
        assert_eq!(artifact.public_key33, threshold_public);
        assert_eq!(artifact.ethereum_address20, ethereum_address20);

        let mut tampered_facts = facts;
        tampered_facts.evm_address = format!("0x{}", "00".repeat(20));
        assert!(
            combine_ecdsa_export_shares(&holder_material, &server_share, &tampered_facts,).is_err()
        );
    }

    #[test]
    fn recipient_digest_check_rejects_server_key_substitution() {
        let holder = b64([3_u8; 32]);
        let server = b64([4_u8; 32]);
        verify_recipient_digests(&holder, &server, &holder, &server)
            .expect("exact recipient digests");
        assert!(verify_recipient_digests(&holder, &b64([5_u8; 32]), &holder, &server).is_err());
    }
}
