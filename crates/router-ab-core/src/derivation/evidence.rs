use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::derivation::context::{
    context_digest_v1, CorrectnessLevel, DerivationContext, RootShareEpoch,
};
use crate::derivation::envelope::{package_commitment_v1, ContentKind, DeliveryPackageV1};
use crate::derivation::error::{
    RouterAbDerivationError, RouterAbDerivationErrorCode, RouterAbDerivationResult,
};
use crate::derivation::material::{PublicDigest32, Role};
use crate::derivation::transcript::{transcript_digest_v1, TranscriptBinding};

const SIGNER_RECEIPT_VERSION: &[u8] = b"router-ab-derivation/signer-receipt/v1";

/// Minimum Level C evidence version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MinimumLevelCEvidenceVersion {
    /// Initial evidence version.
    V1,
}

/// Signer receipt version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignerReceiptVersion {
    /// Initial signer receipt version.
    V1,
}

impl SignerReceiptVersion {
    fn as_str(self) -> &'static str {
        match self {
            Self::V1 => "v1",
        }
    }
}

/// Authenticated signer receipt. Construction means the adapter already
/// verified envelope authentication or a role signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticatedSignerReceiptV1 {
    /// Receipt version.
    pub receipt_version: SignerReceiptVersion,
    /// Signer role.
    pub signer_role: Role,
    /// Signer identity.
    pub signer_identity: String,
    /// Transcript digest accepted by the signer.
    pub accepted_transcript_digest: PublicDigest32,
    /// Root-share epoch accepted by the signer.
    pub accepted_root_share_epoch: RootShareEpoch,
    /// Output package commitments created by this signer.
    pub output_package_commitments: Vec<PublicDigest32>,
}

impl AuthenticatedSignerReceiptV1 {
    /// Validates public receipt metadata.
    pub fn validate(&self) -> RouterAbDerivationResult<()> {
        match self.signer_role {
            Role::SignerA | Role::SignerB => {}
            _ => {
                return Err(RouterAbDerivationError::new(
                    RouterAbDerivationErrorCode::SignerReceiptMismatch,
                    "signer receipt role must be Signer A or Signer B",
                ));
            }
        }

        require_non_empty("signer_identity", &self.signer_identity)?;
        require_non_empty(
            "accepted_root_share_epoch",
            self.accepted_root_share_epoch.as_str(),
        )?;
        Ok(())
    }
}

/// Replay-cache acceptance for one transcript.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceptedReplayCacheDecisionV1 {
    /// Replay cache key.
    pub replay_cache_key: PublicDigest32,
    /// Transcript digest accepted for this key.
    pub accepted_transcript_digest: PublicDigest32,
}

/// Public Minimum Level C evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MinimumLevelCEvidenceV1 {
    /// Evidence version.
    pub evidence_version: MinimumLevelCEvidenceVersion,
    /// Correctness level.
    pub correctness_level: CorrectnessLevel,
    /// Context digest.
    pub context_digest: PublicDigest32,
    /// Transcript digest.
    pub transcript_digest: PublicDigest32,
    /// Signer A receipt digest.
    pub signer_a_receipt_digest: PublicDigest32,
    /// Signer B receipt digest.
    pub signer_b_receipt_digest: PublicDigest32,
    /// Client package commitments.
    pub client_package_commitments: Vec<PublicDigest32>,
    /// Relayer package commitments.
    pub relayer_package_commitments: Vec<PublicDigest32>,
    /// Replay cache key.
    pub replay_cache_key: PublicDigest32,
}

/// Verified Minimum Level C evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedMinimumLevelCEvidenceV1 {
    /// Verified public evidence.
    pub evidence: MinimumLevelCEvidenceV1,
}

/// Input to the Minimum Level C verifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MinimumLevelCVerificationInputV1 {
    /// Expected derivation context.
    pub context: DerivationContext,
    /// Expected transcript binding.
    pub transcript: TranscriptBinding,
    /// Authenticated Signer A receipt.
    pub signer_a_receipt: AuthenticatedSignerReceiptV1,
    /// Authenticated Signer B receipt.
    pub signer_b_receipt: AuthenticatedSignerReceiptV1,
    /// Client delivery packages.
    pub client_packages: Vec<DeliveryPackageV1>,
    /// Relayer delivery packages.
    pub relayer_packages: Vec<DeliveryPackageV1>,
    /// Accepted replay-cache decision.
    pub replay_cache_decision: AcceptedReplayCacheDecisionV1,
}

/// Verifies Minimum Level C transcript, package, recipient, and replay binding.
pub fn verify_minimum_level_c_v1(
    input: MinimumLevelCVerificationInputV1,
) -> RouterAbDerivationResult<VerifiedMinimumLevelCEvidenceV1> {
    input.context.validate()?;
    input.transcript.validate()?;

    if input.context != input.transcript.context {
        return Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::TranscriptMismatch,
            "transcript context does not match verifier context",
        ));
    }

    if input.context.correctness_level != CorrectnessLevel::MinimumLevelC {
        return Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::CorrectnessLevelMismatch,
            "Minimum Level C verifier requires minimum_level_c context",
        ));
    }

    let context_digest = context_digest_v1(&input.context)?;
    let transcript_digest = transcript_digest_v1(&input.transcript)?;

    verify_replay_decision(&input.replay_cache_decision, transcript_digest)?;
    verify_signer_receipt(
        &input.signer_a_receipt,
        Role::SignerA,
        &input.transcript,
        transcript_digest,
        &input.context.root_share_epoch,
    )?;
    verify_signer_receipt(
        &input.signer_b_receipt,
        Role::SignerB,
        &input.transcript,
        transcript_digest,
        &input.context.root_share_epoch,
    )?;

    let client_package_commitments = verify_packages(
        &input.client_packages,
        Role::Client,
        &input.transcript.client_id,
        ContentKind::ClientOutputShare,
        &input.context,
        transcript_digest,
    )?;
    let relayer_package_commitments = verify_packages(
        &input.relayer_packages,
        Role::Relayer,
        &input.transcript.selected_relayer_id,
        ContentKind::RelayerOutputShare,
        &input.context,
        transcript_digest,
    )?;

    verify_receipt_commitments(
        &input.signer_a_receipt,
        Role::SignerA,
        &input.client_packages,
        &input.relayer_packages,
    )?;
    verify_receipt_commitments(
        &input.signer_b_receipt,
        Role::SignerB,
        &input.client_packages,
        &input.relayer_packages,
    )?;

    let evidence = MinimumLevelCEvidenceV1 {
        evidence_version: MinimumLevelCEvidenceVersion::V1,
        correctness_level: CorrectnessLevel::MinimumLevelC,
        context_digest,
        transcript_digest,
        signer_a_receipt_digest: signer_receipt_digest_v1(&input.signer_a_receipt)?,
        signer_b_receipt_digest: signer_receipt_digest_v1(&input.signer_b_receipt)?,
        client_package_commitments,
        relayer_package_commitments,
        replay_cache_key: input.replay_cache_decision.replay_cache_key,
    };

    Ok(VerifiedMinimumLevelCEvidenceV1 { evidence })
}

/// Computes the public signer receipt digest.
pub fn signer_receipt_digest_v1(
    receipt: &AuthenticatedSignerReceiptV1,
) -> RouterAbDerivationResult<PublicDigest32> {
    receipt.validate()?;

    let mut hasher = Sha256::new();
    push_hash_field(&mut hasher, SIGNER_RECEIPT_VERSION);
    push_hash_field(&mut hasher, receipt.receipt_version.as_str().as_bytes());
    push_hash_field(&mut hasher, receipt.signer_role.as_str().as_bytes());
    push_hash_field(&mut hasher, receipt.signer_identity.as_bytes());
    push_hash_field(&mut hasher, receipt.accepted_transcript_digest.as_bytes());
    push_hash_field(
        &mut hasher,
        receipt.accepted_root_share_epoch.as_str().as_bytes(),
    );
    push_hash_field(
        &mut hasher,
        receipt
            .output_package_commitments
            .len()
            .to_string()
            .as_bytes(),
    );
    for commitment in &receipt.output_package_commitments {
        push_hash_field(&mut hasher, commitment.as_bytes());
    }
    Ok(PublicDigest32::new(hasher.finalize().into()))
}

fn verify_replay_decision(
    decision: &AcceptedReplayCacheDecisionV1,
    transcript_digest: PublicDigest32,
) -> RouterAbDerivationResult<()> {
    if decision.accepted_transcript_digest != transcript_digest {
        return Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::ReplayMismatch,
            "replay cache accepted a different transcript digest",
        ));
    }
    Ok(())
}

fn verify_signer_receipt(
    receipt: &AuthenticatedSignerReceiptV1,
    expected_role: Role,
    transcript: &TranscriptBinding,
    transcript_digest: PublicDigest32,
    root_share_epoch: &RootShareEpoch,
) -> RouterAbDerivationResult<()> {
    receipt.validate()?;

    if receipt.signer_role != expected_role {
        return Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::SignerReceiptMismatch,
            "signer receipt role mismatch",
        ));
    }

    let expected_signer = transcript
        .signer_set
        .signer_for_role(expected_role)
        .ok_or_else(|| {
            RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::SignerReceiptMismatch,
                "missing signer in transcript signer set",
            )
        })?;

    if receipt.signer_identity != expected_signer.signer_id {
        return Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::SignerIdentityMismatch,
            "signer receipt identity mismatch",
        ));
    }

    if receipt.accepted_transcript_digest != transcript_digest {
        return Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::SignerReceiptMismatch,
            "signer receipt transcript digest mismatch",
        ));
    }

    if &receipt.accepted_root_share_epoch != root_share_epoch {
        return Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::RootEpochMismatch,
            "signer receipt root-share epoch mismatch",
        ));
    }

    Ok(())
}

fn verify_packages(
    packages: &[DeliveryPackageV1],
    expected_recipient_role: Role,
    expected_recipient_identity: &str,
    expected_content_kind: ContentKind,
    context: &DerivationContext,
    transcript_digest: PublicDigest32,
) -> RouterAbDerivationResult<Vec<PublicDigest32>> {
    let mut commitments = Vec::with_capacity(packages.len());

    for package in packages {
        package.validate()?;
        let header = &package.header;

        if header.candidate_id != context.candidate_id
            || header.request_kind != context.request_kind
            || header.correctness_level != context.correctness_level
            || header.ceremony_id != context.ceremony_id
            || header.root_share_epoch != context.root_share_epoch
        {
            return Err(RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::TranscriptMismatch,
                "package header does not match context",
            ));
        }

        if header.transcript_digest != transcript_digest {
            return Err(RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::TranscriptMismatch,
                "package header transcript digest mismatch",
            ));
        }

        if header.recipient_role != expected_recipient_role
            || header.recipient_identity != expected_recipient_identity
        {
            return Err(RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::RecipientMismatch,
                "package recipient mismatch",
            ));
        }

        if header.content_kind != expected_content_kind {
            return Err(RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::RecipientMismatch,
                "package content kind does not match recipient output kind",
            ));
        }

        commitments.push(package_commitment_v1(package)?);
    }

    Ok(commitments)
}

fn verify_receipt_commitments(
    receipt: &AuthenticatedSignerReceiptV1,
    signer_role: Role,
    client_packages: &[DeliveryPackageV1],
    relayer_packages: &[DeliveryPackageV1],
) -> RouterAbDerivationResult<()> {
    let mut expected = Vec::new();
    collect_commitments_for_signer(&mut expected, signer_role, client_packages)?;
    collect_commitments_for_signer(&mut expected, signer_role, relayer_packages)?;

    if receipt.output_package_commitments != expected {
        return Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::PackageCommitmentMismatch,
            "signer receipt output commitments do not match delivered packages",
        ));
    }

    Ok(())
}

fn collect_commitments_for_signer(
    out: &mut Vec<PublicDigest32>,
    signer_role: Role,
    packages: &[DeliveryPackageV1],
) -> RouterAbDerivationResult<()> {
    for package in packages {
        if package.header.sender_role == signer_role {
            out.push(package_commitment_v1(package)?);
        }
    }
    Ok(())
}

fn push_hash_field(hasher: &mut Sha256, value: &[u8]) {
    let len = value.len() as u32;
    hasher.update(len.to_be_bytes());
    hasher.update(value);
}

fn require_non_empty(field: &'static str, value: &str) -> RouterAbDerivationResult<()> {
    if value.is_empty() {
        return Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::EmptyField,
            format!("{field} is required"),
        ));
    }
    Ok(())
}
