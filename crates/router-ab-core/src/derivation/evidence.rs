use serde::{de::Error as DeError, Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};

use crate::derivation::context::{
    context_digest_v1, CorrectnessLevel, DerivationContext, RootShareEpoch,
};
use crate::derivation::envelope::{
    package_commitment_v1, ContentKind, DeliveryPackageV1, EnvelopeKind,
};
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuthenticatedSignerReceiptV1 {
    /// Receipt version.
    receipt_version: SignerReceiptVersion,
    /// Signer role.
    signer_role: Role,
    /// Signer identity.
    signer_identity: String,
    /// Transcript digest accepted by the signer.
    accepted_transcript_digest: PublicDigest32,
    /// Root-share epoch accepted by the signer.
    accepted_root_share_epoch: RootShareEpoch,
    /// Output package commitments created by this signer.
    output_package_commitments: Vec<PublicDigest32>,
}

impl AuthenticatedSignerReceiptV1 {
    /// Creates a signer receipt after validating the public shape.
    pub fn new(
        receipt_version: SignerReceiptVersion,
        signer_role: Role,
        signer_identity: impl Into<String>,
        accepted_transcript_digest: PublicDigest32,
        accepted_root_share_epoch: RootShareEpoch,
        output_package_commitments: Vec<PublicDigest32>,
    ) -> RouterAbDerivationResult<Self> {
        let receipt = Self {
            receipt_version,
            signer_role,
            signer_identity: signer_identity.into(),
            accepted_transcript_digest,
            accepted_root_share_epoch,
            output_package_commitments,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    /// Receipt version.
    pub fn receipt_version(&self) -> SignerReceiptVersion {
        self.receipt_version
    }

    /// Signer role.
    pub fn signer_role(&self) -> Role {
        self.signer_role
    }

    /// Signer identity.
    pub fn signer_identity(&self) -> &str {
        &self.signer_identity
    }

    /// Accepted transcript digest.
    pub fn accepted_transcript_digest(&self) -> PublicDigest32 {
        self.accepted_transcript_digest
    }

    /// Accepted root-share epoch.
    pub fn accepted_root_share_epoch(&self) -> &RootShareEpoch {
        &self.accepted_root_share_epoch
    }

    /// Output package commitments.
    pub fn output_package_commitments(&self) -> &[PublicDigest32] {
        &self.output_package_commitments
    }

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
        if self.output_package_commitments.len() != 2 {
            return Err(RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::MalformedInput,
                "signer receipt requires exactly two output package commitments",
            ));
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for AuthenticatedSignerReceiptV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            receipt_version: SignerReceiptVersion,
            signer_role: Role,
            signer_identity: String,
            accepted_transcript_digest: PublicDigest32,
            accepted_root_share_epoch: RootShareEpoch,
            output_package_commitments: Vec<PublicDigest32>,
        }

        let wire = Wire::deserialize(deserializer)?;
        Self::new(
            wire.receipt_version,
            wire.signer_role,
            wire.signer_identity,
            wire.accepted_transcript_digest,
            wire.accepted_root_share_epoch,
            wire.output_package_commitments,
        )
        .map_err(D::Error::custom)
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MinimumLevelCEvidenceV1 {
    /// Evidence version.
    evidence_version: MinimumLevelCEvidenceVersion,
    /// Correctness level.
    correctness_level: CorrectnessLevel,
    /// Context digest.
    context_digest: PublicDigest32,
    /// Transcript digest.
    transcript_digest: PublicDigest32,
    /// Signer A receipt digest.
    signer_a_receipt_digest: PublicDigest32,
    /// Signer B receipt digest.
    signer_b_receipt_digest: PublicDigest32,
    /// Client package commitments.
    client_package_commitments: Vec<PublicDigest32>,
    /// Relayer package commitments.
    relayer_package_commitments: Vec<PublicDigest32>,
    /// Replay cache key.
    replay_cache_key: PublicDigest32,
}

impl MinimumLevelCEvidenceV1 {
    /// Creates public Minimum Level C evidence after validating its shape.
    pub fn new(
        evidence_version: MinimumLevelCEvidenceVersion,
        correctness_level: CorrectnessLevel,
        context_digest: PublicDigest32,
        transcript_digest: PublicDigest32,
        signer_a_receipt_digest: PublicDigest32,
        signer_b_receipt_digest: PublicDigest32,
        client_package_commitments: Vec<PublicDigest32>,
        relayer_package_commitments: Vec<PublicDigest32>,
        replay_cache_key: PublicDigest32,
    ) -> RouterAbDerivationResult<Self> {
        let evidence = Self {
            evidence_version,
            correctness_level,
            context_digest,
            transcript_digest,
            signer_a_receipt_digest,
            signer_b_receipt_digest,
            client_package_commitments,
            relayer_package_commitments,
            replay_cache_key,
        };
        evidence.validate()?;
        Ok(evidence)
    }

    /// Evidence version.
    pub fn evidence_version(&self) -> MinimumLevelCEvidenceVersion {
        self.evidence_version
    }

    /// Correctness level.
    pub fn correctness_level(&self) -> CorrectnessLevel {
        self.correctness_level
    }

    /// Context digest.
    pub fn context_digest(&self) -> PublicDigest32 {
        self.context_digest
    }

    /// Transcript digest.
    pub fn transcript_digest(&self) -> PublicDigest32 {
        self.transcript_digest
    }

    /// Signer A receipt digest.
    pub fn signer_a_receipt_digest(&self) -> PublicDigest32 {
        self.signer_a_receipt_digest
    }

    /// Signer B receipt digest.
    pub fn signer_b_receipt_digest(&self) -> PublicDigest32 {
        self.signer_b_receipt_digest
    }

    /// Client package commitments.
    pub fn client_package_commitments(&self) -> &[PublicDigest32] {
        &self.client_package_commitments
    }

    /// Relayer package commitments.
    pub fn relayer_package_commitments(&self) -> &[PublicDigest32] {
        &self.relayer_package_commitments
    }

    /// Replay cache key.
    pub fn replay_cache_key(&self) -> PublicDigest32 {
        self.replay_cache_key
    }

    /// Validates public evidence shape before it is accepted from typed serde.
    pub fn validate(&self) -> RouterAbDerivationResult<()> {
        if self.correctness_level != CorrectnessLevel::MinimumLevelC {
            return Err(RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::CorrectnessLevelMismatch,
                "Minimum Level C evidence requires minimum_level_c correctness",
            ));
        }

        if self.client_package_commitments.len() != 2 {
            return Err(RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::MalformedInput,
                "Minimum Level C evidence requires exactly two client package commitments",
            ));
        }

        if self.relayer_package_commitments.len() != 2 {
            return Err(RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::MalformedInput,
                "Minimum Level C evidence requires exactly two relayer package commitments",
            ));
        }

        Ok(())
    }
}

impl<'de> Deserialize<'de> for MinimumLevelCEvidenceV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            evidence_version: MinimumLevelCEvidenceVersion,
            correctness_level: CorrectnessLevel,
            context_digest: PublicDigest32,
            transcript_digest: PublicDigest32,
            signer_a_receipt_digest: PublicDigest32,
            signer_b_receipt_digest: PublicDigest32,
            client_package_commitments: Vec<PublicDigest32>,
            relayer_package_commitments: Vec<PublicDigest32>,
            replay_cache_key: PublicDigest32,
        }

        let wire = Wire::deserialize(deserializer)?;
        Self::new(
            wire.evidence_version,
            wire.correctness_level,
            wire.context_digest,
            wire.transcript_digest,
            wire.signer_a_receipt_digest,
            wire.signer_b_receipt_digest,
            wire.client_package_commitments,
            wire.relayer_package_commitments,
            wire.replay_cache_key,
        )
        .map_err(D::Error::custom)
    }
}

/// Verified Minimum Level C evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VerifiedMinimumLevelCEvidenceV1 {
    /// Verified public evidence.
    evidence: MinimumLevelCEvidenceV1,
}

impl VerifiedMinimumLevelCEvidenceV1 {
    /// Creates verified evidence after checking the public evidence shape.
    pub fn new(evidence: MinimumLevelCEvidenceV1) -> RouterAbDerivationResult<Self> {
        evidence.validate()?;
        Ok(Self { evidence })
    }

    /// Verified public evidence.
    pub fn evidence(&self) -> &MinimumLevelCEvidenceV1 {
        &self.evidence
    }

    /// Consumes the wrapper and returns the verified public evidence.
    pub fn into_evidence(self) -> MinimumLevelCEvidenceV1 {
        self.evidence
    }
}

/// Input to the Minimum Level C verifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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

    if &input.context != input.transcript.context() {
        return Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::TranscriptMismatch,
            "transcript context does not match verifier context",
        ));
    }

    if input.context.correctness_level() != CorrectnessLevel::MinimumLevelC {
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
        input.context.root_share_epoch(),
    )?;
    verify_signer_receipt(
        &input.signer_b_receipt,
        Role::SignerB,
        &input.transcript,
        transcript_digest,
        input.context.root_share_epoch(),
    )?;

    let client_package_commitments = verify_packages(
        &input.client_packages,
        Role::Client,
        input.transcript.client_id(),
        ContentKind::ClientOutputShare,
        &input.context,
        &input.transcript,
        transcript_digest,
    )?;
    let relayer_package_commitments = verify_packages(
        &input.relayer_packages,
        Role::Relayer,
        input.transcript.selected_relayer_id(),
        ContentKind::RelayerOutputShare,
        &input.context,
        &input.transcript,
        transcript_digest,
    )?;

    verify_receipt_commitments(
        &input.signer_a_receipt,
        client_package_commitments.signer_a,
        relayer_package_commitments.signer_a,
    )?;
    verify_receipt_commitments(
        &input.signer_b_receipt,
        client_package_commitments.signer_b,
        relayer_package_commitments.signer_b,
    )?;

    let evidence = MinimumLevelCEvidenceV1::new(
        MinimumLevelCEvidenceVersion::V1,
        CorrectnessLevel::MinimumLevelC,
        context_digest,
        transcript_digest,
        signer_receipt_digest_v1(&input.signer_a_receipt)?,
        signer_receipt_digest_v1(&input.signer_b_receipt)?,
        client_package_commitments.to_vec(),
        relayer_package_commitments.to_vec(),
        input.replay_cache_decision.replay_cache_key,
    )?;

    VerifiedMinimumLevelCEvidenceV1::new(evidence)
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
        .signer_set()
        .signer_for_role(expected_role)
        .ok_or_else(|| {
            RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::SignerReceiptMismatch,
                "missing signer in transcript signer set",
            )
        })?;

    if receipt.signer_identity != expected_signer.signer_id() {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct V1RecipientPackageCommitments {
    signer_a: PublicDigest32,
    signer_b: PublicDigest32,
}

impl V1RecipientPackageCommitments {
    fn to_vec(self) -> Vec<PublicDigest32> {
        vec![self.signer_a, self.signer_b]
    }
}

fn verify_packages(
    packages: &[DeliveryPackageV1],
    expected_recipient_role: Role,
    expected_recipient_identity: &str,
    expected_content_kind: ContentKind,
    context: &DerivationContext,
    transcript: &TranscriptBinding,
    transcript_digest: PublicDigest32,
) -> RouterAbDerivationResult<V1RecipientPackageCommitments> {
    let signer_a_identity = expected_signer_identity(transcript, Role::SignerA)?;
    let signer_b_identity = expected_signer_identity(transcript, Role::SignerB)?;
    let mut signer_a = None;
    let mut signer_b = None;

    for package in packages {
        package.validate()?;
        let header = package.header();

        if header.candidate_id() != context.candidate_id()
            || header.request_kind() != context.request_kind()
            || header.correctness_level() != context.correctness_level()
            || header.ceremony_id() != context.ceremony_id()
            || header.root_share_epoch() != context.root_share_epoch()
        {
            return Err(RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::TranscriptMismatch,
                "package header does not match context",
            ));
        }

        if header.transcript_digest() != transcript_digest {
            return Err(RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::TranscriptMismatch,
                "package header transcript digest mismatch",
            ));
        }

        if header.recipient_role() != expected_recipient_role
            || header.recipient_identity() != expected_recipient_identity
        {
            return Err(RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::RecipientMismatch,
                "package recipient mismatch",
            ));
        }

        if header.content_kind() != expected_content_kind {
            return Err(RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::RecipientMismatch,
                "package content kind does not match recipient output kind",
            ));
        }

        if header.envelope_kind()
            != expected_package_envelope_kind(header.sender_role(), expected_recipient_role)?
        {
            return Err(RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::RecipientMismatch,
                "package envelope kind does not match required sender and recipient output",
            ));
        }

        let expected_sender_identity = match header.sender_role() {
            Role::SignerA => signer_a_identity,
            Role::SignerB => signer_b_identity,
            _ => {
                return Err(RouterAbDerivationError::new(
                    RouterAbDerivationErrorCode::SignerReceiptMismatch,
                    "package sender role must be Signer A or Signer B",
                ));
            }
        };
        if header.sender_identity() != expected_sender_identity {
            return Err(RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::SignerIdentityMismatch,
                "package sender identity does not match transcript signer identity",
            ));
        }

        let commitment = package_commitment_v1(package)?;
        let slot = match header.sender_role() {
            Role::SignerA => &mut signer_a,
            Role::SignerB => &mut signer_b,
            _ => unreachable!("sender role already restricted"),
        };
        if slot.replace(commitment).is_some() {
            return Err(RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::PackageCommitmentMismatch,
                "Minimum Level C requires exactly one package per signer for each recipient output",
            ));
        }
    }

    Ok(V1RecipientPackageCommitments {
        signer_a: signer_a.ok_or_else(|| {
            RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::PackageCommitmentMismatch,
                "Minimum Level C is missing the Signer A package for a required recipient output",
            )
        })?,
        signer_b: signer_b.ok_or_else(|| {
            RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::PackageCommitmentMismatch,
                "Minimum Level C is missing the Signer B package for a required recipient output",
            )
        })?,
    })
}

fn verify_receipt_commitments(
    receipt: &AuthenticatedSignerReceiptV1,
    client_package_commitment: PublicDigest32,
    relayer_package_commitment: PublicDigest32,
) -> RouterAbDerivationResult<()> {
    let expected = vec![client_package_commitment, relayer_package_commitment];
    if receipt.output_package_commitments != expected {
        return Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::PackageCommitmentMismatch,
            "signer receipt output commitments do not match delivered packages",
        ));
    }

    Ok(())
}

fn expected_signer_identity(
    transcript: &TranscriptBinding,
    role: Role,
) -> RouterAbDerivationResult<&str> {
    transcript
        .signer_set()
        .signer_for_role(role)
        .map(|signer| signer.signer_id())
        .ok_or_else(|| {
            RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::SignerReceiptMismatch,
                "missing signer in transcript signer set",
            )
        })
}

fn expected_package_envelope_kind(
    sender_role: Role,
    recipient_role: Role,
) -> RouterAbDerivationResult<EnvelopeKind> {
    match (sender_role, recipient_role) {
        (Role::SignerA, Role::Client) => Ok(EnvelopeKind::SignerAToClient),
        (Role::SignerB, Role::Client) => Ok(EnvelopeKind::SignerBToClient),
        (Role::SignerA, Role::Relayer) => Ok(EnvelopeKind::SignerAToRelayer),
        (Role::SignerB, Role::Relayer) => Ok(EnvelopeKind::SignerBToRelayer),
        _ => Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::RecipientMismatch,
            "Minimum Level C package has unsupported sender or recipient role",
        )),
    }
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
