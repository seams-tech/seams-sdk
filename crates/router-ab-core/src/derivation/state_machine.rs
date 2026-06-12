use serde::{Deserialize, Serialize};

use crate::derivation::context::DerivationContext;
use crate::derivation::envelope::{EnvelopeHeaderV1, EnvelopeKind};
use crate::derivation::error::{
    RouterAbDerivationError, RouterAbDerivationErrorCode, RouterAbDerivationResult,
};
use crate::derivation::evidence::VerifiedMinimumLevelCEvidenceV1;
use crate::derivation::material::{PublicDigest32, Role};
use crate::derivation::transcript::{transcript_digest_v1, TranscriptBinding};

/// Input for beginning a ceremony.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BeginCeremonyInput {
    /// Ceremony context.
    pub context: DerivationContext,
    /// Transcript binding.
    pub transcript: TranscriptBinding,
    /// Replay cache key for this ceremony.
    pub replay_cache_key: PublicDigest32,
}

/// Initial requested ceremony state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CeremonyRequested {
    /// Ceremony context.
    pub context: DerivationContext,
    /// Transcript binding.
    pub transcript: TranscriptBinding,
    /// Transcript digest.
    pub transcript_digest: PublicDigest32,
    /// Replay cache key for this ceremony.
    pub replay_cache_key: PublicDigest32,
}

/// Input for creating role envelopes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateRoleEnvelopesInput {
    /// Prior requested state.
    pub state: CeremonyRequested,
    /// Signer A envelope header.
    pub signer_a_envelope: EnvelopeHeaderV1,
    /// Signer B envelope header.
    pub signer_b_envelope: EnvelopeHeaderV1,
}

/// State after Router created role envelopes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleEnvelopesCreated {
    /// Prior requested state.
    pub requested: CeremonyRequested,
    /// Signer A envelope header.
    pub signer_a_envelope: EnvelopeHeaderV1,
    /// Signer B envelope header.
    pub signer_b_envelope: EnvelopeHeaderV1,
}

/// Input for signer input acceptance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignerInputAcceptance {
    /// Prior role-envelope state.
    pub state: RoleEnvelopesCreated,
    /// Signer A accepted-input receipt digest.
    pub signer_a_acceptance_digest: PublicDigest32,
    /// Signer B accepted-input receipt digest.
    pub signer_b_acceptance_digest: PublicDigest32,
}

/// State after both signers accepted their own input envelopes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignerInputsAccepted {
    /// Prior role-envelope state.
    pub role_envelopes: RoleEnvelopesCreated,
    /// Signer A accepted-input receipt digest.
    pub signer_a_acceptance_digest: PublicDigest32,
    /// Signer B accepted-input receipt digest.
    pub signer_b_acceptance_digest: PublicDigest32,
}

/// Input for candidate coordination completion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoordinationCompletionInput {
    /// Prior accepted-input state.
    pub state: SignerInputsAccepted,
    /// Candidate-specific coordination commitments.
    pub coordination_commitments: Vec<PublicDigest32>,
}

/// State after candidate coordination completes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoordinationComplete {
    /// Prior accepted-input state.
    pub signer_inputs: SignerInputsAccepted,
    /// Candidate-specific coordination commitments.
    pub coordination_commitments: Vec<PublicDigest32>,
}

/// Input for output binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputBindingInput {
    /// Prior coordination-complete state.
    pub state: CoordinationComplete,
    /// Client package commitments.
    pub client_package_commitments: Vec<PublicDigest32>,
    /// Relayer package commitments.
    pub relayer_package_commitments: Vec<PublicDigest32>,
    /// Signer A output receipt digest.
    pub signer_a_output_receipt_digest: PublicDigest32,
    /// Signer B output receipt digest.
    pub signer_b_output_receipt_digest: PublicDigest32,
}

/// State after outputs are bound to public commitments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutputsBound {
    /// Prior coordination-complete state.
    pub coordination: CoordinationComplete,
    /// Client package commitments.
    pub client_package_commitments: Vec<PublicDigest32>,
    /// Relayer package commitments.
    pub relayer_package_commitments: Vec<PublicDigest32>,
    /// Signer A output receipt digest.
    pub signer_a_output_receipt_digest: PublicDigest32,
    /// Signer B output receipt digest.
    pub signer_b_output_receipt_digest: PublicDigest32,
}

/// Input for marking delivery complete.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeliveryReceiptInput {
    /// Prior output-bound state.
    pub state: OutputsBound,
    /// Delivery receipt digests.
    pub delivery_receipt_digests: Vec<PublicDigest32>,
    /// Delivery attempt counter.
    pub delivery_attempts: u32,
}

/// State after delivery receipts are recorded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CeremonyDelivered {
    /// Prior output-bound state.
    pub outputs: OutputsBound,
    /// Delivery receipt digests.
    pub delivery_receipt_digests: Vec<PublicDigest32>,
    /// Delivery attempt counter.
    pub delivery_attempts: u32,
}

/// Input for marking a delivered ceremony verified.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationInput {
    /// Prior delivered state.
    pub state: CeremonyDelivered,
    /// Verified Minimum Level C evidence.
    pub verified_evidence: VerifiedMinimumLevelCEvidenceV1,
    /// Verifier identity.
    pub verifier_identity: String,
    /// Verifier sequence number.
    pub verifier_sequence: u64,
}

/// Terminal verified ceremony state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CeremonyVerified {
    /// Prior delivered state.
    pub delivered: CeremonyDelivered,
    /// Verified Minimum Level C evidence.
    pub verified_evidence: VerifiedMinimumLevelCEvidenceV1,
    /// Verifier identity.
    pub verifier_identity: String,
    /// Verifier sequence number.
    pub verifier_sequence: u64,
}

/// Input for aborting a ceremony.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbortInput {
    /// Last active state label.
    pub last_active_state: CeremonyStateLabel,
    /// Ceremony id.
    pub ceremony_id: String,
    /// Transcript digest when available.
    pub transcript_digest: Option<PublicDigest32>,
    /// Stable abort error code.
    pub error_code: RouterAbDerivationErrorCode,
    /// Redacted abort reason.
    pub redacted_reason: String,
}

/// Terminal aborted ceremony state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CeremonyAborted {
    /// Last active state label.
    pub last_active_state: CeremonyStateLabel,
    /// Ceremony id.
    pub ceremony_id: String,
    /// Transcript digest when available.
    pub transcript_digest: Option<PublicDigest32>,
    /// Stable abort error code.
    pub error_code: RouterAbDerivationErrorCode,
    /// Redacted abort reason.
    pub redacted_reason: String,
}

/// Public ceremony state label for diagnostics and persistence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CeremonyStateLabel {
    /// Requested state.
    Requested,
    /// Role envelopes created state.
    RoleEnvelopesCreated,
    /// Signer inputs accepted state.
    SignerInputsAccepted,
    /// Coordination complete state.
    CoordinationComplete,
    /// Outputs bound state.
    OutputsBound,
    /// Delivered state.
    Delivered,
    /// Verified state.
    Verified,
    /// Aborted state.
    Aborted,
}

/// Begins a ceremony from typed context and transcript metadata.
pub fn begin_requested(input: BeginCeremonyInput) -> RouterAbDerivationResult<CeremonyRequested> {
    input.context.validate()?;
    input.transcript.validate()?;

    if input.context != input.transcript.context {
        return Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::TranscriptMismatch,
            "requested ceremony context does not match transcript context",
        ));
    }

    let transcript_digest = transcript_digest_v1(&input.transcript)?;
    Ok(CeremonyRequested {
        context: input.context,
        transcript: input.transcript,
        transcript_digest,
        replay_cache_key: input.replay_cache_key,
    })
}

/// Creates role envelopes from a requested ceremony.
pub fn create_role_envelopes(
    input: CreateRoleEnvelopesInput,
) -> RouterAbDerivationResult<RoleEnvelopesCreated> {
    verify_signer_envelope(
        &input.signer_a_envelope,
        EnvelopeKind::RouterToSignerA,
        Role::SignerA,
        &input.state,
    )?;
    verify_signer_envelope(
        &input.signer_b_envelope,
        EnvelopeKind::RouterToSignerB,
        Role::SignerB,
        &input.state,
    )?;

    Ok(RoleEnvelopesCreated {
        requested: input.state,
        signer_a_envelope: input.signer_a_envelope,
        signer_b_envelope: input.signer_b_envelope,
    })
}

/// Marks signer inputs accepted by both signers.
pub fn accept_signer_inputs(
    input: SignerInputAcceptance,
) -> RouterAbDerivationResult<SignerInputsAccepted> {
    Ok(SignerInputsAccepted {
        role_envelopes: input.state,
        signer_a_acceptance_digest: input.signer_a_acceptance_digest,
        signer_b_acceptance_digest: input.signer_b_acceptance_digest,
    })
}

/// Marks candidate coordination complete.
pub fn complete_coordination(
    input: CoordinationCompletionInput,
) -> RouterAbDerivationResult<CoordinationComplete> {
    Ok(CoordinationComplete {
        signer_inputs: input.state,
        coordination_commitments: input.coordination_commitments,
    })
}

/// Binds output package commitments.
pub fn bind_outputs(input: OutputBindingInput) -> RouterAbDerivationResult<OutputsBound> {
    if input.client_package_commitments.is_empty() || input.relayer_package_commitments.is_empty() {
        return Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::MalformedInput,
            "output binding requires client and relayer package commitments",
        ));
    }

    Ok(OutputsBound {
        coordination: input.state,
        client_package_commitments: input.client_package_commitments,
        relayer_package_commitments: input.relayer_package_commitments,
        signer_a_output_receipt_digest: input.signer_a_output_receipt_digest,
        signer_b_output_receipt_digest: input.signer_b_output_receipt_digest,
    })
}

/// Marks output packages delivered.
pub fn mark_delivered(input: DeliveryReceiptInput) -> RouterAbDerivationResult<CeremonyDelivered> {
    if input.delivery_receipt_digests.is_empty() {
        return Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::MalformedInput,
            "delivery requires at least one delivery receipt digest",
        ));
    }

    Ok(CeremonyDelivered {
        outputs: input.state,
        delivery_receipt_digests: input.delivery_receipt_digests,
        delivery_attempts: input.delivery_attempts,
    })
}

/// Marks a delivered ceremony verified.
pub fn verify_ceremony(input: VerificationInput) -> RouterAbDerivationResult<CeremonyVerified> {
    let transcript_digest = input
        .state
        .outputs
        .coordination
        .signer_inputs
        .role_envelopes
        .requested
        .transcript_digest;

    if input.verified_evidence.evidence.transcript_digest != transcript_digest {
        return Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::TranscriptMismatch,
            "verified evidence transcript does not match delivered ceremony",
        ));
    }

    require_non_empty("verifier_identity", &input.verifier_identity)?;

    Ok(CeremonyVerified {
        delivered: input.state,
        verified_evidence: input.verified_evidence,
        verifier_identity: input.verifier_identity,
        verifier_sequence: input.verifier_sequence,
    })
}

/// Aborts a ceremony with redacted metadata.
pub fn abort_ceremony(input: AbortInput) -> RouterAbDerivationResult<CeremonyAborted> {
    require_non_empty("ceremony_id", &input.ceremony_id)?;
    require_non_empty("redacted_reason", &input.redacted_reason)?;

    Ok(CeremonyAborted {
        last_active_state: input.last_active_state,
        ceremony_id: input.ceremony_id,
        transcript_digest: input.transcript_digest,
        error_code: input.error_code,
        redacted_reason: input.redacted_reason,
    })
}

fn verify_signer_envelope(
    envelope: &EnvelopeHeaderV1,
    expected_kind: EnvelopeKind,
    expected_signer_role: Role,
    state: &CeremonyRequested,
) -> RouterAbDerivationResult<()> {
    envelope.validate()?;

    if envelope.envelope_kind != expected_kind
        || envelope.sender_role != Role::Router
        || envelope.recipient_role != expected_signer_role
    {
        return Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::RecipientMismatch,
            "signer envelope role or kind mismatch",
        ));
    }

    let signer = state
        .transcript
        .signer_set
        .signer_for_role(expected_signer_role)
        .ok_or_else(|| {
            RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::SignerIdentityMismatch,
                "missing signer role in signer set",
            )
        })?;

    if envelope.recipient_identity != signer.signer_id {
        return Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::SignerIdentityMismatch,
            "signer envelope recipient identity mismatch",
        ));
    }

    if envelope.candidate_id != state.context.candidate_id
        || envelope.request_kind != state.context.request_kind
        || envelope.correctness_level != state.context.correctness_level
        || envelope.ceremony_id != state.context.ceremony_id
        || envelope.root_share_epoch != state.context.root_share_epoch
        || envelope.transcript_digest != state.transcript_digest
    {
        return Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::TranscriptMismatch,
            "signer envelope does not match requested transcript",
        ));
    }

    Ok(())
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
