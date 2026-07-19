use core::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::derivation::context::{DerivationContext, RootShareEpoch};
use crate::derivation::error::{
    RouterAbDerivationError, RouterAbDerivationErrorCode, RouterAbDerivationResult,
};
use crate::derivation::material::{OpenedShareKind, PublicDigest32, Role};
use crate::derivation::transcript::{transcript_digest_v1, TranscriptBinding};

const MPC_PRF_CONTEXT_BYTES_VERSION_V1: &[u8] = b"router-ab-derivation/mpc-prf/context-bytes/v1";
const MPC_PRF_CONTEXT_DIGEST_VERSION_V1: &[u8] = b"router-ab-derivation/mpc-prf/context-digest/v1";
const FIXED_ECDSA_THRESHOLD_PRF_ADAPTER_SUITE_LABEL_V1: &[u8] =
    b"threshold_prf_ristretto255_sha512";
const FIXED_ECDSA_THRESHOLD_PRF_BACKEND_SUITE_LABEL_V1: &[u8] =
    b"threshold-prf/ristretto255-sha512";
const FIXED_ECDSA_THRESHOLD_PRF_OUTPUT_ENCODING_LABEL_V1: &[u8] = b"canonical_ed25519_scalar_32";

/// Router/A/B threshold-PRF partial wire length: share id, context tag, compressed point.
pub const MPC_PRF_PARTIAL_WIRE_V1_LEN: usize = 66;
/// Router/A/B threshold-PRF signing-root-share commitment wire length.
pub const MPC_PRF_COMMITMENT_WIRE_V1_LEN: usize = 34;
/// Router/A/B threshold-PRF DLEQ proof wire length.
pub const MPC_PRF_DLEQ_PROOF_WIRE_V1_LEN: usize = 64;

/// ECDSA output purpose bound into the underlying threshold-PRF context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MpcPrfOutputPurposeV1 {
    /// Router/A/B client-base output.
    RouterAbXClientBase,
    /// Router/A/B server-base output.
    RouterAbXServerBase,
}

impl MpcPrfOutputPurposeV1 {
    /// Derives the purpose from an already validated output request.
    pub fn from_output_request(request: &MpcPrfOutputRequestV1) -> RouterAbDerivationResult<Self> {
        request.validate()?;
        match request.opened_share_kind {
            OpenedShareKind::XClientBase => Ok(Self::RouterAbXClientBase),
            OpenedShareKind::XServerBase => Ok(Self::RouterAbXServerBase),
        }
    }

    /// Returns the canonical purpose label expected from `threshold-prf`.
    pub fn threshold_prf_purpose_label(self) -> &'static str {
        match self {
            Self::RouterAbXClientBase => "router-ab/x_client_base/v1",
            Self::RouterAbXServerBase => "router-ab/x_server_base/v1",
        }
    }
}

/// Purpose-binding plan for calling the fixed ECDSA threshold PRF.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MpcPrfPurposeBindingPlanV1 {
    /// Router/A/B output purpose.
    pub output_purpose: MpcPrfOutputPurposeV1,
    /// External `threshold-prf` purpose label.
    pub threshold_prf_purpose_label: String,
    /// Transcript digest bound into the PRF context bytes.
    pub transcript_digest: PublicDigest32,
    /// Digest of the exact PRF context bytes.
    pub threshold_prf_context_digest: PublicDigest32,
    /// Exact context bytes to supply to `threshold-prf`.
    pub threshold_prf_context_bytes: Vec<u8>,
    /// Opened share kind.
    pub opened_share_kind: OpenedShareKind,
    /// Recipient role.
    pub recipient_role: Role,
    /// Recipient identity.
    pub recipient_identity: String,
}

/// Output requested from a signer partial derivation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MpcPrfOutputRequestV1 {
    /// Output kind to open after recipient combine.
    pub opened_share_kind: OpenedShareKind,
    /// Role that will receive and combine this output.
    pub recipient_role: Role,
    /// Canonical recipient identity.
    pub recipient_identity: String,
}

impl MpcPrfOutputRequestV1 {
    /// Creates a validated output request.
    pub fn new(
        opened_share_kind: OpenedShareKind,
        recipient_role: Role,
        recipient_identity: impl Into<String>,
    ) -> RouterAbDerivationResult<Self> {
        let request = Self {
            opened_share_kind,
            recipient_role,
            recipient_identity: recipient_identity.into(),
        };
        request.validate()?;
        Ok(request)
    }

    /// Validates output recipient binding.
    pub fn validate(&self) -> RouterAbDerivationResult<()> {
        require_non_empty("recipient_identity", &self.recipient_identity)?;
        match (self.opened_share_kind, self.recipient_role) {
            (OpenedShareKind::XClientBase, Role::Client)
            | (OpenedShareKind::XServerBase, Role::Server) => Ok(()),
            _ => Err(RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::RecipientMismatch,
                "MPC PRF output request recipient does not match opened share kind",
            )),
        }
    }
}

/// Router-to-Deriver input for fixed ECDSA threshold-PRF evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MpcPrfSignerPartialInputV1 {
    /// Canonical derivation context.
    pub context: DerivationContext,
    /// Transcript binding for this ceremony.
    pub transcript: TranscriptBinding,
    /// Signer role executing the derivation.
    pub signer_role: Role,
    /// Canonical signer identity.
    pub signer_identity: String,
    /// Root-share epoch the signer must hold.
    pub root_share_epoch: RootShareEpoch,
    /// Outputs requested from this signer.
    pub output_requests: Vec<MpcPrfOutputRequestV1>,
}

impl MpcPrfSignerPartialInputV1 {
    /// Creates a validated signer partial input.
    pub fn new(
        context: DerivationContext,
        transcript: TranscriptBinding,
        signer_role: Role,
        signer_identity: impl Into<String>,
        root_share_epoch: RootShareEpoch,
        output_requests: Vec<MpcPrfOutputRequestV1>,
    ) -> RouterAbDerivationResult<Self> {
        let input = Self {
            context,
            transcript,
            signer_role,
            signer_identity: signer_identity.into(),
            root_share_epoch,
            output_requests,
        };
        input.validate()?;
        Ok(input)
    }

    /// Validates public ECDSA threshold-PRF Deriver input metadata.
    pub fn validate(&self) -> RouterAbDerivationResult<()> {
        self.context.validate()?;
        self.transcript.validate()?;
        require_mpc_context(&self.context)?;
        require_context_matches_transcript(&self.context, &self.transcript)?;
        require_signer_identity(&self.transcript, self.signer_role, &self.signer_identity)?;
        if &self.root_share_epoch != self.context.root_share_epoch() {
            return Err(RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::RootEpochMismatch,
                "MPC PRF signer input root-share epoch does not match context",
            ));
        }
        if self.output_requests.is_empty() {
            return Err(RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::MalformedInput,
                "MPC PRF signer input requires at least one output request",
            ));
        }
        for request in &self.output_requests {
            request.validate()?;
        }
        Ok(())
    }
}

/// Public metadata bound to one ECDSA threshold-PRF partial.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MpcPrfPartialBindingV1 {
    /// Transcript digest.
    pub transcript_digest: PublicDigest32,
    /// Root-share epoch.
    pub root_share_epoch: RootShareEpoch,
    /// Opened share kind.
    pub opened_share_kind: OpenedShareKind,
    /// Recipient role.
    pub recipient_role: Role,
    /// Recipient identity.
    pub recipient_identity: String,
    /// Signer role.
    pub signer_role: Role,
    /// Signer identity.
    pub signer_identity: String,
}

impl MpcPrfPartialBindingV1 {
    /// Creates the public binding for one signer/output partial.
    pub fn from_signer_input(
        input: &MpcPrfSignerPartialInputV1,
        request: &MpcPrfOutputRequestV1,
    ) -> RouterAbDerivationResult<Self> {
        input.validate()?;
        request.validate()?;
        Ok(Self {
            transcript_digest: transcript_digest_v1(&input.transcript)?,
            root_share_epoch: input.root_share_epoch.clone(),
            opened_share_kind: request.opened_share_kind,
            recipient_role: request.recipient_role,
            recipient_identity: request.recipient_identity.clone(),
            signer_role: input.signer_role,
            signer_identity: input.signer_identity.clone(),
        })
    }

    /// Validates public partial binding metadata.
    pub fn validate(&self, transcript: &TranscriptBinding) -> RouterAbDerivationResult<()> {
        transcript.validate()?;
        if self.transcript_digest != transcript_digest_v1(transcript)? {
            return Err(RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::TranscriptMismatch,
                "MPC PRF partial transcript digest mismatch",
            ));
        }
        if &self.root_share_epoch != transcript.context().root_share_epoch() {
            return Err(RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::RootEpochMismatch,
                "MPC PRF partial root-share epoch mismatch",
            ));
        }
        MpcPrfOutputRequestV1::new(
            self.opened_share_kind,
            self.recipient_role,
            self.recipient_identity.clone(),
        )?;
        require_signer_identity(transcript, self.signer_role, &self.signer_identity)
    }
}

/// Secret ECDSA threshold-PRF partial wire bytes. Debug output is always redacted.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct MpcPrfPartialWireV1 {
    bytes: Vec<u8>,
}

impl MpcPrfPartialWireV1 {
    /// Creates a fixed-width partial wire.
    pub fn new(bytes: Vec<u8>) -> RouterAbDerivationResult<Self> {
        require_len(
            "mpc_prf_partial_wire",
            bytes.len(),
            MPC_PRF_PARTIAL_WIRE_V1_LEN,
        )?;
        let share_id = u16::from_be_bytes([bytes[0], bytes[1]]);
        if !matches!(share_id, 1 | 2) {
            return Err(RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::MalformedInput,
                "ECDSA threshold-PRF partial share id must be 1 or 2",
            ));
        }
        Ok(Self { bytes })
    }

    /// Returns partial wire bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Debug for MpcPrfPartialWireV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MpcPrfPartialWireV1([redacted])")
    }
}

/// Public ECDSA threshold-PRF share-commitment wire bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MpcPrfShareCommitmentWireV1 {
    /// Fixed-width commitment bytes.
    pub bytes: Vec<u8>,
}

impl MpcPrfShareCommitmentWireV1 {
    /// Creates a fixed-width share commitment wire.
    pub fn new(bytes: Vec<u8>) -> RouterAbDerivationResult<Self> {
        require_len(
            "mpc_prf_share_commitment_wire",
            bytes.len(),
            MPC_PRF_COMMITMENT_WIRE_V1_LEN,
        )?;
        let share_id = u16::from_be_bytes([bytes[0], bytes[1]]);
        if !matches!(share_id, 1 | 2) {
            return Err(RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::MalformedInput,
                "ECDSA threshold-PRF commitment share id must be 1 or 2",
            ));
        }
        Ok(Self { bytes })
    }

    /// Returns commitment wire bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// ECDSA threshold-PRF DLEQ proof wire bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MpcPrfDleqProofWireV1 {
    /// Fixed-width proof bytes.
    pub bytes: Vec<u8>,
}

impl MpcPrfDleqProofWireV1 {
    /// Creates a fixed-width DLEQ proof wire.
    pub fn new(bytes: Vec<u8>) -> RouterAbDerivationResult<Self> {
        require_len(
            "mpc_prf_dleq_proof_wire",
            bytes.len(),
            MPC_PRF_DLEQ_PROOF_WIRE_V1_LEN,
        )?;
        Ok(Self { bytes })
    }

    /// Returns proof wire bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// One Deriver-produced ECDSA threshold-PRF partial plus its public binding.
#[derive(Clone, PartialEq, Eq)]
pub struct MpcPrfSignerPartialV1 {
    /// Public metadata bound to the partial.
    pub binding: MpcPrfPartialBindingV1,
    /// Fixed-width secret partial wire.
    pub partial_wire: MpcPrfPartialWireV1,
}

impl MpcPrfSignerPartialV1 {
    /// Creates a validated signer partial wrapper.
    pub fn new(
        binding: MpcPrfPartialBindingV1,
        partial_wire: MpcPrfPartialWireV1,
    ) -> RouterAbDerivationResult<Self> {
        if partial_wire.as_bytes().len() != MPC_PRF_PARTIAL_WIRE_V1_LEN {
            return Err(RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::MalformedInput,
                "MPC PRF signer partial wire length mismatch",
            ));
        }
        Ok(Self {
            binding,
            partial_wire,
        })
    }
}

impl fmt::Debug for MpcPrfSignerPartialV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MpcPrfSignerPartialV1")
            .field("binding", &self.binding)
            .field("partial_wire", &"[redacted]")
            .finish()
    }
}

/// Partial plus proof material before combiner acceptance.
#[derive(Clone, PartialEq, Eq)]
pub struct MpcPrfPartialProofBundleV1 {
    /// Signer partial.
    pub signer_partial: MpcPrfSignerPartialV1,
    /// Public share commitment.
    pub commitment_wire: MpcPrfShareCommitmentWireV1,
    /// Public DLEQ proof wire.
    pub proof_wire: MpcPrfDleqProofWireV1,
}

impl MpcPrfPartialProofBundleV1 {
    /// Creates a validated proof bundle wrapper.
    pub fn new(
        signer_partial: MpcPrfSignerPartialV1,
        commitment_wire: MpcPrfShareCommitmentWireV1,
        proof_wire: MpcPrfDleqProofWireV1,
    ) -> RouterAbDerivationResult<Self> {
        require_len(
            "mpc_prf_partial_wire",
            signer_partial.partial_wire.as_bytes().len(),
            MPC_PRF_PARTIAL_WIRE_V1_LEN,
        )?;
        require_len(
            "mpc_prf_share_commitment_wire",
            commitment_wire.as_bytes().len(),
            MPC_PRF_COMMITMENT_WIRE_V1_LEN,
        )?;
        require_len(
            "mpc_prf_dleq_proof_wire",
            proof_wire.as_bytes().len(),
            MPC_PRF_DLEQ_PROOF_WIRE_V1_LEN,
        )?;
        Ok(Self {
            signer_partial,
            commitment_wire,
            proof_wire,
        })
    }
}

impl fmt::Debug for MpcPrfPartialProofBundleV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MpcPrfPartialProofBundleV1")
            .field("signer_partial", &self.signer_partial)
            .field("commitment_wire", &self.commitment_wire)
            .field("proof_wire", &self.proof_wire)
            .finish()
    }
}

/// ECDSA threshold-PRF partial after proof verification at the adapter boundary.
#[derive(Clone, PartialEq, Eq)]
pub struct MpcPrfVerifiedPartialV1 {
    /// Verified signer partial.
    pub signer_partial: MpcPrfSignerPartialV1,
    /// Commitment authenticated for the signer and epoch.
    pub commitment_wire: MpcPrfShareCommitmentWireV1,
}

impl MpcPrfVerifiedPartialV1 {
    /// Creates a verified partial after the adapter verifies the proof statement.
    pub fn from_verified_parts(
        signer_partial: MpcPrfSignerPartialV1,
        commitment_wire: MpcPrfShareCommitmentWireV1,
    ) -> RouterAbDerivationResult<Self> {
        Ok(Self {
            signer_partial,
            commitment_wire,
        })
    }
}

impl fmt::Debug for MpcPrfVerifiedPartialV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MpcPrfVerifiedPartialV1")
            .field("signer_partial", &self.signer_partial)
            .field("commitment_wire", &self.commitment_wire)
            .finish()
    }
}

/// Recipient combiner input for two verified ECDSA threshold-PRF partials.
#[derive(Clone, PartialEq, Eq)]
pub struct MpcPrfCombinerInputV1 {
    /// Transcript binding for the output.
    pub transcript: TranscriptBinding,
    /// Opened share kind being combined.
    pub opened_share_kind: OpenedShareKind,
    /// Recipient role.
    pub recipient_role: Role,
    /// Recipient identity.
    pub recipient_identity: String,
    /// First verified partial.
    pub left: MpcPrfVerifiedPartialV1,
    /// Second verified partial.
    pub right: MpcPrfVerifiedPartialV1,
}

/// Public combiner plan produced after metadata validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MpcPrfCombinePlanV1 {
    /// Transcript digest.
    pub transcript_digest: PublicDigest32,
    /// Opened share kind being combined.
    pub opened_share_kind: OpenedShareKind,
    /// Recipient role.
    pub recipient_role: Role,
    /// Recipient identity.
    pub recipient_identity: String,
    /// Signer roles represented in the combine input.
    pub signer_roles: [Role; 2],
}

/// Boundary input for ECDSA threshold-PRF partial proof verification planning.
#[derive(Clone, PartialEq, Eq)]
pub struct MpcPrfPartialVerificationInputV1 {
    /// Transcript binding for the partial.
    pub transcript: TranscriptBinding,
    /// Proof bundle to validate before cryptographic verification.
    pub proof_bundle: MpcPrfPartialProofBundleV1,
}

/// Public verification plan produced after Router/A/B metadata validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MpcPrfPartialVerificationPlanV1 {
    /// Transcript digest.
    pub transcript_digest: PublicDigest32,
    /// Root-share epoch.
    pub root_share_epoch: RootShareEpoch,
    /// Opened share kind.
    pub opened_share_kind: OpenedShareKind,
    /// Recipient role.
    pub recipient_role: Role,
    /// Recipient identity.
    pub recipient_identity: String,
    /// Signer role.
    pub signer_role: Role,
    /// Signer identity.
    pub signer_identity: String,
    /// Fixed partial wire length.
    pub partial_wire_len: usize,
    /// Fixed commitment wire length.
    pub commitment_wire_len: usize,
    /// Fixed proof wire length.
    pub proof_wire_len: usize,
}

/// Validates ECDSA threshold-PRF proof-bundle metadata before cryptographic verification.
pub fn plan_mpc_prf_partial_verification_v1(
    input: MpcPrfPartialVerificationInputV1,
) -> RouterAbDerivationResult<MpcPrfPartialVerificationPlanV1> {
    input.transcript.validate()?;
    require_mpc_context(input.transcript.context())?;

    let bundle = input.proof_bundle;
    let binding = &bundle.signer_partial.binding;
    binding.validate(&input.transcript)?;
    require_len(
        "mpc_prf_partial_wire",
        bundle.signer_partial.partial_wire.as_bytes().len(),
        MPC_PRF_PARTIAL_WIRE_V1_LEN,
    )?;
    require_len(
        "mpc_prf_share_commitment_wire",
        bundle.commitment_wire.as_bytes().len(),
        MPC_PRF_COMMITMENT_WIRE_V1_LEN,
    )?;
    require_len(
        "mpc_prf_dleq_proof_wire",
        bundle.proof_wire.as_bytes().len(),
        MPC_PRF_DLEQ_PROOF_WIRE_V1_LEN,
    )?;

    Ok(MpcPrfPartialVerificationPlanV1 {
        transcript_digest: binding.transcript_digest,
        root_share_epoch: binding.root_share_epoch.clone(),
        opened_share_kind: binding.opened_share_kind,
        recipient_role: binding.recipient_role,
        recipient_identity: binding.recipient_identity.clone(),
        signer_role: binding.signer_role,
        signer_identity: binding.signer_identity.clone(),
        partial_wire_len: MPC_PRF_PARTIAL_WIRE_V1_LEN,
        commitment_wire_len: MPC_PRF_COMMITMENT_WIRE_V1_LEN,
        proof_wire_len: MPC_PRF_DLEQ_PROOF_WIRE_V1_LEN,
    })
}

/// Plans signer-neutral purpose binding before calling the underlying threshold PRF.
pub fn plan_mpc_prf_purpose_binding_v1(
    input: &MpcPrfSignerPartialInputV1,
    request: &MpcPrfOutputRequestV1,
) -> RouterAbDerivationResult<MpcPrfPurposeBindingPlanV1> {
    input.validate()?;
    request.validate()?;
    if !input
        .output_requests
        .iter()
        .any(|candidate| candidate == request)
    {
        return Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::RecipientMismatch,
            "MPC PRF purpose request is missing from signer input",
        ));
    }

    plan_mpc_prf_purpose_binding_for_output_v1(&input.transcript, request)
}

pub(crate) fn plan_mpc_prf_purpose_binding_for_output_v1(
    transcript: &TranscriptBinding,
    request: &MpcPrfOutputRequestV1,
) -> RouterAbDerivationResult<MpcPrfPurposeBindingPlanV1> {
    transcript.validate()?;
    require_mpc_context(transcript.context())?;
    request.validate()?;

    let output_purpose = MpcPrfOutputPurposeV1::from_output_request(request)?;
    let transcript_digest = transcript_digest_v1(transcript)?;
    let threshold_prf_context_bytes =
        encode_mpc_prf_context_bytes_v1(request, output_purpose, transcript_digest)?;
    let threshold_prf_context_digest = mpc_prf_context_digest_v1(&threshold_prf_context_bytes)?;

    Ok(MpcPrfPurposeBindingPlanV1 {
        output_purpose,
        threshold_prf_purpose_label: output_purpose.threshold_prf_purpose_label().to_owned(),
        transcript_digest,
        threshold_prf_context_digest,
        threshold_prf_context_bytes,
        opened_share_kind: request.opened_share_kind,
        recipient_role: request.recipient_role,
        recipient_identity: request.recipient_identity.clone(),
    })
}

/// Validates two verified partials before recipient-side threshold-PRF combination.
pub fn plan_mpc_prf_combine_v1(
    input: MpcPrfCombinerInputV1,
) -> RouterAbDerivationResult<MpcPrfCombinePlanV1> {
    input.transcript.validate()?;
    require_mpc_context(input.transcript.context())?;
    MpcPrfOutputRequestV1::new(
        input.opened_share_kind,
        input.recipient_role,
        input.recipient_identity.clone(),
    )?;

    let transcript_digest = transcript_digest_v1(&input.transcript)?;
    let left = &input.left.signer_partial.binding;
    let right = &input.right.signer_partial.binding;
    left.validate(&input.transcript)?;
    right.validate(&input.transcript)?;

    if left.signer_role == right.signer_role {
        return Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::DuplicateSignerIdentity,
            "MPC PRF combine requires distinct signer roles",
        ));
    }

    for binding in [left, right] {
        if binding.opened_share_kind != input.opened_share_kind
            || binding.recipient_role != input.recipient_role
            || binding.recipient_identity != input.recipient_identity
        {
            return Err(RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::RecipientMismatch,
                "MPC PRF combine input partial recipient binding mismatch",
            ));
        }
    }

    Ok(MpcPrfCombinePlanV1 {
        transcript_digest,
        opened_share_kind: input.opened_share_kind,
        recipient_role: input.recipient_role,
        recipient_identity: input.recipient_identity,
        signer_roles: [left.signer_role, right.signer_role],
    })
}

fn encode_mpc_prf_context_bytes_v1(
    request: &MpcPrfOutputRequestV1,
    output_purpose: MpcPrfOutputPurposeV1,
    transcript_digest: PublicDigest32,
) -> RouterAbDerivationResult<Vec<u8>> {
    let mut out = Vec::new();
    push_field(&mut out, MPC_PRF_CONTEXT_BYTES_VERSION_V1);
    push_field(&mut out, FIXED_ECDSA_THRESHOLD_PRF_ADAPTER_SUITE_LABEL_V1);
    push_field(&mut out, FIXED_ECDSA_THRESHOLD_PRF_BACKEND_SUITE_LABEL_V1);
    push_field(
        &mut out,
        output_purpose.threshold_prf_purpose_label().as_bytes(),
    );
    push_field(&mut out, FIXED_ECDSA_THRESHOLD_PRF_OUTPUT_ENCODING_LABEL_V1);
    push_field(&mut out, transcript_digest.as_bytes());
    push_field(&mut out, request.opened_share_kind.as_str().as_bytes());
    push_field(&mut out, request.recipient_role.as_str().as_bytes());
    push_field(&mut out, request.recipient_identity.as_bytes());
    Ok(out)
}

fn mpc_prf_context_digest_v1(context_bytes: &[u8]) -> RouterAbDerivationResult<PublicDigest32> {
    let mut hasher = Sha256::new();
    push_hash_field(&mut hasher, MPC_PRF_CONTEXT_DIGEST_VERSION_V1);
    push_hash_field(&mut hasher, context_bytes);
    Ok(PublicDigest32::new(hasher.finalize().into()))
}

fn require_mpc_context(context: &DerivationContext) -> RouterAbDerivationResult<()> {
    context.validate()
}

fn push_field(out: &mut Vec<u8>, value: &[u8]) {
    let len = value.len() as u32;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(value);
}

fn push_hash_field(hasher: &mut Sha256, value: &[u8]) {
    let len = value.len() as u32;
    hasher.update(len.to_be_bytes());
    hasher.update(value);
}

fn require_context_matches_transcript(
    context: &DerivationContext,
    transcript: &TranscriptBinding,
) -> RouterAbDerivationResult<()> {
    if context != transcript.context() {
        return Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::TranscriptMismatch,
            "MPC PRF input context does not match transcript context",
        ));
    }
    Ok(())
}

fn require_signer_identity(
    transcript: &TranscriptBinding,
    role: Role,
    identity: &str,
) -> RouterAbDerivationResult<()> {
    require_non_empty("signer_identity", identity)?;
    match role {
        Role::SignerA | Role::SignerB => {}
        _ => {
            return Err(RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::SignerIdentityMismatch,
                "MPC PRF signer role must be Signer A or Signer B",
            ));
        }
    }

    let signer = transcript
        .signer_set()
        .signer_for_role(role)
        .ok_or_else(|| {
            RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::SignerIdentityMismatch,
                "MPC PRF signer role is missing from transcript",
            )
        })?;
    if signer.signer_id() != identity {
        return Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::SignerIdentityMismatch,
            "MPC PRF signer identity does not match transcript",
        ));
    }
    Ok(())
}

fn require_len(
    field: &'static str,
    actual: usize,
    expected: usize,
) -> RouterAbDerivationResult<()> {
    if actual != expected {
        return Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::MalformedInput,
            format!("{field} must be {expected} bytes"),
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
