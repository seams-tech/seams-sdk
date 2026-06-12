use core::fmt;

use curve25519_dalek::scalar::Scalar;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::derivation::context::{CandidateId, DerivationContext, RootShareEpoch};
use crate::derivation::error::{
    RouterAbDerivationError, RouterAbDerivationErrorCode, RouterAbDerivationResult,
};
use crate::derivation::material::{
    OpenedShareKind, PublicDigest32, PublicMaterial32, Role, SecretMaterial32,
};
use crate::derivation::scope::RefreshScope;
use crate::derivation::transcript::{
    transcript_binding_digest, transcript_digest_v1, TranscriptBinding,
};

/// Candidate B root share length.
pub const SPLIT_ROOT_SECRET_SHARE_V1_LEN: usize = 32;
/// Candidate B output-share wire length.
pub const SPLIT_ROOT_OUTPUT_SHARE_WIRE_V1_LEN: usize = 32;

/// Candidate B suite identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SplitRootSuiteId {
    /// SHA-512 based hash-to-scalar suite under evaluation.
    HashToScalarSha512V1,
}

impl SplitRootSuiteId {
    /// Returns the canonical suite label.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HashToScalarSha512V1 => "split_root_hash_to_scalar_sha512_v1",
        }
    }
}

/// Domain-separated Candidate B derivation label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SplitRootDerivationLabelV1 {
    /// Output-share derivation.
    OutputShare,
}

impl SplitRootDerivationLabelV1 {
    /// Returns the canonical derivation label.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OutputShare => "router-ab-derivation/split-root/output-share/v1",
        }
    }
}

/// Secret Candidate B signer root share.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct SplitRootSecretShareV1 {
    #[zeroize(skip)]
    signer_role: Role,
    #[zeroize(skip)]
    root_share_epoch: RootShareEpoch,
    bytes: Vec<u8>,
}

impl SplitRootSecretShareV1 {
    /// Creates a fixed-width signer root share wrapper.
    pub fn new(
        signer_role: Role,
        root_share_epoch: RootShareEpoch,
        bytes: Vec<u8>,
    ) -> RouterAbDerivationResult<Self> {
        require_signer_role(signer_role)?;
        require_len(
            "split_root_secret_share",
            bytes.len(),
            SPLIT_ROOT_SECRET_SHARE_V1_LEN,
        )?;
        Ok(Self {
            signer_role,
            root_share_epoch,
            bytes,
        })
    }

    /// Returns the signer role that owns this root share.
    pub fn signer_role(&self) -> Role {
        self.signer_role
    }

    /// Returns the public root-share epoch for this root share.
    pub fn root_share_epoch(&self) -> &RootShareEpoch {
        &self.root_share_epoch
    }

    /// Returns root-share bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Debug for SplitRootSecretShareV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SplitRootSecretShareV1")
            .field("signer_role", &self.signer_role)
            .field("root_share_epoch", &self.root_share_epoch.as_str())
            .field("bytes", &"[redacted]")
            .finish()
    }
}

/// Output requested from Candidate B signer-local derivation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SplitRootOutputRequestV1 {
    /// Output kind to open after recipient combine.
    pub opened_share_kind: OpenedShareKind,
    /// Role that will receive and combine this output.
    pub recipient_role: Role,
    /// Canonical recipient identity.
    pub recipient_identity: String,
}

impl SplitRootOutputRequestV1 {
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

    /// Validates recipient binding.
    pub fn validate(&self) -> RouterAbDerivationResult<()> {
        require_non_empty("recipient_identity", &self.recipient_identity)?;
        match (self.opened_share_kind, self.recipient_role) {
            (OpenedShareKind::XClientBase, Role::Client)
            | (OpenedShareKind::XRelayerBase, Role::Relayer) => Ok(()),
            _ => Err(RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::RecipientMismatch,
                "split-root output request recipient does not match opened share kind",
            )),
        }
    }
}

/// Input shape for the split-root derivation candidate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SplitRootCandidateInput {
    /// Canonical derivation context.
    pub context: DerivationContext,
    /// Transcript binding for this ceremony.
    pub transcript: TranscriptBinding,
}

/// Router-to-signer input for Candidate B output-share derivation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SplitRootSignerInputV1 {
    /// Canonical derivation context.
    pub context: DerivationContext,
    /// Transcript binding for this ceremony.
    pub transcript: TranscriptBinding,
    /// Candidate B suite.
    pub suite_id: SplitRootSuiteId,
    /// Signer role executing the derivation.
    pub signer_role: Role,
    /// Canonical signer identity.
    pub signer_identity: String,
    /// Root-share epoch the signer must hold.
    pub root_share_epoch: RootShareEpoch,
    /// Outputs requested from this signer.
    pub output_requests: Vec<SplitRootOutputRequestV1>,
}

impl SplitRootSignerInputV1 {
    /// Creates a validated signer input.
    pub fn new(
        context: DerivationContext,
        transcript: TranscriptBinding,
        suite_id: SplitRootSuiteId,
        signer_role: Role,
        signer_identity: impl Into<String>,
        root_share_epoch: RootShareEpoch,
        output_requests: Vec<SplitRootOutputRequestV1>,
    ) -> RouterAbDerivationResult<Self> {
        let input = Self {
            context,
            transcript,
            suite_id,
            signer_role,
            signer_identity: signer_identity.into(),
            root_share_epoch,
            output_requests,
        };
        input.validate()?;
        Ok(input)
    }

    /// Validates public Candidate B signer input metadata.
    pub fn validate(&self) -> RouterAbDerivationResult<()> {
        self.context.validate()?;
        self.transcript.validate()?;
        require_split_root_context(&self.context)?;
        require_context_matches_transcript(&self.context, &self.transcript)?;
        require_signer_identity(&self.transcript, self.signer_role, &self.signer_identity)?;
        if self.root_share_epoch != self.context.root_share_epoch {
            return Err(RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::RootEpochMismatch,
                "split-root signer input root-share epoch does not match context",
            ));
        }
        if self.output_requests.is_empty() {
            return Err(RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::MalformedInput,
                "split-root signer input requires at least one output request",
            ));
        }
        for request in &self.output_requests {
            request.validate()?;
        }
        Ok(())
    }
}

/// Public metadata bound to one Candidate B output share.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SplitRootOutputShareBindingV1 {
    /// Candidate B suite.
    pub suite_id: SplitRootSuiteId,
    /// Domain-separated derivation label.
    pub derivation_label: SplitRootDerivationLabelV1,
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

impl SplitRootOutputShareBindingV1 {
    /// Creates the public binding for one signer/output share.
    pub fn from_signer_input(
        input: &SplitRootSignerInputV1,
        request: &SplitRootOutputRequestV1,
    ) -> RouterAbDerivationResult<Self> {
        input.validate()?;
        request.validate()?;
        Ok(Self {
            suite_id: input.suite_id,
            derivation_label: SplitRootDerivationLabelV1::OutputShare,
            transcript_digest: transcript_digest_v1(&input.transcript)?,
            root_share_epoch: input.root_share_epoch.clone(),
            opened_share_kind: request.opened_share_kind,
            recipient_role: request.recipient_role,
            recipient_identity: request.recipient_identity.clone(),
            signer_role: input.signer_role,
            signer_identity: input.signer_identity.clone(),
        })
    }

    /// Validates output-share binding metadata.
    pub fn validate(&self, transcript: &TranscriptBinding) -> RouterAbDerivationResult<()> {
        transcript.validate()?;
        require_split_root_context(&transcript.context)?;
        if self.transcript_digest != transcript_digest_v1(transcript)? {
            return Err(RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::TranscriptMismatch,
                "split-root output share transcript digest mismatch",
            ));
        }
        if self.root_share_epoch != transcript.context.root_share_epoch {
            return Err(RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::RootEpochMismatch,
                "split-root output share root-share epoch mismatch",
            ));
        }
        SplitRootOutputRequestV1::new(
            self.opened_share_kind,
            self.recipient_role,
            self.recipient_identity.clone(),
        )?;
        require_signer_identity(transcript, self.signer_role, &self.signer_identity)
    }
}

/// Secret Candidate B output-share wire bytes. Debug output is always redacted.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct SplitRootOutputShareWireV1 {
    bytes: Vec<u8>,
}

impl SplitRootOutputShareWireV1 {
    /// Creates a fixed-width output-share wire.
    pub fn new(bytes: Vec<u8>) -> RouterAbDerivationResult<Self> {
        require_len(
            "split_root_output_share_wire",
            bytes.len(),
            SPLIT_ROOT_OUTPUT_SHARE_WIRE_V1_LEN,
        )?;
        Ok(Self { bytes })
    }

    /// Returns output-share wire bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Debug for SplitRootOutputShareWireV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SplitRootOutputShareWireV1([redacted])")
    }
}

/// One signer-produced Candidate B output share plus its public binding.
#[derive(Clone, PartialEq, Eq)]
pub struct SplitRootSignerOutputShareV1 {
    /// Public metadata bound to the output share.
    pub binding: SplitRootOutputShareBindingV1,
    /// Fixed-width secret output-share wire.
    pub share_wire: SplitRootOutputShareWireV1,
}

impl SplitRootSignerOutputShareV1 {
    /// Creates a validated signer output-share wrapper.
    pub fn new(
        binding: SplitRootOutputShareBindingV1,
        share_wire: SplitRootOutputShareWireV1,
    ) -> RouterAbDerivationResult<Self> {
        require_len(
            "split_root_output_share_wire",
            share_wire.as_bytes().len(),
            SPLIT_ROOT_OUTPUT_SHARE_WIRE_V1_LEN,
        )?;
        Ok(Self {
            binding,
            share_wire,
        })
    }
}

impl fmt::Debug for SplitRootSignerOutputShareV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SplitRootSignerOutputShareV1")
            .field("binding", &self.binding)
            .field("share_wire", &"[redacted]")
            .finish()
    }
}

/// Candidate B output share after adapter-side authenticity checks.
#[derive(Clone, PartialEq, Eq)]
pub struct SplitRootVerifiedOutputShareV1 {
    /// Verified signer output share.
    pub signer_share: SplitRootSignerOutputShareV1,
}

impl SplitRootVerifiedOutputShareV1 {
    /// Creates a verified output share wrapper.
    pub fn from_verified_share(
        signer_share: SplitRootSignerOutputShareV1,
    ) -> RouterAbDerivationResult<Self> {
        Ok(Self { signer_share })
    }
}

impl fmt::Debug for SplitRootVerifiedOutputShareV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SplitRootVerifiedOutputShareV1")
            .field("signer_share", &self.signer_share)
            .finish()
    }
}

/// Recipient combiner input for two verified Candidate B output shares.
#[derive(Clone, PartialEq, Eq)]
pub struct SplitRootCombinerInputV1 {
    /// Transcript binding for the output.
    pub transcript: TranscriptBinding,
    /// Opened share kind being combined.
    pub opened_share_kind: OpenedShareKind,
    /// Recipient role.
    pub recipient_role: Role,
    /// Recipient identity.
    pub recipient_identity: String,
    /// First verified output share.
    pub left: SplitRootVerifiedOutputShareV1,
    /// Second verified output share.
    pub right: SplitRootVerifiedOutputShareV1,
}

/// Public combiner plan produced after metadata validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SplitRootCombinePlanV1 {
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

/// Candidate B refresh mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SplitRootRefreshModeV1 {
    /// New epoch creates a new verified output relation before activation.
    FutureEpochNewOutputRelation,
}

/// Refresh planner input for Candidate B.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SplitRootRefreshPlanInputV1 {
    /// Request-kind-specific refresh scope.
    pub refresh_scope: RefreshScope,
    /// Candidate B refresh mode.
    pub refresh_mode: SplitRootRefreshModeV1,
}

/// Candidate B refresh plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SplitRootRefreshPlanV1 {
    /// Old root-share epoch.
    pub old_root_share_epoch: RootShareEpoch,
    /// New root-share epoch.
    pub new_root_share_epoch: RootShareEpoch,
    /// Candidate B refresh mode.
    pub refresh_mode: SplitRootRefreshModeV1,
    /// Whether this plan preserves the old output relation.
    pub preserves_existing_output_relation: bool,
    /// Release gate before activating the new epoch.
    pub activation_gate: String,
}

/// Output shape for the split-root derivation candidate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SplitRootCandidateOutput {
    /// Digest that binds context, identities, and candidate transcript.
    pub transcript_digest: [u8; 32],
    /// Kind of opened share produced by this candidate.
    pub opened_share_kind: OpenedShareKind,
    /// Opened public material for the designated recipient.
    pub opened_material: PublicMaterial32,
}

/// Recipient-local combined Candidate B output. Debug output redacts material.
#[derive(Clone, PartialEq, Eq)]
pub struct SplitRootCombinedOutputV1 {
    /// Transcript digest.
    pub transcript_digest: PublicDigest32,
    /// Opened share kind.
    pub opened_share_kind: OpenedShareKind,
    /// Recipient role.
    pub recipient_role: Role,
    /// Recipient identity.
    pub recipient_identity: String,
    /// Recipient-local combined output material.
    pub output_material: SecretMaterial32,
}

impl fmt::Debug for SplitRootCombinedOutputV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SplitRootCombinedOutputV1")
            .field("transcript_digest", &self.transcript_digest)
            .field("opened_share_kind", &self.opened_share_kind)
            .field("recipient_role", &self.recipient_role)
            .field("recipient_identity", &self.recipient_identity)
            .field("output_material", &"[redacted]")
            .finish()
    }
}

/// Evaluates the split-root candidate after the decision gate lands.
pub fn evaluate_split_root_candidate(
    input: &SplitRootCandidateInput,
) -> RouterAbDerivationResult<SplitRootCandidateOutput> {
    let _digest = transcript_binding_digest(&input.transcript)?;
    Err(RouterAbDerivationError::new(
        RouterAbDerivationErrorCode::NotImplemented,
        "split_root_derivation_v1 is gated on vectors and leakage analysis",
    ))
}

/// Creates a public output-share binding plan before secret derivation.
pub fn plan_split_root_output_share_v1(
    input: &SplitRootSignerInputV1,
    request: &SplitRootOutputRequestV1,
) -> RouterAbDerivationResult<SplitRootOutputShareBindingV1> {
    SplitRootOutputShareBindingV1::from_signer_input(input, request)
}

/// Derives one signer-local Candidate B output share from a split root.
pub fn derive_split_root_output_share_v1(
    input: &SplitRootSignerInputV1,
    request: &SplitRootOutputRequestV1,
    root_share: &SplitRootSecretShareV1,
) -> RouterAbDerivationResult<SplitRootSignerOutputShareV1> {
    input.validate()?;
    request.validate()?;
    if !input
        .output_requests
        .iter()
        .any(|candidate| candidate == request)
    {
        return Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::RecipientMismatch,
            "split-root output request is missing from signer input",
        ));
    }
    if root_share.signer_role() != input.signer_role {
        return Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::SignerIdentityMismatch,
            "split-root secret share signer role does not match signer input",
        ));
    }
    if root_share.root_share_epoch() != &input.root_share_epoch {
        return Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::RootEpochMismatch,
            "split-root secret share epoch does not match signer input",
        ));
    }

    let binding = SplitRootOutputShareBindingV1::from_signer_input(input, request)?;
    let share = derive_split_root_scalar_share_v1(root_share, &binding)?;
    SplitRootSignerOutputShareV1::new(
        binding,
        SplitRootOutputShareWireV1::new(share.to_bytes().to_vec())?,
    )
}

/// Combines two verified Candidate B output shares into recipient-local output.
pub fn combine_split_root_verified_output_shares_v1(
    input: SplitRootCombinerInputV1,
) -> RouterAbDerivationResult<SplitRootCombinedOutputV1> {
    let plan = plan_split_root_combine_v1(input.clone())?;
    let left = scalar_from_output_share_wire(
        input.left.signer_share.share_wire.as_bytes(),
        "left_split_root_output_share",
    )?;
    let right = scalar_from_output_share_wire(
        input.right.signer_share.share_wire.as_bytes(),
        "right_split_root_output_share",
    )?;
    let output = left + right;
    Ok(SplitRootCombinedOutputV1 {
        transcript_digest: plan.transcript_digest,
        opened_share_kind: plan.opened_share_kind,
        recipient_role: plan.recipient_role,
        recipient_identity: plan.recipient_identity,
        output_material: SecretMaterial32::new(output.to_bytes()),
    })
}

/// Validates two verified shares before recipient-side Candidate B combine.
pub fn plan_split_root_combine_v1(
    input: SplitRootCombinerInputV1,
) -> RouterAbDerivationResult<SplitRootCombinePlanV1> {
    input.transcript.validate()?;
    require_split_root_context(&input.transcript.context)?;
    SplitRootOutputRequestV1::new(
        input.opened_share_kind,
        input.recipient_role,
        input.recipient_identity.clone(),
    )?;

    let transcript_digest = transcript_digest_v1(&input.transcript)?;
    let left = &input.left.signer_share.binding;
    let right = &input.right.signer_share.binding;
    left.validate(&input.transcript)?;
    right.validate(&input.transcript)?;

    if left.signer_role == right.signer_role {
        return Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::DuplicateSignerIdentity,
            "split-root combine requires distinct signer roles",
        ));
    }

    for binding in [left, right] {
        if binding.opened_share_kind != input.opened_share_kind
            || binding.recipient_role != input.recipient_role
            || binding.recipient_identity != input.recipient_identity
        {
            return Err(RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::RecipientMismatch,
                "split-root combine input share recipient binding mismatch",
            ));
        }
    }

    Ok(SplitRootCombinePlanV1 {
        transcript_digest,
        opened_share_kind: input.opened_share_kind,
        recipient_role: input.recipient_role,
        recipient_identity: input.recipient_identity,
        signer_roles: [left.signer_role, right.signer_role],
    })
}

/// Plans Candidate B refresh semantics.
pub fn plan_split_root_refresh_v1(
    input: SplitRootRefreshPlanInputV1,
) -> RouterAbDerivationResult<SplitRootRefreshPlanV1> {
    input.refresh_scope.validate()?;
    Ok(SplitRootRefreshPlanV1 {
        old_root_share_epoch: input.refresh_scope.old_root_share_epoch,
        new_root_share_epoch: input.refresh_scope.new_root_share_epoch,
        refresh_mode: input.refresh_mode,
        preserves_existing_output_relation: false,
        activation_gate: "address_verification_required_before_epoch_activation".to_owned(),
    })
}

fn require_split_root_context(context: &DerivationContext) -> RouterAbDerivationResult<()> {
    if context.candidate_id != CandidateId::SplitRootDerivationV1 {
        return Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::UnsupportedCandidate,
            "split-root candidate input requires split_root_derivation_v1 context",
        ));
    }
    Ok(())
}

fn derive_split_root_scalar_share_v1(
    root_share: &SplitRootSecretShareV1,
    binding: &SplitRootOutputShareBindingV1,
) -> RouterAbDerivationResult<Scalar> {
    let mut transcript = Vec::new();
    push_len32(
        &mut transcript,
        binding.derivation_label.as_str().as_bytes(),
    );
    push_len32(&mut transcript, binding.suite_id.as_str().as_bytes());
    push_len32(&mut transcript, root_share.as_bytes());
    push_len32(&mut transcript, binding.transcript_digest.as_bytes());
    push_len32(
        &mut transcript,
        binding.opened_share_kind.as_str().as_bytes(),
    );
    push_len32(&mut transcript, binding.recipient_role.as_str().as_bytes());
    push_len32(&mut transcript, binding.recipient_identity.as_bytes());
    push_len32(&mut transcript, binding.signer_role.as_str().as_bytes());
    push_len32(&mut transcript, binding.signer_identity.as_bytes());
    push_len32(
        &mut transcript,
        binding.root_share_epoch.as_str().as_bytes(),
    );

    let digest = Sha512::digest(transcript);
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&digest);
    Ok(Scalar::from_bytes_mod_order_wide(&wide))
}

fn scalar_from_output_share_wire(
    bytes: &[u8],
    field: &'static str,
) -> RouterAbDerivationResult<Scalar> {
    let scalar_bytes: [u8; SPLIT_ROOT_OUTPUT_SHARE_WIRE_V1_LEN] =
        bytes.try_into().map_err(|_| {
            RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::MalformedInput,
                format!("{field} must be {SPLIT_ROOT_OUTPUT_SHARE_WIRE_V1_LEN} bytes"),
            )
        })?;
    Option::<Scalar>::from(Scalar::from_canonical_bytes(scalar_bytes)).ok_or_else(|| {
        RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::MalformedInput,
            format!("{field} must be canonical scalar bytes"),
        )
    })
}

fn push_len32(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn require_context_matches_transcript(
    context: &DerivationContext,
    transcript: &TranscriptBinding,
) -> RouterAbDerivationResult<()> {
    if context != &transcript.context {
        return Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::TranscriptMismatch,
            "split-root input context does not match transcript context",
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
    require_signer_role(role)?;

    let signer = transcript.signer_set.signer_for_role(role).ok_or_else(|| {
        RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::SignerIdentityMismatch,
            "split-root signer role is missing from transcript",
        )
    })?;
    if signer.signer_id != identity {
        return Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::SignerIdentityMismatch,
            "split-root signer identity does not match transcript",
        ));
    }
    Ok(())
}

fn require_signer_role(role: Role) -> RouterAbDerivationResult<()> {
    match role {
        Role::SignerA | Role::SignerB => Ok(()),
        _ => Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::SignerIdentityMismatch,
            "split-root signer role must be Signer A or Signer B",
        )),
    }
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
