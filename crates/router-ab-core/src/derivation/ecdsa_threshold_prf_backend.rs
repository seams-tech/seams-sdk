use core::fmt;

use rand_core::{CryptoRng, RngCore};
use threshold_prf::{
    combine_verified_partials, evaluate_partial_with_dleq_proof, verify_partial_dleq_proof,
    PrfDleqProof, PrfPartialProofBundle as BackendProofBundle,
    PrfPartialWire as BackendPartialWire, SigningRootShareCommitment, SigningRootShareWire,
    ThresholdPolicy, ValidatedThresholdSet,
};
use threshold_prf::{PrfContext, PrfOutputEncoding, PrfPurpose, SuiteId, ThresholdPrfError};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::derivation::ecdsa_threshold_prf::{
    plan_mpc_prf_combine_v1, plan_mpc_prf_partial_verification_v1,
    plan_mpc_prf_purpose_binding_for_output_v1, plan_mpc_prf_purpose_binding_v1,
    MpcPrfCombinerInputV1, MpcPrfDleqProofWireV1, MpcPrfOutputPurposeV1, MpcPrfOutputRequestV1,
    MpcPrfPartialProofBundleV1, MpcPrfPartialVerificationInputV1, MpcPrfPartialWireV1,
    MpcPrfPurposeBindingPlanV1, MpcPrfShareCommitmentWireV1, MpcPrfSignerPartialInputV1,
    MpcPrfSignerPartialV1, MpcPrfVerifiedPartialV1,
};
use crate::derivation::error::{
    RouterAbDerivationError, RouterAbDerivationErrorCode, RouterAbDerivationResult,
};
use crate::derivation::material::{OpenedShareKind, PublicDigest32, Role, SecretMaterial32};
use crate::derivation::transcript::TranscriptBinding;

/// Router/A/B signing-root share wire length for the threshold-prf backend.
pub const MPC_PRF_SIGNING_ROOT_SHARE_WIRE_V1_LEN: usize = 34;

fn fixed_threshold_policy_v1() -> RouterAbDerivationResult<ThresholdPolicy> {
    ThresholdPolicy::from_u16s(2, 2).map_err(map_threshold_error)
}

/// Signer-local secret signing-root-share wire. Debug output is always redacted.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct MpcPrfSigningRootShareWireV1 {
    bytes: Vec<u8>,
}

impl MpcPrfSigningRootShareWireV1 {
    /// Creates a fixed-width signer-local share wire.
    pub fn new(bytes: Vec<u8>) -> RouterAbDerivationResult<Self> {
        if bytes.len() != MPC_PRF_SIGNING_ROOT_SHARE_WIRE_V1_LEN {
            return Err(RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::MalformedInput,
                "MPC PRF signing-root-share wire has invalid length",
            ));
        }
        require_fixed_share_id(u16::from_be_bytes([bytes[0], bytes[1]]))?;
        Ok(Self { bytes })
    }

    /// Returns the fixed public share identifier encoded by the wire.
    pub fn share_id(&self) -> u16 {
        u16::from_be_bytes([self.bytes[0], self.bytes[1]])
    }

    /// Returns the signer-local share bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Debug for MpcPrfSigningRootShareWireV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MpcPrfSigningRootShareWireV1([redacted])")
    }
}

/// Deriver-side production backend input for the fixed ECDSA threshold PRF.
#[derive(Clone, PartialEq, Eq)]
pub struct MpcPrfThresholdSignerInputV1 {
    /// Public signer metadata and requested outputs.
    pub signer_input: MpcPrfSignerPartialInputV1,
    /// Single output request to evaluate.
    pub output_request: MpcPrfOutputRequestV1,
    /// Decrypted signer-local signing-root share.
    pub signing_root_share_wire: MpcPrfSigningRootShareWireV1,
}

impl fmt::Debug for MpcPrfThresholdSignerInputV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MpcPrfThresholdSignerInputV1")
            .field("signer_input", &self.signer_input)
            .field("output_request", &self.output_request)
            .field("signing_root_share_wire", &"[redacted]")
            .finish()
    }
}

/// Deriver-side batch input for evaluating every requested ECDSA output.
#[derive(Clone, PartialEq, Eq)]
pub struct MpcPrfThresholdSignerBatchInputV1 {
    /// Public signer metadata and requested outputs.
    pub signer_input: MpcPrfSignerPartialInputV1,
    /// Decrypted signer-local signing-root share.
    pub signing_root_share_wire: MpcPrfSigningRootShareWireV1,
}

impl fmt::Debug for MpcPrfThresholdSignerBatchInputV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MpcPrfThresholdSignerBatchInputV1")
            .field("signer_input", &self.signer_input)
            .field("signing_root_share_wire", &"[redacted]")
            .finish()
    }
}

/// Signer-side batch output containing one proof bundle per requested output.
#[derive(Clone, PartialEq, Eq)]
pub struct MpcPrfThresholdSignerBatchOutputV1 {
    /// Transcript digest shared by every proof bundle.
    pub transcript_digest: PublicDigest32,
    /// Signer role that produced every proof bundle.
    pub signer_role: Role,
    /// Canonical signer identity.
    pub signer_identity: String,
    /// Root-share epoch used by the signer.
    pub root_share_epoch: crate::derivation::context::RootShareEpoch,
    /// Proof bundles in signer-input output request order.
    pub proof_bundles: Vec<MpcPrfPartialProofBundleV1>,
}

impl fmt::Debug for MpcPrfThresholdSignerBatchOutputV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MpcPrfThresholdSignerBatchOutputV1")
            .field("transcript_digest", &self.transcript_digest)
            .field("signer_role", &self.signer_role)
            .field("signer_identity", &self.signer_identity)
            .field("root_share_epoch", &self.root_share_epoch)
            .field("proof_bundle_count", &self.proof_bundles.len())
            .finish()
    }
}

/// Recipient-side production backend input for ECDSA threshold-PRF combination.
#[derive(Clone, PartialEq, Eq)]
pub struct MpcPrfThresholdCombineInputV1 {
    /// Transcript binding for the output.
    pub transcript: TranscriptBinding,
    /// Opened share kind being combined.
    pub opened_share_kind: OpenedShareKind,
    /// Recipient role.
    pub recipient_role: Role,
    /// Recipient identity.
    pub recipient_identity: String,
    /// First signer proof bundle.
    pub left: MpcPrfPartialProofBundleV1,
    /// Second signer proof bundle.
    pub right: MpcPrfPartialProofBundleV1,
}

/// Recipient-side batch combine input for matching A/B proof bundles.
#[derive(Clone, PartialEq, Eq)]
pub struct MpcPrfThresholdBatchCombineInputV1 {
    /// Transcript binding for every output.
    pub transcript: TranscriptBinding,
    /// First signer batch output.
    pub left: MpcPrfThresholdSignerBatchOutputV1,
    /// Second signer batch output.
    pub right: MpcPrfThresholdSignerBatchOutputV1,
}

/// Recipient-local combined batch output. Debug output redacts material.
#[derive(Clone, PartialEq, Eq)]
pub struct MpcPrfThresholdBatchCombinedOutputV1 {
    /// Transcript digest shared by every combined output.
    pub transcript_digest: PublicDigest32,
    /// Combined outputs in left batch order.
    pub outputs: Vec<MpcPrfThresholdCombinedOutputV1>,
}

impl fmt::Debug for MpcPrfThresholdBatchCombinedOutputV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MpcPrfThresholdBatchCombinedOutputV1")
            .field("transcript_digest", &self.transcript_digest)
            .field("output_count", &self.outputs.len())
            .finish()
    }
}

/// Recipient-local combined ECDSA threshold-PRF output. Debug output redacts material.
#[derive(Clone, PartialEq, Eq)]
pub struct MpcPrfThresholdCombinedOutputV1 {
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

impl fmt::Debug for MpcPrfThresholdCombinedOutputV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MpcPrfThresholdCombinedOutputV1")
            .field("transcript_digest", &self.transcript_digest)
            .field("opened_share_kind", &self.opened_share_kind)
            .field("recipient_role", &self.recipient_role)
            .field("recipient_identity", &self.recipient_identity)
            .field("output_material", &"[redacted]")
            .finish()
    }
}

/// Evaluates one Deriver-local partial through `threshold-prf`.
pub fn evaluate_mpc_prf_signer_partial_with_threshold_backend_v1<R>(
    input: MpcPrfThresholdSignerInputV1,
    proof_rng: &mut R,
) -> RouterAbDerivationResult<MpcPrfPartialProofBundleV1>
where
    R: RngCore + CryptoRng,
{
    input.signer_input.validate()?;
    input.output_request.validate()?;
    let purpose_plan = plan_mpc_prf_purpose_binding_v1(&input.signer_input, &input.output_request)?;
    let context = threshold_context_from_plan_v1(&purpose_plan)?;
    let backend_share_wire =
        SigningRootShareWire::decode_slice(input.signing_root_share_wire.as_bytes())
            .map_err(map_threshold_error)?;
    let backend_share = backend_share_wire.to_share().map_err(map_threshold_error)?;
    require_backend_share_role(
        input.signer_input.signer_role,
        backend_share.id().get().get(),
    )?;

    let backend_bundle = evaluate_partial_with_dleq_proof(&backend_share, &context, proof_rng)
        .map_err(map_threshold_error)?;
    let binding =
        crate::derivation::ecdsa_threshold_prf::MpcPrfPartialBindingV1::from_signer_input(
            &input.signer_input,
            &input.output_request,
        )?;
    let signer_partial = MpcPrfSignerPartialV1::new(
        binding,
        MpcPrfPartialWireV1::new(
            BackendPartialWire::from_partial(&backend_bundle.partial)
                .to_bytes()
                .to_vec(),
        )?,
    )?;
    MpcPrfPartialProofBundleV1::new(
        signer_partial,
        MpcPrfShareCommitmentWireV1::new(backend_bundle.commitment.to_bytes().to_vec())?,
        MpcPrfDleqProofWireV1::new(backend_bundle.proof.to_bytes().to_vec())?,
    )
}

/// Evaluates every requested Deriver-local ECDSA output through `threshold-prf`.
pub fn evaluate_mpc_prf_signer_output_batch_with_threshold_backend_v1<R>(
    input: MpcPrfThresholdSignerBatchInputV1,
    proof_rng: &mut R,
) -> RouterAbDerivationResult<MpcPrfThresholdSignerBatchOutputV1>
where
    R: RngCore + CryptoRng,
{
    input.signer_input.validate()?;
    require_unique_output_requests(&input.signer_input.output_requests)?;
    let transcript_digest =
        crate::derivation::transcript::transcript_digest_v1(&input.signer_input.transcript)?;
    let mut proof_bundles = Vec::with_capacity(input.signer_input.output_requests.len());
    for output_request in input.signer_input.output_requests.clone() {
        proof_bundles.push(evaluate_mpc_prf_signer_partial_with_threshold_backend_v1(
            MpcPrfThresholdSignerInputV1 {
                signer_input: input.signer_input.clone(),
                output_request,
                signing_root_share_wire: input.signing_root_share_wire.clone(),
            },
            proof_rng,
        )?);
    }

    Ok(MpcPrfThresholdSignerBatchOutputV1 {
        transcript_digest,
        signer_role: input.signer_input.signer_role,
        signer_identity: input.signer_input.signer_identity,
        root_share_epoch: input.signer_input.root_share_epoch,
        proof_bundles,
    })
}

/// Verifies one ECDSA threshold-PRF proof bundle.
pub fn verify_mpc_prf_partial_with_threshold_backend_v1(
    input: MpcPrfPartialVerificationInputV1,
) -> RouterAbDerivationResult<MpcPrfVerifiedPartialV1> {
    let plan = plan_mpc_prf_partial_verification_v1(input.clone())?;
    let request = MpcPrfOutputRequestV1::new(
        plan.opened_share_kind,
        plan.recipient_role,
        plan.recipient_identity.clone(),
    )?;
    let purpose_plan = plan_mpc_prf_purpose_binding_for_output_v1(&input.transcript, &request)?;
    let context = threshold_context_from_plan_v1(&purpose_plan)?;
    let backend_bundle = backend_bundle_from_router_bundle_v1(
        &input.proof_bundle,
        &input.proof_bundle.commitment_wire,
    )?;
    require_backend_share_role(plan.signer_role, backend_bundle.partial.id().get().get())?;
    verify_partial_dleq_proof(
        &backend_bundle.commitment,
        &backend_bundle.partial,
        &context,
        &backend_bundle.proof,
    )
    .map_err(map_threshold_error)?;

    MpcPrfVerifiedPartialV1::from_verified_parts(
        input.proof_bundle.signer_partial,
        input.proof_bundle.commitment_wire,
    )
}

/// Verifies two ECDSA threshold-PRF proof bundles and combines them for the recipient.
pub fn combine_mpc_prf_proof_bundles_with_threshold_backend_v1(
    input: MpcPrfThresholdCombineInputV1,
) -> RouterAbDerivationResult<MpcPrfThresholdCombinedOutputV1> {
    let left_verified =
        verify_mpc_prf_partial_with_threshold_backend_v1(MpcPrfPartialVerificationInputV1 {
            transcript: input.transcript.clone(),
            proof_bundle: input.left.clone(),
        })?;
    let right_verified =
        verify_mpc_prf_partial_with_threshold_backend_v1(MpcPrfPartialVerificationInputV1 {
            transcript: input.transcript.clone(),
            proof_bundle: input.right.clone(),
        })?;
    let plan = plan_mpc_prf_combine_v1(MpcPrfCombinerInputV1 {
        transcript: input.transcript.clone(),
        opened_share_kind: input.opened_share_kind,
        recipient_role: input.recipient_role,
        recipient_identity: input.recipient_identity.clone(),
        left: left_verified,
        right: right_verified,
    })?;
    let request = MpcPrfOutputRequestV1::new(
        plan.opened_share_kind,
        plan.recipient_role,
        plan.recipient_identity.clone(),
    )?;
    let purpose_plan = plan_mpc_prf_purpose_binding_for_output_v1(&input.transcript, &request)?;
    let context = threshold_context_from_plan_v1(&purpose_plan)?;
    let left_backend =
        backend_bundle_from_router_bundle_v1(&input.left, &input.left.commitment_wire)?;
    let right_backend =
        backend_bundle_from_router_bundle_v1(&input.right, &input.right.commitment_wire)?;
    let policy = fixed_threshold_policy_v1()?;
    let backend_bundles =
        ValidatedThresholdSet::from_proof_bundles(policy, vec![left_backend, right_backend])
            .map_err(map_threshold_error)?;
    let output =
        combine_verified_partials(&backend_bundles, &context).map_err(map_threshold_error)?;

    Ok(MpcPrfThresholdCombinedOutputV1 {
        transcript_digest: plan.transcript_digest,
        opened_share_kind: plan.opened_share_kind,
        recipient_role: plan.recipient_role,
        recipient_identity: plan.recipient_identity,
        output_material: SecretMaterial32::new(output.into_bytes()),
    })
}

/// Verifies and combines every matching output in two signer proof batches.
pub fn combine_mpc_prf_batch_outputs_with_threshold_backend_v1(
    input: MpcPrfThresholdBatchCombineInputV1,
) -> RouterAbDerivationResult<MpcPrfThresholdBatchCombinedOutputV1> {
    input.transcript.validate()?;
    let transcript_digest = crate::derivation::transcript::transcript_digest_v1(&input.transcript)?;
    validate_batch_metadata("left", &input.left, transcript_digest)?;
    validate_batch_metadata("right", &input.right, transcript_digest)?;
    if input.left.signer_role == input.right.signer_role {
        return Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::DuplicateSignerIdentity,
            "MPC PRF batch combine requires distinct signer roles",
        ));
    }
    let mut matched_right = vec![false; input.right.proof_bundles.len()];
    let mut outputs = Vec::with_capacity(input.left.proof_bundles.len());
    for left_bundle in &input.left.proof_bundles {
        let left_binding = &left_bundle.signer_partial.binding;
        let mut matching_index = None;
        for (right_index, right_bundle) in input.right.proof_bundles.iter().enumerate() {
            let right_binding = &right_bundle.signer_partial.binding;
            if left_binding.opened_share_kind == right_binding.opened_share_kind
                && left_binding.recipient_role == right_binding.recipient_role
                && left_binding.recipient_identity == right_binding.recipient_identity
            {
                if matching_index.is_some() || matched_right[right_index] {
                    return Err(RouterAbDerivationError::new(
                        RouterAbDerivationErrorCode::MalformedInput,
                        "MPC PRF batch combine found duplicate output binding",
                    ));
                }
                matching_index = Some(right_index);
            }
        }
        let right_index = matching_index.ok_or_else(|| {
            RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::RecipientMismatch,
                "MPC PRF batch combine is missing matching peer output binding",
            )
        })?;
        matched_right[right_index] = true;
        let right_bundle = input.right.proof_bundles[right_index].clone();
        outputs.push(combine_mpc_prf_proof_bundles_with_threshold_backend_v1(
            MpcPrfThresholdCombineInputV1 {
                transcript: input.transcript.clone(),
                opened_share_kind: left_binding.opened_share_kind,
                recipient_role: left_binding.recipient_role,
                recipient_identity: left_binding.recipient_identity.clone(),
                left: left_bundle.clone(),
                right: right_bundle,
            },
        )?);
    }
    if matched_right.iter().any(|matched| !matched) {
        return Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::RecipientMismatch,
            "MPC PRF batch combine found unmatched peer output binding",
        ));
    }
    Ok(MpcPrfThresholdBatchCombinedOutputV1 {
        transcript_digest,
        outputs,
    })
}

fn backend_bundle_from_router_bundle_v1(
    bundle: &MpcPrfPartialProofBundleV1,
    authenticated_commitment: &MpcPrfShareCommitmentWireV1,
) -> RouterAbDerivationResult<BackendProofBundle> {
    let partial = BackendPartialWire::decode_slice(bundle.signer_partial.partial_wire.as_bytes())
        .and_then(|wire| wire.to_partial())
        .map_err(map_threshold_error)?;
    let commitment = SigningRootShareCommitment::from_slice(authenticated_commitment.as_bytes())
        .map_err(map_threshold_error)?;
    let proof =
        PrfDleqProof::from_slice(bundle.proof_wire.as_bytes()).map_err(map_threshold_error)?;
    Ok(BackendProofBundle {
        partial,
        commitment,
        proof,
    })
}

fn threshold_context_from_plan_v1(
    plan: &MpcPrfPurposeBindingPlanV1,
) -> RouterAbDerivationResult<PrfContext> {
    let purpose = threshold_purpose_v1(plan.output_purpose)?;
    if plan.threshold_prf_purpose_label.as_bytes() != purpose.as_bytes()
        || purpose.output_encoding() != PrfOutputEncoding::CanonicalEd25519Scalar32
    {
        return Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::MalformedInput,
            "MPC PRF backend purpose binding mismatch",
        ));
    }

    Ok(PrfContext::new(
        SuiteId::Ristretto255Sha512,
        purpose,
        plan.threshold_prf_context_bytes.clone(),
    ))
}

fn threshold_purpose_v1(purpose: MpcPrfOutputPurposeV1) -> RouterAbDerivationResult<PrfPurpose> {
    match purpose {
        MpcPrfOutputPurposeV1::RouterAbXClientBase => Ok(PrfPurpose::RouterAbXClientBaseV1),
        MpcPrfOutputPurposeV1::RouterAbXServerBase => Ok(PrfPurpose::RouterAbXServerBaseV1),
    }
}

fn require_backend_share_role(role: Role, share_id: u16) -> RouterAbDerivationResult<()> {
    let expected = match role {
        Role::SignerA => 1,
        Role::SignerB => 2,
        _ => {
            return Err(RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::SignerIdentityMismatch,
                "MPC PRF backend requires a signer role",
            ));
        }
    };
    if share_id != expected {
        return Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::SignerIdentityMismatch,
            "MPC PRF backend share id does not match signer role",
        ));
    }
    Ok(())
}

fn require_fixed_share_id(share_id: u16) -> RouterAbDerivationResult<()> {
    if matches!(share_id, 1 | 2) {
        return Ok(());
    }
    Err(RouterAbDerivationError::new(
        RouterAbDerivationErrorCode::MalformedInput,
        "ECDSA threshold-PRF share id must be 1 or 2",
    ))
}

fn validate_batch_metadata(
    field: &'static str,
    batch: &MpcPrfThresholdSignerBatchOutputV1,
    transcript_digest: PublicDigest32,
) -> RouterAbDerivationResult<()> {
    if batch.transcript_digest != transcript_digest {
        return Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::TranscriptMismatch,
            format!("MPC PRF {field} batch transcript digest mismatch"),
        ));
    }
    if batch.proof_bundles.is_empty() {
        return Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::MalformedInput,
            format!("MPC PRF {field} batch requires at least one proof bundle"),
        ));
    }
    for (index, bundle) in batch.proof_bundles.iter().enumerate() {
        let backend_partial =
            BackendPartialWire::decode_slice(bundle.signer_partial.partial_wire.as_bytes())
                .and_then(|wire| wire.to_partial())
                .map_err(map_threshold_error)?;
        require_backend_share_role(batch.signer_role, backend_partial.id().get().get())?;
        let binding = &bundle.signer_partial.binding;
        if binding.transcript_digest != batch.transcript_digest {
            return Err(RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::TranscriptMismatch,
                format!("MPC PRF {field} batch proof transcript mismatch"),
            ));
        }
        if binding.signer_role != batch.signer_role
            || binding.signer_identity != batch.signer_identity
        {
            return Err(RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::SignerIdentityMismatch,
                format!("MPC PRF {field} batch proof signer mismatch"),
            ));
        }
        if binding.root_share_epoch != batch.root_share_epoch {
            return Err(RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::RootEpochMismatch,
                format!("MPC PRF {field} batch proof root epoch mismatch"),
            ));
        }
        for prior in &batch.proof_bundles[..index] {
            let prior_binding = &prior.signer_partial.binding;
            if prior_binding.opened_share_kind == binding.opened_share_kind
                && prior_binding.recipient_role == binding.recipient_role
                && prior_binding.recipient_identity == binding.recipient_identity
            {
                return Err(RouterAbDerivationError::new(
                    RouterAbDerivationErrorCode::MalformedInput,
                    format!("MPC PRF {field} batch contains duplicate output binding"),
                ));
            }
        }
    }
    Ok(())
}

fn require_unique_output_requests(
    output_requests: &[MpcPrfOutputRequestV1],
) -> RouterAbDerivationResult<()> {
    for (index, request) in output_requests.iter().enumerate() {
        for prior in &output_requests[..index] {
            if prior == request {
                return Err(RouterAbDerivationError::new(
                    RouterAbDerivationErrorCode::MalformedInput,
                    "MPC PRF signer batch requires unique output requests",
                ));
            }
        }
    }
    Ok(())
}

fn map_threshold_error(error: ThresholdPrfError) -> RouterAbDerivationError {
    let code = match error {
        ThresholdPrfError::DuplicateShareId => RouterAbDerivationErrorCode::DuplicateSignerIdentity,
        ThresholdPrfError::ContextMismatch => RouterAbDerivationErrorCode::TranscriptMismatch,
        ThresholdPrfError::InvalidDleqProof => {
            RouterAbDerivationErrorCode::OutputVerificationFailed
        }
        ThresholdPrfError::InvalidScalarEncoding
        | ThresholdPrfError::InvalidPointEncoding
        | ThresholdPrfError::InvalidPartialEncoding
        | ThresholdPrfError::InvalidShareEncoding
        | ThresholdPrfError::ZeroScalar
        | ThresholdPrfError::InvalidShareId
        | ThresholdPrfError::InvalidThresholdSubset
        | ThresholdPrfError::TranscriptLengthOverflow
        | ThresholdPrfError::InvalidCommitmentEncoding
        | ThresholdPrfError::InvalidDleqProofEncoding => {
            RouterAbDerivationErrorCode::MalformedInput
        }
    };
    RouterAbDerivationError::new(
        code,
        format!("threshold-prf backend rejected input: {error}"),
    )
}
