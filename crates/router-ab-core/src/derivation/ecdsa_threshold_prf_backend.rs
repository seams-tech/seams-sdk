use core::fmt;

use rand_core::{CryptoRng, RngCore};
use subtle::ConstantTimeEq;
use threshold_prf::{
    combine_verified_partials, combine_verified_partials_bound_to_digest,
    evaluate_partial_with_dleq_proof, evaluate_partial_with_dleq_proof_bound_to_digest,
    verify_partial_dleq_proof, verify_partial_dleq_proof_bound_to_digest, PrfDleqProof,
    PrfPartialProofBundle as BackendProofBundle, PrfPartialWire as BackendPartialWire,
    SigningRootShareCommitment, SigningRootShareWire, ThresholdPolicy, TwoPartyDeriverRole,
    ValidatedThresholdSet,
};
use threshold_prf::{PrfContext, PrfOutputEncoding, PrfPurpose, SuiteId, ThresholdPrfError};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::derivation::ecdsa_threshold_prf::{
    plan_mpc_prf_combine_v1, plan_mpc_prf_partial_verification_v1,
    plan_mpc_prf_purpose_binding_for_output_v1, plan_mpc_prf_purpose_binding_v1,
    plan_mpc_prf_stable_purpose_binding_v2, MpcPrfCombinerInputV1, MpcPrfDleqProofWireV1,
    MpcPrfOutputPurposeV1, MpcPrfOutputRequestV1, MpcPrfPartialProofBundleV1,
    MpcPrfPartialVerificationInputV1, MpcPrfPartialWireV1, MpcPrfPurposeBindingPlanV1,
    MpcPrfShareCommitmentWireV1, MpcPrfSignerPartialInputV1, MpcPrfSignerPartialV1,
    MpcPrfStablePurposeBindingPlanV2, MpcPrfVerifiedPartialV1,
};
use crate::derivation::error::{
    RouterAbDerivationError, RouterAbDerivationErrorCode, RouterAbDerivationResult,
};
use crate::derivation::material::{OpenedShareKind, PublicDigest32, Role, SecretMaterial32};
use crate::derivation::transcript::TranscriptBinding;
use crate::derivation::{
    TenantRootActiveRootPairV1, TenantRootCustodyBindingV1, TenantRootManagedRestoreRoleV1,
    TenantRootProtocolDigestV1, VerifiedTenantRootOnlineRoleShareV1,
};
use crate::protocol::EcdsaThresholdPrfPrivateRequestV2;

/// Router/A/B signing-root share wire length for the threshold-prf backend.
pub const MPC_PRF_SIGNING_ROOT_SHARE_WIRE_V1_LEN: usize = 34;

fn fixed_threshold_policy_v1() -> RouterAbDerivationResult<ThresholdPolicy> {
    ThresholdPolicy::from_u16s(2, 2).map_err(map_threshold_error)
}

/// Signer-local secret signing-root-share wire. Debug output is always redacted.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MpcPrfSigningRootShareWireV1 {
    bytes: Vec<u8>,
}

impl MpcPrfSigningRootShareWireV1 {
    /// Creates a fixed-width signer-local share wire.
    pub fn new(bytes: Vec<u8>) -> RouterAbDerivationResult<Self> {
        let mut bytes = Zeroizing::new(bytes);
        if bytes.len() != MPC_PRF_SIGNING_ROOT_SHARE_WIRE_V1_LEN {
            return Err(RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::MalformedInput,
                "MPC PRF signing-root-share wire has invalid length",
            ));
        }
        require_fixed_share_id(u16::from_be_bytes([bytes[0], bytes[1]]))?;
        Ok(Self {
            bytes: core::mem::take(&mut *bytes),
        })
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
#[derive(Clone)]
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

/// Dormant Deriver input for stable-context, custody-bound threshold PRF.
pub struct MpcPrfStableThresholdSignerInputV2 {
    /// Stable PRF context and independent epoch-bound custody digest.
    purpose_plan: MpcPrfStablePurposeBindingPlanV2,
    /// Exact Deriver role holding the local share.
    signer_role: Role,
    /// Decrypted role-local tenant-root share.
    signing_root_share_wire: MpcPrfSigningRootShareWireV1,
}

impl MpcPrfStableThresholdSignerInputV2 {
    /// Creates a stable signer input from one fresh, authoritative custody tuple.
    pub fn new(
        purpose_plan: MpcPrfStablePurposeBindingPlanV2,
        custody_binding: &TenantRootCustodyBindingV1,
        active_pair: &TenantRootActiveRootPairV1,
        signer_role: Role,
        signing_root_share_wire: MpcPrfSigningRootShareWireV1,
        now_ms: u64,
    ) -> RouterAbDerivationResult<Self> {
        custody_binding.validate_at(now_ms)?;
        if purpose_plan.custody_binding_digest() != custody_binding.digest()? {
            return Err(RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::TranscriptMismatch,
                "stable MPC PRF purpose plan does not match custody binding",
            ));
        }
        validate_stable_active_pair_binding(active_pair, custody_binding)?;
        let expected_commitment = stable_share_commitment_for_role(active_pair, signer_role)?;

        let backend_share_wire =
            SigningRootShareWire::decode_slice(signing_root_share_wire.as_bytes())
                .map_err(map_threshold_error)?;
        let backend_share = backend_share_wire.to_share().map_err(map_threshold_error)?;
        require_backend_share_role(signer_role, backend_share.id().get().get())?;
        let opened_commitment = SigningRootShareCommitment::from_share(&backend_share);
        if !bool::from(
            opened_commitment
                .to_bytes()
                .as_ref()
                .ct_eq(expected_commitment.as_bytes()),
        ) {
            return Err(RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::OutputVerificationFailed,
                "stable MPC PRF opened share does not match its active commitment",
            ));
        }

        Ok(Self {
            purpose_plan,
            signer_role,
            signing_root_share_wire,
        })
    }

    /// Creates a stable signer input from one validated private request and
    /// the role-local share opened by the server's authenticated provider.
    pub fn from_private_request(
        request: &EcdsaThresholdPrfPrivateRequestV2,
        custody_binding: &TenantRootCustodyBindingV1,
        active_pair: &TenantRootActiveRootPairV1,
        verified_share: VerifiedTenantRootOnlineRoleShareV1,
        now_ms: u64,
    ) -> RouterAbDerivationResult<Self> {
        request
            .validate_for_custody(custody_binding, now_ms)
            .map_err(map_protocol_error)?;
        let purpose_plan = plan_mpc_prf_stable_purpose_binding_v2(
            request.stable_context(),
            custody_binding,
            request.purpose().threshold_prf_purpose(),
        )?;
        Self::from_verified_online_role_share(
            purpose_plan,
            custody_binding,
            active_pair,
            verified_share,
            now_ms,
        )
    }

    /// Creates a stable signer input from one server-authenticated role share.
    ///
    /// The verified share supplies the Deriver role and all epoch-bound
    /// coordinates. Callers provide no role, identity, lineage, or epoch.
    pub fn from_verified_online_role_share(
        purpose_plan: MpcPrfStablePurposeBindingPlanV2,
        custody_binding: &TenantRootCustodyBindingV1,
        active_pair: &TenantRootActiveRootPairV1,
        verified_share: VerifiedTenantRootOnlineRoleShareV1,
        now_ms: u64,
    ) -> RouterAbDerivationResult<Self> {
        custody_binding.validate_at(now_ms)?;
        if verified_share.identity_digest() != custody_binding.identity_digest()
            || verified_share.custody_lineage() != custody_binding.custody_lineage()
            || verified_share.epoch() != custody_binding.epoch()
        {
            return Err(RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::MismatchedActiveTenantRootPair,
                "stable MPC PRF opened share does not match custody binding",
            ));
        }
        let signer_role = role_from_tenant_root_share(verified_share.role());
        let expected_commitment = stable_share_commitment_for_role(active_pair, signer_role)?;
        if verified_share.share_commitment() != expected_commitment {
            return Err(RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::OutputVerificationFailed,
                "stable MPC PRF opened share commitment does not match its active pair",
            ));
        }
        let (_, share_wire) = verified_share.into_parts();
        let signing_root_share_wire =
            MpcPrfSigningRootShareWireV1::new(share_wire.to_bytes().to_vec())?;
        Self::new(
            purpose_plan,
            custody_binding,
            active_pair,
            signer_role,
            signing_root_share_wire,
            now_ms,
        )
    }
}

impl fmt::Debug for MpcPrfStableThresholdSignerInputV2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MpcPrfStableThresholdSignerInputV2")
            .field("purpose_plan", &self.purpose_plan)
            .field("signer_role", &self.signer_role)
            .field("signing_root_share_wire", &"[redacted]")
            .finish()
    }
}

/// Stable-context partial whose proof is bound to one custody record digest.
#[derive(Clone, PartialEq, Eq)]
pub struct MpcPrfStablePartialProofBundleV2 {
    /// Exact public purpose and context plan used for this partial.
    pub purpose_plan: MpcPrfStablePurposeBindingPlanV2,
    /// Deriver role that produced the partial.
    pub signer_role: Role,
    /// Canonical threshold-PRF partial wire.
    pub partial_wire: MpcPrfPartialWireV1,
    /// Public commitment to the role-local tenant-root share.
    pub commitment_wire: MpcPrfShareCommitmentWireV1,
    /// DLEQ proof bound to the plan's custody digest.
    pub proof_wire: MpcPrfDleqProofWireV1,
}

impl fmt::Debug for MpcPrfStablePartialProofBundleV2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MpcPrfStablePartialProofBundleV2")
            .field("purpose_plan", &self.purpose_plan)
            .field("signer_role", &self.signer_role)
            .field("partial_wire", &"[redacted]")
            .field("commitment_wire", &self.commitment_wire)
            .field("proof_wire", &"[redacted]")
            .finish()
    }
}

/// Recipient input for verifying and combining stable-context A/B partials.
#[derive(Clone, PartialEq, Eq)]
pub struct MpcPrfStableThresholdCombineInputV2 {
    /// Expected stable context and authenticated custody binding.
    pub purpose_plan: MpcPrfStablePurposeBindingPlanV2,
    /// First Deriver proof bundle.
    pub left: MpcPrfStablePartialProofBundleV2,
    /// Second Deriver proof bundle.
    pub right: MpcPrfStablePartialProofBundleV2,
}

/// Combined stable threshold-PRF output with public binding digests.
#[derive(Clone)]
pub struct MpcPrfStableThresholdCombinedOutputV2 {
    /// Digest of the exact stable PRF bytes.
    pub stable_context_digest: TenantRootProtocolDigestV1,
    /// Digest of the separately authenticated custody record.
    pub custody_binding_digest: TenantRootProtocolDigestV1,
    /// Combined secret output material.
    pub output_material: SecretMaterial32,
}

impl fmt::Debug for MpcPrfStableThresholdCombinedOutputV2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MpcPrfStableThresholdCombinedOutputV2")
            .field("stable_context_digest", &self.stable_context_digest)
            .field("custody_binding_digest", &self.custody_binding_digest)
            .field("output_material", &"[redacted]")
            .finish()
    }
}

/// Deriver-side batch input for evaluating every requested ECDSA output.
#[derive(Clone)]
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
#[derive(Clone)]
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
#[derive(Clone)]
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

/// Evaluates one role-local tenant-root partial over stable PRF bytes.
pub fn evaluate_mpc_prf_stable_signer_partial_with_threshold_backend_v2<R>(
    input: MpcPrfStableThresholdSignerInputV2,
    proof_rng: &mut R,
) -> RouterAbDerivationResult<MpcPrfStablePartialProofBundleV2>
where
    R: RngCore + CryptoRng,
{
    let context = threshold_context_from_stable_plan_v2(&input.purpose_plan)?;
    let backend_share_wire =
        SigningRootShareWire::decode_slice(input.signing_root_share_wire.as_bytes())
            .map_err(map_threshold_error)?;
    let backend_share = backend_share_wire.to_share().map_err(map_threshold_error)?;
    require_backend_share_role(input.signer_role, backend_share.id().get().get())?;
    let backend_bundle = evaluate_partial_with_dleq_proof_bound_to_digest(
        &backend_share,
        &context,
        input.purpose_plan.custody_binding_digest().as_bytes(),
        proof_rng,
    )
    .map_err(map_threshold_error)?;

    Ok(MpcPrfStablePartialProofBundleV2 {
        purpose_plan: input.purpose_plan,
        signer_role: input.signer_role,
        partial_wire: MpcPrfPartialWireV1::new(
            BackendPartialWire::from_partial(&backend_bundle.partial)
                .to_bytes()
                .to_vec(),
        )?,
        commitment_wire: MpcPrfShareCommitmentWireV1::new(
            backend_bundle.commitment.to_bytes().to_vec(),
        )?,
        proof_wire: MpcPrfDleqProofWireV1::new(backend_bundle.proof.to_bytes().to_vec())?,
    })
}

/// Verifies one stable-context proof against the expected custody digest.
pub fn verify_mpc_prf_stable_partial_with_threshold_backend_v2(
    purpose_plan: &MpcPrfStablePurposeBindingPlanV2,
    bundle: &MpcPrfStablePartialProofBundleV2,
) -> RouterAbDerivationResult<()> {
    if &bundle.purpose_plan != purpose_plan {
        return Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::TranscriptMismatch,
            "stable MPC PRF partial purpose or custody binding mismatch",
        ));
    }
    let context = threshold_context_from_stable_plan_v2(purpose_plan)?;
    let backend_bundle = backend_bundle_from_stable_bundle_v2(bundle)?;
    require_backend_share_role(bundle.signer_role, backend_bundle.partial.id().get().get())?;
    verify_partial_dleq_proof_bound_to_digest(
        &backend_bundle.commitment,
        &backend_bundle.partial,
        &context,
        purpose_plan.custody_binding_digest().as_bytes(),
        &backend_bundle.proof,
    )
    .map_err(map_threshold_error)
}

/// Verifies and combines exact A/B stable-context proof bundles.
pub fn combine_mpc_prf_stable_proof_bundles_with_threshold_backend_v2(
    input: MpcPrfStableThresholdCombineInputV2,
) -> RouterAbDerivationResult<MpcPrfStableThresholdCombinedOutputV2> {
    verify_mpc_prf_stable_partial_with_threshold_backend_v2(&input.purpose_plan, &input.left)?;
    verify_mpc_prf_stable_partial_with_threshold_backend_v2(&input.purpose_plan, &input.right)?;
    if input.left.signer_role == input.right.signer_role {
        return Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::DuplicateSignerIdentity,
            "stable MPC PRF combine requires distinct Deriver roles",
        ));
    }
    let context = threshold_context_from_stable_plan_v2(&input.purpose_plan)?;
    let left = backend_bundle_from_stable_bundle_v2(&input.left)?;
    let right = backend_bundle_from_stable_bundle_v2(&input.right)?;
    let bundles =
        ValidatedThresholdSet::from_proof_bundles(fixed_threshold_policy_v1()?, vec![left, right])
            .map_err(map_threshold_error)?;
    let output = combine_verified_partials_bound_to_digest(
        &bundles,
        &context,
        input.purpose_plan.custody_binding_digest().as_bytes(),
    )
    .map_err(map_threshold_error)?;

    Ok(MpcPrfStableThresholdCombinedOutputV2 {
        stable_context_digest: input.purpose_plan.stable_context_digest(),
        custody_binding_digest: input.purpose_plan.custody_binding_digest(),
        output_material: SecretMaterial32::new(output.into_bytes()),
    })
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

fn backend_bundle_from_stable_bundle_v2(
    bundle: &MpcPrfStablePartialProofBundleV2,
) -> RouterAbDerivationResult<BackendProofBundle> {
    let partial = BackendPartialWire::decode_slice(bundle.partial_wire.as_bytes())
        .and_then(|wire| wire.to_partial())
        .map_err(map_threshold_error)?;
    let commitment = SigningRootShareCommitment::from_slice(bundle.commitment_wire.as_bytes())
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

fn validate_stable_active_pair_binding(
    active_pair: &TenantRootActiveRootPairV1,
    custody_binding: &TenantRootCustodyBindingV1,
) -> RouterAbDerivationResult<()> {
    if active_pair.identity_digest() != custody_binding.identity_digest()
        || active_pair.custody_lineage() != custody_binding.custody_lineage()
        || active_pair.epoch() != custody_binding.epoch()
        || active_pair.commitments() != custody_binding.commitments()
    {
        return Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::MismatchedActiveTenantRootPair,
            "stable MPC PRF active root pair does not match custody binding",
        ));
    }
    let expected_receipt = custody_binding.activation_receipt_digest();
    if active_pair.deriver_a().activation_receipt_digest() != expected_receipt
        || active_pair.deriver_b().activation_receipt_digest() != expected_receipt
    {
        return Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::MismatchedActiveTenantRootPair,
            "stable MPC PRF active root pair receipt does not match custody binding",
        ));
    }
    Ok(())
}

fn stable_share_commitment_for_role(
    active_pair: &TenantRootActiveRootPairV1,
    signer_role: Role,
) -> RouterAbDerivationResult<&MpcPrfShareCommitmentWireV1> {
    match signer_role {
        Role::SignerA => {
            if active_pair.deriver_a().role() != TenantRootManagedRestoreRoleV1::DeriverA {
                return Err(RouterAbDerivationError::new(
                    RouterAbDerivationErrorCode::SignerIdentityMismatch,
                    "stable MPC PRF active pair Deriver A role mapping is invalid",
                ));
            }
            Ok(active_pair.commitments().deriver_a())
        }
        Role::SignerB => {
            if active_pair.deriver_b().role() != TenantRootManagedRestoreRoleV1::DeriverB {
                return Err(RouterAbDerivationError::new(
                    RouterAbDerivationErrorCode::SignerIdentityMismatch,
                    "stable MPC PRF active pair Deriver B role mapping is invalid",
                ));
            }
            Ok(active_pair.commitments().deriver_b())
        }
        _ => Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::SignerIdentityMismatch,
            "stable MPC PRF signer input requires a Deriver role",
        )),
    }
}

fn role_from_tenant_root_share(role: TwoPartyDeriverRole) -> Role {
    match role {
        TwoPartyDeriverRole::DeriverA => Role::SignerA,
        TwoPartyDeriverRole::DeriverB => Role::SignerB,
    }
}

fn map_protocol_error(error: crate::protocol::RouterAbProtocolError) -> RouterAbDerivationError {
    RouterAbDerivationError::new(
        RouterAbDerivationErrorCode::MalformedInput,
        format!("ECDSA threshold-PRF V2 request was rejected: {error}"),
    )
}

fn threshold_context_from_stable_plan_v2(
    plan: &MpcPrfStablePurposeBindingPlanV2,
) -> RouterAbDerivationResult<PrfContext> {
    if matches!(
        plan.purpose(),
        PrfPurpose::Ed25519DeriverAContributionRoot | PrfPurpose::Ed25519DeriverBContributionRoot
    ) {
        return Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::MalformedInput,
            "stable ECDSA MPC PRF backend received an Ed25519 purpose",
        ));
    }
    Ok(PrfContext::new(
        SuiteId::Ristretto255Sha512,
        plan.purpose().clone(),
        plan.threshold_prf_context_bytes().to_vec(),
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
        ThresholdPrfError::RefreshContinuityMismatch
        | ThresholdPrfError::InvalidKnowledgeProof
        | ThresholdPrfError::UnexpectedPeerCommitment => {
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
        | ThresholdPrfError::InvalidDleqProofEncoding
        | ThresholdPrfError::InvalidRefreshRole
        | ThresholdPrfError::InvalidRefreshContribution
        | ThresholdPrfError::RefreshNoOp
        | ThresholdPrfError::InvalidRootCommitment
        | ThresholdPrfError::InvalidKnowledgeProofEncoding => {
            RouterAbDerivationErrorCode::MalformedInput
        }
    };
    RouterAbDerivationError::new(
        code,
        format!("threshold-prf backend rejected input: {error}"),
    )
}
