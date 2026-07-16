#![forbid(unsafe_code)]
//! Fixed ECDSA threshold-PRF derivation for the Router/A/B signer architecture.
//!
//! The crate is intentionally scoped to derivation and transcript-bound output
//! material. Router, signer, and server networking lives in adapters around
//! this crate.

mod context;
mod diagnostics;
mod ecdsa_commitment_registry;
mod ecdsa_threshold_prf;
mod ecdsa_threshold_prf_backend;
mod error;
mod leakage;
mod material;
mod scope;
mod signer_plaintext;
mod transcript;
mod wire;

pub use self::context::{
    context_digest_v1, AccountScope, DerivationContext, RequestKind, RootShareEpoch,
};
pub use self::diagnostics::redacted_diagnostic;
pub use self::ecdsa_commitment_registry::{
    AuthenticatedRootShareCommitmentV1, RootShareCommitmentRegistryV1,
};
pub use self::ecdsa_threshold_prf::{
    plan_mpc_prf_combine_v1, plan_mpc_prf_partial_verification_v1, plan_mpc_prf_purpose_binding_v1,
    MpcPrfCombinePlanV1, MpcPrfCombinerInputV1, MpcPrfDleqProofWireV1, MpcPrfOutputPurposeV1,
    MpcPrfOutputRequestV1, MpcPrfPartialBindingV1, MpcPrfPartialProofBundleV1,
    MpcPrfPartialVerificationInputV1, MpcPrfPartialVerificationPlanV1, MpcPrfPartialWireV1,
    MpcPrfPurposeBindingPlanV1, MpcPrfShareCommitmentWireV1, MpcPrfSignerPartialInputV1,
    MpcPrfSignerPartialV1, MpcPrfVerifiedPartialV1, MPC_PRF_COMMITMENT_WIRE_V1_LEN,
    MPC_PRF_DLEQ_PROOF_WIRE_V1_LEN, MPC_PRF_PARTIAL_WIRE_V1_LEN,
};
pub use self::ecdsa_threshold_prf_backend::{
    combine_mpc_prf_batch_outputs_with_threshold_backend_v1,
    combine_mpc_prf_proof_bundles_with_threshold_backend_v1,
    evaluate_mpc_prf_signer_output_batch_with_threshold_backend_v1,
    evaluate_mpc_prf_signer_partial_with_threshold_backend_v1,
    verify_mpc_prf_partial_with_threshold_backend_v1, MpcPrfSigningRootShareWireV1,
    MpcPrfThresholdBatchCombineInputV1, MpcPrfThresholdBatchCombinedOutputV1,
    MpcPrfThresholdCombineInputV1, MpcPrfThresholdCombinedOutputV1,
    MpcPrfThresholdSignerBatchInputV1, MpcPrfThresholdSignerBatchOutputV1,
    MpcPrfThresholdSignerInputV1, MPC_PRF_SIGNING_ROOT_SHARE_WIRE_V1_LEN,
};
pub use self::error::{
    RedactedDiagnostic, RouterAbDerivationError, RouterAbDerivationErrorCode,
    RouterAbDerivationResult,
};
pub use self::leakage::{default_leakage_questions, LeakageQuestion, LeakageQuestionId};
pub use self::material::{
    OpenedShareKind, PublicDigest32, PublicMaterial32, Role, SecretMaterial32,
};
pub use self::scope::{ExportScope, RefreshScope, RegistrationScope, RequestScope};
pub use self::signer_plaintext::{
    decode_signer_input_plaintext_v1, encode_signer_input_plaintext_v1, SignerInputPlaintextV1,
    SignerInputQuorumPolicyV1,
};
pub use self::transcript::{
    transcript_binding_digest, transcript_digest_v1, IndexedSignerBinding, QuorumPolicy,
    SignerSetBinding, TranscriptBinding,
};
pub use self::wire::{CanonicalEncoding, WireVersion};
