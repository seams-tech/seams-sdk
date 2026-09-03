#![forbid(unsafe_code)]
//! Fixed ECDSA threshold-PRF derivation for the Router/A/B signer architecture.
//!
//! The crate is intentionally scoped to derivation and transcript-bound output
//! material. Router, signer, and server networking lives in adapters around
//! this crate.

mod context;
mod diagnostics;
mod ecdsa_stable_context;
mod ecdsa_threshold_prf;
mod ecdsa_threshold_prf_backend;
mod error;
mod leakage;
mod material;
mod scope;
mod signer_plaintext;
mod tenant_root;
mod tenant_root_activation_evidence;
mod tenant_root_activation_receipt;
mod tenant_root_activation_support_evidence;
mod tenant_root_active_binding;
mod tenant_root_command_replay;
mod tenant_root_command_terminal_receipt;
mod tenant_root_creation_capability;
mod tenant_root_creation_grant;
mod tenant_root_creation_journal;
mod tenant_root_creation_role_command;
mod tenant_root_custody_binding;
mod tenant_root_deletion_lifecycle;
mod tenant_root_initial_role_attempt;
mod tenant_root_lifecycle;
mod tenant_root_managed_backup;
mod tenant_root_managed_restore_lifecycle;
mod tenant_root_managed_restore_transport;
mod tenant_root_online_sealing;
mod tenant_root_protocol;
mod tenant_root_recovery_artifacts;
mod tenant_root_recovery_recipient_proof;
mod tenant_root_recovery_reshare;
mod tenant_root_refresh_checkpoint;
mod tenant_root_refresh_role_attempt;
mod tenant_root_refresh_role_command;
mod tenant_root_refresh_transport;
mod tenant_root_restore_import;
mod tenant_root_role_cleanup_command;

pub use threshold_prf::TwoPartyDeriverRole;
mod transcript;
mod wire;
mod x25519_canonical;

pub use self::context::{
    context_digest_v1, AccountScope, DerivationContext, RequestKind, RootShareEpoch,
};
pub use self::diagnostics::redacted_diagnostic;
pub use self::ecdsa_stable_context::StableTenantDerivationContextV2;
pub use self::ecdsa_threshold_prf::{
    plan_mpc_prf_combine_v1, plan_mpc_prf_partial_verification_v1, plan_mpc_prf_purpose_binding_v1,
    plan_mpc_prf_stable_purpose_binding_from_authenticated_custody_digest_v2,
    plan_mpc_prf_stable_purpose_binding_v2, MpcPrfCombinePlanV1, MpcPrfCombinerInputV1,
    MpcPrfDleqProofWireV1, MpcPrfOutputPurposeV1, MpcPrfOutputRequestV1, MpcPrfPartialBindingV1,
    MpcPrfPartialProofBundleV1, MpcPrfPartialVerificationInputV1, MpcPrfPartialVerificationPlanV1,
    MpcPrfPartialWireV1, MpcPrfPurposeBindingPlanV1, MpcPrfShareCommitmentWireV1,
    MpcPrfSignerPartialInputV1, MpcPrfSignerPartialV1, MpcPrfStablePurposeBindingPlanV2,
    MpcPrfVerifiedPartialV1, MPC_PRF_COMMITMENT_WIRE_V1_LEN, MPC_PRF_DLEQ_PROOF_WIRE_V1_LEN,
    MPC_PRF_PARTIAL_WIRE_V1_LEN,
};
pub use self::ecdsa_threshold_prf_backend::{
    combine_mpc_prf_batch_outputs_with_threshold_backend_v1,
    combine_mpc_prf_proof_bundles_with_threshold_backend_v1,
    combine_mpc_prf_stable_proof_bundles_with_threshold_backend_v2,
    evaluate_mpc_prf_signer_output_batch_with_threshold_backend_v1,
    evaluate_mpc_prf_signer_partial_with_threshold_backend_v1,
    evaluate_mpc_prf_stable_signer_partial_with_threshold_backend_v2,
    verify_mpc_prf_partial_with_threshold_backend_v1,
    verify_mpc_prf_stable_partial_with_threshold_backend_v2, MpcPrfSigningRootShareWireV1,
    MpcPrfStablePartialProofBundleV2, MpcPrfStableThresholdCombineInputV2,
    MpcPrfStableThresholdCombinedOutputV2, MpcPrfStableThresholdSignerInputV2,
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
pub(crate) use self::tenant_root::require_tenant_root_identifier;
pub use self::tenant_root::{
    TenantRootCustodyLineageId, TenantRootIdentityDigestV1, TenantRootIdentityV1,
    TenantRootShareEpoch, TENANT_ROOT_MAX_CLOCK_SKEW_MS_V1, TENANT_ROOT_MAX_LIFETIME_MS_V1,
};
pub use self::tenant_root_activation_evidence::*;
pub use self::tenant_root_activation_receipt::*;
pub use self::tenant_root_activation_support_evidence::*;
pub use self::tenant_root_active_binding::*;
pub use self::tenant_root_command_replay::*;
pub use self::tenant_root_command_terminal_receipt::*;
pub use self::tenant_root_creation_capability::*;
pub use self::tenant_root_creation_grant::*;
pub use self::tenant_root_creation_journal::*;
pub use self::tenant_root_creation_role_command::*;
pub use self::tenant_root_custody_binding::*;
pub use self::tenant_root_deletion_lifecycle::*;
pub use self::tenant_root_initial_role_attempt::*;
pub use self::tenant_root_lifecycle::*;
pub use self::tenant_root_managed_backup::*;
pub use self::tenant_root_managed_restore_lifecycle::*;
pub use self::tenant_root_managed_restore_transport::*;
pub use self::tenant_root_online_sealing::*;
pub use self::tenant_root_protocol::{
    verify_tenant_root_creation_evidence_v1, verify_tenant_root_refresh_evidence_v1,
    TenantRootCeremonyContextV1, TenantRootCeremonyEpochsV1, TenantRootCeremonyNonceV1,
    TenantRootCeremonySessionIdV1, TenantRootProtocolDigestV1,
    TenantRootShareInstallationEvidenceV1, TenantRootShareInstallationTranscriptV1,
    VerifiedTenantRootShareInstallationEvidenceV1,
};
pub use self::tenant_root_recovery_artifacts::{
    decode_tenant_root_recovery_manifest_v1, decode_tenant_root_recovery_package_v1,
    seal_tenant_root_recovery_package_v1, sign_tenant_root_recovery_manifest_v1,
    verify_and_open_tenant_root_recovery_role_package_v1, TenantRootRecoveryDescriptorDigestV1,
    TenantRootRecoveryDescriptorV1, TenantRootRecoveryManifestV1,
    TenantRootRecoveryPackageDigestV1, TenantRootRecoveryPackageHeaderV1,
    TenantRootRecoveryPackageV1, TenantRootRecoveryRecipientFingerprintV1,
    TenantRootRecoveryRecipientKeypairV1, TenantRootRecoveryRecipientPublicKeyV1,
    TenantRootRecoveryRoleDescriptorV1, TenantRootRecoverySetId,
    TenantRootRecoveryTrustedVerifyingKeysV1, VerifiedTenantRootRecoveryRoleShareV1,
    TENANT_ROOT_RECOVERY_MANIFEST_MAX_BYTES, TENANT_ROOT_RECOVERY_MANIFEST_MIME_TYPE,
    TENANT_ROOT_RECOVERY_PACKAGE_MAX_BYTES, TENANT_ROOT_RECOVERY_PACKAGE_MIME_TYPE,
};
pub use self::tenant_root_recovery_recipient_proof::{
    confirm_tenant_root_recovery_recipient_proof_v1,
    decode_tenant_root_recovery_recipient_proof_v1, open_tenant_root_recovery_recipient_proof_v1,
    seal_tenant_root_recovery_recipient_proof_v1, verify_tenant_root_recovery_recipient_proof_v1,
    TenantRootRecoveryRecipientProofBindingV1, TenantRootRecoveryRecipientProofConfirmationV1,
    TenantRootRecoveryRecipientProofEnvelopeV1, TenantRootRecoveryRecipientProofSecretV1,
    TENANT_ROOT_RECOVERY_RECIPIENT_PROOF_MAX_BYTES,
};
pub use self::tenant_root_recovery_reshare::{
    PendingTenantRootRecoveryShareV1, TenantRootRecoveryReshareContextV1,
    TenantRootRecoveryReshareHpkeKeypairV1, TenantRootRecoveryReshareHpkePublicKeyV1,
    TenantRootRecoveryShareInstallationEvidenceV1, TenantRootSignedRecoveryReshareCommitmentV1,
    TenantRootSignedRecoveryReshareContributionV1,
    TenantRootSignedRecoveryShareInstallationEvidenceV1,
    VerifiedTenantRootRecoveryReshareCommitmentV1, VerifiedTenantRootRecoveryReshareContributionV1,
    VerifiedTenantRootRecoveryResharePairV1, VerifiedTenantRootRecoveryShareV1,
};
pub use self::tenant_root_refresh_checkpoint::*;
pub use self::tenant_root_refresh_role_attempt::*;
pub use self::tenant_root_refresh_role_command::*;
pub use self::tenant_root_refresh_transport::{
    open_tenant_root_refresh_contribution_v1, seal_tenant_root_refresh_contribution_v1,
    TenantRootCreationCommitmentTranscriptV1, TenantRootEncryptedRefreshContributionV1,
    TenantRootRefreshCommitmentTranscriptV1, TenantRootRefreshContributionAadDigestV1,
    TenantRootRefreshContributionAadV1, TenantRootRefreshHpkeKeypairV1,
    TenantRootRefreshHpkePublicKeyV1, TenantRootSignedCreationCommitmentV1,
    TenantRootSignedRefreshCommitmentV1, TenantRootSignedRefreshContributionV1,
    TenantRootSignedShareInstallationEvidenceV1, VerifiedTenantRootCreationCommitmentPairV1,
    VerifiedTenantRootCreationCommitmentV1, VerifiedTenantRootRefreshCommitmentPairV1,
    VerifiedTenantRootRefreshCommitmentV1, VerifiedTenantRootSignedRefreshContributionV1,
    VerifiedTenantRootSignedShareInstallationEvidenceWireV1,
    TENANT_ROOT_SIGNED_CREATION_COMMITMENT_MAX_BYTES_V1,
    TENANT_ROOT_SIGNED_SHARE_INSTALLATION_EVIDENCE_MAX_BYTES_V1,
};
pub use self::tenant_root_restore_import::{
    ExpectedTenantRootRestoreImportV1, ImportedTenantRootRecoveryRoleShareV1,
    TenantRootRestoreDestinationFingerprintV1, TenantRootRestoreImportBindingV1,
    TenantRootRestoreImportEnvelopeV1, TenantRootRestoreImportKeypairV1,
    TenantRootRestoreImportPublicKeyV1, TenantRootRestoreSessionIdV1,
    TENANT_ROOT_RESTORE_IMPORT_MAX_BYTES,
};
pub use self::tenant_root_role_cleanup_command::*;
pub use self::transcript::{
    transcript_binding_digest, transcript_digest_v1, IndexedSignerBinding, QuorumPolicy,
    SignerSetBinding, TranscriptBinding,
};
pub use self::wire::{CanonicalEncoding, WireVersion};
