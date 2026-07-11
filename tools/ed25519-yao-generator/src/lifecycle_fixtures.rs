//! Strict host-only lifecycle-continuity vector fixtures.
//!
//! Every secret-looking value is public synthetic test data. This module models
//! continuity arithmetic and zero-evaluation activation metadata only.

use core::fmt;
use core::num::NonZeroU64;

use curve25519_dalek::scalar::Scalar;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::kdf_fixtures::{
    canonical_synthetic_kdf_material_v1, kdf_clear_reference_trace_v1, kdf_contribution_vector_v1,
    CanonicalSyntheticKdfMaterialV1, KdfApplicationBindingVectorV1, KdfClearReferenceTraceV1,
    KdfContributionVectorV1, KdfStableContextVectorV1, KdfSyntheticRootsV1,
    SYNTHETIC_CLIENT_ROOT_V1, SYNTHETIC_DERIVER_A_ROOT_V1, SYNTHETIC_DERIVER_B_ROOT_V1,
    SYNTHETIC_KEY_CREATION_SIGNER_SLOT_V1, SYNTHETIC_SIGNING_KEY_ID_V1,
    SYNTHETIC_SIGNING_ROOT_ID_V1, SYNTHETIC_WALLET_ID_V1,
};
use crate::{
    evaluate_activation, prepare_host_only_recovery_reference_v1,
    prepare_host_only_refresh_reference_v1, HostOnlyDeriverARefreshDeltaContributionV1,
    HostOnlyDeriverBRefreshDeltaContributionV1, HostOnlyJointRefreshDeltaCoinsV1,
    HostOnlyRecoveryReferenceInputsV1, HostOnlyRefreshReferenceInputsV1,
    SyntheticClientDerivationRootV1,
};

/// Schema identifier for the version-one lifecycle-continuity corpus.
pub const LIFECYCLE_CONTINUITY_CORPUS_SCHEMA_V1: &str =
    "seams:router-ab:ed25519-yao:lifecycle-continuity-vectors:v1";

/// Fixed evidence-scope identifier excluding production lifecycle claims.
pub const LIFECYCLE_CONTINUITY_EVIDENCE_SCOPE_V1: &str = "host_only_synthetic_continuity_v1";

/// Canonical synthetic registration-candidate metadata case identifier.
pub const REGISTRATION_CANDIDATE_CASE_ID_V1: &str = "registration_candidate_metadata_v1";

/// Canonical registration-origin activation case identifier.
pub const REGISTRATION_ACTIVATION_CASE_ID_V1: &str =
    "activation_after_registration_zero_evaluation_v1";

/// Canonical same-root recovery case identifier.
pub const RECOVERY_CONTINUITY_CASE_ID_V1: &str = "recovery_same_root_continuity_v1";

/// Canonical recovery-origin activation case identifier.
pub const RECOVERY_ACTIVATION_CASE_ID_V1: &str = "activation_after_recovery_zero_evaluation_v1";

/// Canonical opposite-delta refresh case identifier.
pub const REFRESH_CONTINUITY_CASE_ID_V1: &str = "refresh_opposite_delta_continuity_v1";

/// Canonical refresh-origin activation case identifier.
pub const REFRESH_ACTIVATION_CASE_ID_V1: &str = "activation_after_refresh_zero_evaluation_v1";

const DERIVER_A_ROOT_EPOCH_V1: u64 = 3;
const DERIVER_B_ROOT_EPOCH_V1: u64 = 9;
const DERIVER_A_CURRENT_INPUT_EPOCH_V1: u64 = 11;
const DERIVER_B_CURRENT_INPUT_EPOCH_V1: u64 = 41;
const DERIVER_A_NEXT_INPUT_EPOCH_V1: u64 = 12;
const DERIVER_B_NEXT_INPUT_EPOCH_V1: u64 = 43;
const INITIAL_ACTIVATION_EPOCH_V1: u64 = 7;
const RECOVERY_ACTIVATION_EPOCH_V1: u64 = 8;
const REFRESH_ACTIVATION_EPOCH_V1: u64 = 9;
const REFRESH_DELTA_Y_V1: [u8; 32] = [0xa5; 32];
const REFRESH_DELTA_TAU_V1: u64 = 17;
const REFRESH_DERIVER_A_DELTA_Y_V1: [u8; 32] = [0x3c; 32];
const REFRESH_DERIVER_A_DELTA_TAU_V1: u64 = 5;
const REFRESH_DERIVER_B_DELTA_Y_V1: [u8; 32] = [0x69; 32];
const REFRESH_DERIVER_B_DELTA_TAU_V1: u64 = 12;

/// Strict portable corpus containing the six canonical continuity cases.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LifecycleContinuityCorpusV1 {
    /// Fixed lifecycle-continuity schema identifier.
    pub schema: String,
    /// Fixed Ed25519 Router A/B Yao protocol identifier.
    pub protocol_id: String,
    /// Fixed host-only evidence-scope identifier.
    pub evidence_scope: String,
    /// Canonical registration/activation/recovery/activation/refresh/activation sequence.
    pub cases: Vec<LifecycleContinuityCaseV1>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawLifecycleContinuityCorpusV1 {
    schema: String,
    protocol_id: String,
    evidence_scope: String,
    cases: Vec<LifecycleContinuityCaseV1>,
}

impl<'de> Deserialize<'de> for LifecycleContinuityCorpusV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawLifecycleContinuityCorpusV1::deserialize(deserializer)?;
        let corpus = Self {
            schema: raw.schema,
            protocol_id: raw.protocol_id,
            evidence_scope: raw.evidence_scope,
            cases: raw.cases,
        };
        corpus
            .validate()
            .map_err(<D::Error as serde::de::Error>::custom)?;
        Ok(corpus)
    }
}

/// Validation failure for a decoded lifecycle-continuity corpus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LifecycleContinuityValidationErrorV1;

impl fmt::Display for LifecycleContinuityValidationErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("lifecycle-continuity corpus differs from the canonical v1 relation")
    }
}

impl std::error::Error for LifecycleContinuityValidationErrorV1 {}

impl LifecycleContinuityCorpusV1 {
    /// Requires the exact frozen six-case schema, values, and cross-case relations.
    pub fn validate(&self) -> Result<(), LifecycleContinuityValidationErrorV1> {
        if self != &canonical_lifecycle_continuity_corpus_v1() {
            return Err(LifecycleContinuityValidationErrorV1);
        }
        Ok(())
    }
}

/// Request-kind-tagged host-only lifecycle-continuity case.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "request_kind",
    content = "vector",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum LifecycleContinuityCaseV1 {
    /// Synthetic public registration-candidate metadata snapshot.
    Registration(RegistrationCandidateMetadataVectorV1),
    /// Same-logical-root recovery continuity.
    Recovery(RecoveryContinuityVectorV1),
    /// Zero-evaluation activation continuation.
    Activation(ActivationContinuityVectorV1),
    /// Opposite-delta refresh continuity.
    Refresh(RefreshContinuityVectorV1),
}

/// Pending-origin-tagged activation continuation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "origin_kind",
    content = "transition",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ActivationContinuityVectorV1 {
    /// Continuation of the canonical registration-candidate case.
    Registration(RegistrationActivationContinuationV1),
    /// Continuation of the canonical recovery case.
    Recovery(RecoveryActivationContinuationV1),
    /// Continuation of the canonical refresh case.
    Refresh(RefreshActivationContinuationV1),
}

/// Public immutable identity and point evidence shared by every case.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureIdentityV1 {
    /// Frozen SDK-owned application-binding record.
    pub application_binding: KdfApplicationBindingVectorV1,
    /// Frozen stable-context record and binding.
    pub context: KdfStableContextVectorV1,
    /// Registered Ed25519 public key.
    pub registered_public_key_hex: String,
    /// Public client-labelled signing point.
    pub x_client_point_hex: String,
    /// Public server-labelled signing point.
    pub x_server_point_hex: String,
}

/// Validated nonzero lifecycle epoch encoded as one JSON integer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NonZeroEpochV1(NonZeroU64);

impl NonZeroEpochV1 {
    /// Validates a nonzero epoch value.
    pub const fn new(value: u64) -> Option<Self> {
        match NonZeroU64::new(value) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    /// Returns the validated nonzero epoch.
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

impl Serialize for NonZeroEpochV1 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u64(self.get())
    }
}

impl<'de> Deserialize<'de> for NonZeroEpochV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u64::deserialize(deserializer)?;
        Self::new(value).ok_or_else(|| {
            <D::Error as serde::de::Error>::custom("lifecycle epoch must be nonzero")
        })
    }
}

/// Role-root and role-input-state epochs for one Deriver.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleEpochV1 {
    /// Nonzero stable role-root record epoch.
    pub role_root_epoch: NonZeroEpochV1,
    /// Nonzero effective role-input-state epoch.
    pub role_input_state_epoch: NonZeroEpochV1,
}

/// Independently valued epoch records for Deriver A and Deriver B.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleEpochPairV1 {
    /// Deriver A epoch record.
    pub deriver_a: RoleEpochV1,
    /// Deriver B epoch record.
    pub deriver_b: RoleEpochV1,
}

/// Public continuity state with one active activation epoch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActiveContinuityPublicStateV1 {
    /// Immutable public identity.
    pub identity: FixtureIdentityV1,
    /// Currently active role epochs.
    pub active_role_epochs: RoleEpochPairV1,
    /// Currently active SigningWorker activation epoch.
    pub active_activation_epoch: NonZeroEpochV1,
}

/// Public registration candidate awaiting its first activation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrationPendingPublicStateV1 {
    /// Candidate public identity.
    pub identity: FixtureIdentityV1,
    /// Candidate role epochs that become active together.
    pub candidate_role_epochs: RoleEpochPairV1,
    /// First activation epoch, with no active predecessor.
    pub pending_activation_epoch: NonZeroEpochV1,
}

/// Public pending state produced by the recovery reference case.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryPendingPublicStateV1 {
    /// Unchanged public identity.
    pub identity: FixtureIdentityV1,
    /// Unchanged current role epochs.
    pub current_role_epochs: RoleEpochPairV1,
    /// Prior active activation epoch.
    pub active_activation_epoch: NonZeroEpochV1,
    /// Fresh pending activation epoch.
    pub pending_activation_epoch: NonZeroEpochV1,
}

/// Public pending state produced by the refresh reference case.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefreshPendingPublicStateV1 {
    /// Unchanged public identity.
    pub identity: FixtureIdentityV1,
    /// Current role epochs retained until activation completes.
    pub current_role_epochs: RoleEpochPairV1,
    /// Staged next role epochs.
    pub next_role_epochs: RoleEpochPairV1,
    /// Prior active activation epoch.
    pub active_activation_epoch: NonZeroEpochV1,
    /// Fresh pending activation epoch.
    pub pending_activation_epoch: NonZeroEpochV1,
    /// Frozen derivation admission during the staged transition.
    pub derivation_admission: FrozenAdmissionV1,
}

/// Branch-specific marker proving derivation admission is frozen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FrozenAdmissionV1 {
    /// New derivation admission is frozen.
    Frozen,
}

/// Public state after the refresh-origin activation continuation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefreshActivatedPublicStateV1 {
    /// Unchanged public identity.
    pub identity: FixtureIdentityV1,
    /// Promoted next role epochs.
    pub active_role_epochs: RoleEpochPairV1,
    /// Former role-input-state epochs retained as semantic tombstones.
    pub retired_role_input_state_epochs: RetiredRoleInputEpochPairV1,
    /// Promoted activation epoch.
    pub active_activation_epoch: NonZeroEpochV1,
    /// Reopened derivation admission after promotion.
    pub derivation_admission: OpenAdmissionV1,
}

/// Retired input-state epoch values after refresh promotion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetiredRoleInputEpochPairV1 {
    /// Retired Deriver A input-state epoch.
    pub deriver_a: NonZeroEpochV1,
    /// Retired Deriver B input-state epoch.
    pub deriver_b: NonZeroEpochV1,
}

/// Branch-specific marker proving derivation admission is open.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpenAdmissionV1 {
    /// New derivation admission is open.
    Open,
}

/// Explicit reference-operation counts for one fixture case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReferenceOperationCountsV1 {
    /// Deriver A ideal invocation count.
    pub deriver_a_invocations: u8,
    /// Deriver B ideal invocation count.
    pub deriver_b_invocations: u8,
    /// Client/A KDF derivation count.
    pub client_kdf_derivations_a: u8,
    /// Client/B KDF derivation count.
    pub client_kdf_derivations_b: u8,
    /// Server/A KDF derivation count.
    pub server_kdf_derivations_a: u8,
    /// Server/B KDF derivation count.
    pub server_kdf_derivations_b: u8,
    /// Activation-family ideal reference evaluation count.
    pub activation_family_evaluations: u8,
    /// Export-family ideal reference evaluation count.
    pub export_family_evaluations: u8,
    /// Pending activation continuation consumption count.
    pub pending_activation_consumptions: u8,
}

/// Re-derived role-separated client contributions during recovery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientContributionPairV1 {
    /// Client seed-domain contribution addressed to Deriver A.
    pub y_client_a_hex: String,
    /// Client scalar-domain contribution addressed to Deriver A.
    pub tau_client_a_hex: String,
    /// Client seed-domain contribution addressed to Deriver B.
    pub y_client_b_hex: String,
    /// Client scalar-domain contribution addressed to Deriver B.
    pub tau_client_b_hex: String,
}

/// Aggregate host-only recovery continuity evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryHostOnlyReferenceV1 {
    /// Public synthetic roots treated as host-only semantic inputs.
    pub synthetic_roots: KdfSyntheticRootsV1,
    /// Current eight-contribution tuple.
    pub current_contributions: KdfContributionVectorV1,
    /// Recovered client root required to equal the current client root.
    pub recovered_client_root_hex: String,
    /// Client contributions re-derived from the recovered root.
    pub rederived_client_contributions: ClientContributionPairV1,
    /// Complete after-contribution tuple.
    pub after_contributions: KdfContributionVectorV1,
    /// Host-only trace before recovery.
    pub before_clear_reference_trace: KdfClearReferenceTraceV1,
    /// Host-only trace after recovery.
    pub after_clear_reference_trace: KdfClearReferenceTraceV1,
}

/// One role's public synthetic ideal refresh-delta contribution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefreshDeltaContributionV1 {
    /// Little-endian seed-domain contribution.
    pub delta_y_hex: String,
    /// Canonical little-endian scalar-domain contribution.
    pub delta_tau_hex: String,
}

/// Role-local ideal contributions and their nonzero combined refresh delta.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JointRefreshDeltaV1 {
    /// Deriver A's contribution.
    pub deriver_a: RefreshDeltaContributionV1,
    /// Deriver B's contribution.
    pub deriver_b: RefreshDeltaContributionV1,
    /// Sum of the two seed-domain contributions modulo `2^256`.
    pub combined_delta_y_hex: String,
    /// Sum of the two scalar contributions modulo `l`.
    pub combined_delta_tau_hex: String,
}

/// Aggregate host-only refresh continuity evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefreshHostOnlyReferenceV1 {
    /// Public synthetic roots treated as host-only semantic inputs.
    pub synthetic_roots: KdfSyntheticRootsV1,
    /// Complete contribution tuple before refresh.
    pub before_contributions: KdfContributionVectorV1,
    /// Joint ideal role contributions and combined opposite-signed delta.
    pub delta: JointRefreshDeltaV1,
    /// Complete contribution tuple after refresh.
    pub after_contributions: KdfContributionVectorV1,
    /// Host-only trace before refresh.
    pub before_clear_reference_trace: KdfClearReferenceTraceV1,
    /// Host-only trace after refresh.
    pub after_clear_reference_trace: KdfClearReferenceTraceV1,
}

/// Same-logical-root recovery continuity vector.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryContinuityVectorV1 {
    /// Stable canonical case identifier.
    pub case_id: String,
    /// Public state before recovery.
    pub before_public: ActiveContinuityPublicStateV1,
    /// Public pending state after the host-only recovery reference.
    pub pending_public: RecoveryPendingPublicStateV1,
    /// Frozen ideal operation counts.
    pub reference_operation_counts: ReferenceOperationCountsV1,
    /// Aggregate host-only continuity evidence.
    pub host_only_reference: RecoveryHostOnlyReferenceV1,
}

/// Synthetic public registration-candidate metadata vector.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrationCandidateMetadataVectorV1 {
    /// Stable canonical case identifier.
    pub case_id: String,
    /// Candidate metadata awaiting first activation.
    pub pending_public: RegistrationPendingPublicStateV1,
    /// Frozen zero-work metadata-snapshot counts.
    pub reference_operation_counts: ReferenceOperationCountsV1,
}

/// Opposite-delta refresh continuity vector.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefreshContinuityVectorV1 {
    /// Stable canonical case identifier.
    pub case_id: String,
    /// Public state before refresh.
    pub before_public: ActiveContinuityPublicStateV1,
    /// Public staged state after the host-only refresh reference.
    pub pending_public: RefreshPendingPublicStateV1,
    /// Frozen ideal operation counts.
    pub reference_operation_counts: ReferenceOperationCountsV1,
    /// Aggregate host-only continuity evidence.
    pub host_only_reference: RefreshHostOnlyReferenceV1,
}

/// Zero-evaluation continuation of the recovery pending state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryActivationContinuationV1 {
    /// Stable canonical case identifier.
    pub case_id: String,
    /// Exact earlier recovery case identifier.
    pub origin_case_id: String,
    /// Copied recovery pending public state.
    pub pending_public: RecoveryPendingPublicStateV1,
    /// Promoted active public state.
    pub activated_public: ActiveContinuityPublicStateV1,
    /// Frozen zero-evaluation operation counts.
    pub reference_operation_counts: ReferenceOperationCountsV1,
}

/// Zero-evaluation continuation of registration-candidate metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrationActivationContinuationV1 {
    /// Stable canonical case identifier.
    pub case_id: String,
    /// Exact earlier registration-candidate case identifier.
    pub origin_case_id: String,
    /// Copied registration pending public state.
    pub pending_public: RegistrationPendingPublicStateV1,
    /// Initial active public state.
    pub activated_public: ActiveContinuityPublicStateV1,
    /// Frozen zero-evaluation operation counts.
    pub reference_operation_counts: ReferenceOperationCountsV1,
}

/// Zero-evaluation continuation of the refresh pending state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefreshActivationContinuationV1 {
    /// Stable canonical case identifier.
    pub case_id: String,
    /// Exact earlier refresh case identifier.
    pub origin_case_id: String,
    /// Copied refresh pending public state.
    pub pending_public: RefreshPendingPublicStateV1,
    /// Promoted refresh public state.
    pub activated_public: RefreshActivatedPublicStateV1,
    /// Frozen zero-evaluation operation counts.
    pub reference_operation_counts: ReferenceOperationCountsV1,
}

/// Builds the canonical six-case host-only continuity corpus.
pub fn canonical_lifecycle_continuity_corpus_v1() -> LifecycleContinuityCorpusV1 {
    let material = canonical_synthetic_kdf_material_v1();
    let current_activation = evaluate_activation(&material.deriver_a, &material.deriver_b);
    let current_trace = kdf_clear_reference_trace_v1(
        &material.deriver_a,
        &material.deriver_b,
        current_activation.material(),
    );
    let registration =
        build_registration_candidate_metadata_v1(fixture_identity_v1(&material, &current_trace));
    let registration_activation =
        build_registration_activation_continuation_v1(registration.pending_public.clone());
    let recovery =
        build_recovery_continuity_v1(&material, registration_activation.activated_public.clone());
    let recovery_activation =
        build_recovery_activation_continuation_v1(recovery.pending_public.clone());
    let refresh =
        build_refresh_continuity_v1(&material, recovery_activation.activated_public.clone());
    let refresh_activation =
        build_refresh_activation_continuation_v1(refresh.pending_public.clone());

    LifecycleContinuityCorpusV1 {
        schema: LIFECYCLE_CONTINUITY_CORPUS_SCHEMA_V1.to_owned(),
        protocol_id: ed25519_yao::PROTOCOL_ID_STR.to_owned(),
        evidence_scope: LIFECYCLE_CONTINUITY_EVIDENCE_SCOPE_V1.to_owned(),
        cases: vec![
            LifecycleContinuityCaseV1::Registration(registration),
            LifecycleContinuityCaseV1::Activation(ActivationContinuityVectorV1::Registration(
                registration_activation,
            )),
            LifecycleContinuityCaseV1::Recovery(recovery),
            LifecycleContinuityCaseV1::Activation(ActivationContinuityVectorV1::Recovery(
                recovery_activation,
            )),
            LifecycleContinuityCaseV1::Refresh(refresh),
            LifecycleContinuityCaseV1::Activation(ActivationContinuityVectorV1::Refresh(
                refresh_activation,
            )),
        ],
    }
}

fn build_registration_candidate_metadata_v1(
    identity: FixtureIdentityV1,
) -> RegistrationCandidateMetadataVectorV1 {
    RegistrationCandidateMetadataVectorV1 {
        case_id: REGISTRATION_CANDIDATE_CASE_ID_V1.to_owned(),
        pending_public: RegistrationPendingPublicStateV1 {
            identity,
            candidate_role_epochs: current_role_epochs_v1(),
            pending_activation_epoch: epoch_v1(INITIAL_ACTIVATION_EPOCH_V1),
        },
        reference_operation_counts: registration_metadata_reference_operation_counts_v1(),
    }
}

fn build_registration_activation_continuation_v1(
    pending_public: RegistrationPendingPublicStateV1,
) -> RegistrationActivationContinuationV1 {
    let activated_public = ActiveContinuityPublicStateV1 {
        identity: pending_public.identity.clone(),
        active_role_epochs: pending_public.candidate_role_epochs,
        active_activation_epoch: pending_public.pending_activation_epoch,
    };

    RegistrationActivationContinuationV1 {
        case_id: REGISTRATION_ACTIVATION_CASE_ID_V1.to_owned(),
        origin_case_id: REGISTRATION_CANDIDATE_CASE_ID_V1.to_owned(),
        pending_public,
        activated_public,
        reference_operation_counts: activation_reference_operation_counts_v1(),
    }
}

fn build_recovery_continuity_v1(
    material: &CanonicalSyntheticKdfMaterialV1,
    before_public: ActiveContinuityPublicStateV1,
) -> RecoveryContinuityVectorV1 {
    let current_activation = evaluate_activation(&material.deriver_a, &material.deriver_b);
    let current_trace = kdf_clear_reference_trace_v1(
        &material.deriver_a,
        &material.deriver_b,
        current_activation.material(),
    );
    assert_eq!(
        before_public.identity,
        fixture_identity_v1(material, &current_trace)
    );
    assert_eq!(before_public.active_role_epochs, current_role_epochs_v1());
    assert_eq!(
        before_public.active_activation_epoch,
        epoch_v1(INITIAL_ACTIVATION_EPOCH_V1)
    );
    let identity = before_public.identity.clone();
    let current_role_epochs = before_public.active_role_epochs;
    let current_root =
        SyntheticClientDerivationRootV1::from_fixture_bytes(SYNTHETIC_CLIENT_ROOT_V1);
    let recovered_root =
        SyntheticClientDerivationRootV1::from_fixture_bytes(SYNTHETIC_CLIENT_ROOT_V1);
    let recovery = prepare_host_only_recovery_reference_v1(HostOnlyRecoveryReferenceInputsV1::new(
        &current_root,
        &recovered_root,
        &material.context,
        &material.deriver_a,
        &material.deriver_b,
    ))
    .expect("canonical fixture satisfies same-root recovery continuity");
    let recovered_client = recovery.rederived_client();
    let recovered_a = recovery.recovered_deriver_a();
    let recovered_b = recovery.recovered_deriver_b();
    let after_activation = recovery.recovered_activation();
    let _continuity_witness = recovery.continuity_witness();
    let after_trace =
        kdf_clear_reference_trace_v1(recovered_a, recovered_b, after_activation.material());
    let current_contributions =
        kdf_contribution_vector_v1(&material.deriver_a, &material.deriver_b);
    let after_contributions = kdf_contribution_vector_v1(recovered_a, recovered_b);
    assert_eq!(current_contributions, after_contributions);
    assert_eq!(current_trace, after_trace);

    RecoveryContinuityVectorV1 {
        case_id: RECOVERY_CONTINUITY_CASE_ID_V1.to_owned(),
        before_public,
        pending_public: RecoveryPendingPublicStateV1 {
            identity,
            current_role_epochs,
            active_activation_epoch: epoch_v1(INITIAL_ACTIVATION_EPOCH_V1),
            pending_activation_epoch: epoch_v1(RECOVERY_ACTIVATION_EPOCH_V1),
        },
        reference_operation_counts: recovery_reference_operation_counts_v1(),
        host_only_reference: RecoveryHostOnlyReferenceV1 {
            synthetic_roots: synthetic_roots_v1(),
            current_contributions,
            recovered_client_root_hex: encode_hex(&SYNTHETIC_CLIENT_ROOT_V1),
            rederived_client_contributions: ClientContributionPairV1 {
                y_client_a_hex: encode_hex(
                    &recovered_client.deriver_a().y().expose_fixture_bytes(),
                ),
                tau_client_a_hex: encode_hex(
                    &recovered_client.deriver_a().tau().expose_fixture_bytes(),
                ),
                y_client_b_hex: encode_hex(
                    &recovered_client.deriver_b().y().expose_fixture_bytes(),
                ),
                tau_client_b_hex: encode_hex(
                    &recovered_client.deriver_b().tau().expose_fixture_bytes(),
                ),
            },
            after_contributions,
            before_clear_reference_trace: current_trace,
            after_clear_reference_trace: after_trace,
        },
    }
}

fn build_recovery_activation_continuation_v1(
    pending_public: RecoveryPendingPublicStateV1,
) -> RecoveryActivationContinuationV1 {
    let activated_public = ActiveContinuityPublicStateV1 {
        identity: pending_public.identity.clone(),
        active_role_epochs: pending_public.current_role_epochs,
        active_activation_epoch: pending_public.pending_activation_epoch,
    };

    RecoveryActivationContinuationV1 {
        case_id: RECOVERY_ACTIVATION_CASE_ID_V1.to_owned(),
        origin_case_id: RECOVERY_CONTINUITY_CASE_ID_V1.to_owned(),
        pending_public,
        activated_public,
        reference_operation_counts: activation_reference_operation_counts_v1(),
    }
}

fn build_refresh_continuity_v1(
    material: &CanonicalSyntheticKdfMaterialV1,
    before_public: ActiveContinuityPublicStateV1,
) -> RefreshContinuityVectorV1 {
    let deriver_a_delta_tau = Scalar::from(REFRESH_DERIVER_A_DELTA_TAU_V1).to_bytes();
    let deriver_b_delta_tau = Scalar::from(REFRESH_DERIVER_B_DELTA_TAU_V1).to_bytes();
    let delta_tau_bytes = Scalar::from(REFRESH_DELTA_TAU_V1).to_bytes();
    let delta_coins = HostOnlyJointRefreshDeltaCoinsV1::new(
        HostOnlyDeriverARefreshDeltaContributionV1::from_host_only_fixture(
            REFRESH_DERIVER_A_DELTA_Y_V1,
            deriver_a_delta_tau,
        )
        .expect("canonical Deriver A refresh contribution is valid"),
        HostOnlyDeriverBRefreshDeltaContributionV1::from_host_only_fixture(
            REFRESH_DERIVER_B_DELTA_Y_V1,
            deriver_b_delta_tau,
        )
        .expect("canonical Deriver B refresh contribution is valid"),
    );
    let refresh = prepare_host_only_refresh_reference_v1(HostOnlyRefreshReferenceInputsV1::new(
        &material.deriver_a,
        &material.deriver_b,
        delta_coins,
    ))
    .expect("canonical fixture satisfies opposite-delta refresh continuity");
    let refreshed_a = refresh.refreshed_deriver_a();
    let refreshed_b = refresh.refreshed_deriver_b();
    let before_activation = refresh.current_activation();
    let after_activation = refresh.refreshed_activation();
    let _continuity_witness = refresh.continuity_witness();
    let before_trace = kdf_clear_reference_trace_v1(
        &material.deriver_a,
        &material.deriver_b,
        before_activation.material(),
    );
    let after_trace =
        kdf_clear_reference_trace_v1(refreshed_a, refreshed_b, after_activation.material());
    assert_refresh_trace_continuity_v1(&before_trace, &after_trace);
    assert_eq!(
        before_public.identity,
        fixture_identity_v1(material, &before_trace)
    );
    let current_role_epochs = before_public.active_role_epochs;
    let next_role_epochs = next_role_epochs_v1();

    RefreshContinuityVectorV1 {
        case_id: REFRESH_CONTINUITY_CASE_ID_V1.to_owned(),
        pending_public: RefreshPendingPublicStateV1 {
            identity: before_public.identity.clone(),
            current_role_epochs,
            next_role_epochs,
            active_activation_epoch: before_public.active_activation_epoch,
            pending_activation_epoch: epoch_v1(REFRESH_ACTIVATION_EPOCH_V1),
            derivation_admission: FrozenAdmissionV1::Frozen,
        },
        reference_operation_counts: refresh_reference_operation_counts_v1(),
        host_only_reference: RefreshHostOnlyReferenceV1 {
            synthetic_roots: synthetic_roots_v1(),
            before_contributions: kdf_contribution_vector_v1(
                &material.deriver_a,
                &material.deriver_b,
            ),
            delta: JointRefreshDeltaV1 {
                deriver_a: RefreshDeltaContributionV1 {
                    delta_y_hex: encode_hex(&REFRESH_DERIVER_A_DELTA_Y_V1),
                    delta_tau_hex: encode_hex(&deriver_a_delta_tau),
                },
                deriver_b: RefreshDeltaContributionV1 {
                    delta_y_hex: encode_hex(&REFRESH_DERIVER_B_DELTA_Y_V1),
                    delta_tau_hex: encode_hex(&deriver_b_delta_tau),
                },
                combined_delta_y_hex: encode_hex(&REFRESH_DELTA_Y_V1),
                combined_delta_tau_hex: encode_hex(&delta_tau_bytes),
            },
            after_contributions: kdf_contribution_vector_v1(refreshed_a, refreshed_b),
            before_clear_reference_trace: before_trace,
            after_clear_reference_trace: after_trace,
        },
        before_public,
    }
}

fn build_refresh_activation_continuation_v1(
    pending_public: RefreshPendingPublicStateV1,
) -> RefreshActivationContinuationV1 {
    let activated_public = RefreshActivatedPublicStateV1 {
        identity: pending_public.identity.clone(),
        active_role_epochs: pending_public.next_role_epochs,
        retired_role_input_state_epochs: RetiredRoleInputEpochPairV1 {
            deriver_a: pending_public
                .current_role_epochs
                .deriver_a
                .role_input_state_epoch,
            deriver_b: pending_public
                .current_role_epochs
                .deriver_b
                .role_input_state_epoch,
        },
        active_activation_epoch: pending_public.pending_activation_epoch,
        derivation_admission: OpenAdmissionV1::Open,
    };

    RefreshActivationContinuationV1 {
        case_id: REFRESH_ACTIVATION_CASE_ID_V1.to_owned(),
        origin_case_id: REFRESH_CONTINUITY_CASE_ID_V1.to_owned(),
        pending_public,
        activated_public,
        reference_operation_counts: activation_reference_operation_counts_v1(),
    }
}

fn fixture_identity_v1(
    material: &CanonicalSyntheticKdfMaterialV1,
    trace: &KdfClearReferenceTraceV1,
) -> FixtureIdentityV1 {
    let application_binding_encoding = material.application_binding.encode();
    let application_binding_digest = material.application_binding.digest();

    FixtureIdentityV1 {
        application_binding: KdfApplicationBindingVectorV1 {
            wallet_id: SYNTHETIC_WALLET_ID_V1.to_owned(),
            near_ed25519_signing_key_id: SYNTHETIC_SIGNING_KEY_ID_V1.to_owned(),
            signing_root_id: SYNTHETIC_SIGNING_ROOT_ID_V1.to_owned(),
            key_creation_signer_slot: SYNTHETIC_KEY_CREATION_SIGNER_SLOT_V1,
            encoded_hex: encode_hex(application_binding_encoding.as_bytes()),
            digest_sha256_hex: encode_hex(application_binding_digest.as_bytes()),
        },
        context: KdfStableContextVectorV1 {
            application_binding_digest_hex: encode_hex(
                material.context.application_binding_digest().as_bytes(),
            ),
            participant_ids: material.context.participant_ids().as_array(),
            encoded_hex: encode_hex(material.context.encode().as_bytes()),
            binding_sha256_hex: encode_hex(material.context.binding_digest().as_bytes()),
        },
        registered_public_key_hex: trace.public_key_hex.clone(),
        x_client_point_hex: trace.x_client_point_hex.clone(),
        x_server_point_hex: trace.x_server_point_hex.clone(),
    }
}

fn assert_refresh_trace_continuity_v1(
    before: &KdfClearReferenceTraceV1,
    after: &KdfClearReferenceTraceV1,
) {
    assert_ne!(before.y_a_hex, after.y_a_hex);
    assert_ne!(before.y_b_hex, after.y_b_hex);
    assert_ne!(before.tau_a_hex, after.tau_a_hex);
    assert_ne!(before.tau_b_hex, after.tau_b_hex);
    assert_eq!(before.joined_seed_hex, after.joined_seed_hex);
    assert_eq!(before.sha512_digest_hex, after.sha512_digest_hex);
    assert_eq!(
        before.clamped_scalar_bytes_hex,
        after.clamped_scalar_bytes_hex
    );
    assert_eq!(before.signing_scalar_hex, after.signing_scalar_hex);
    assert_eq!(before.tau_hex, after.tau_hex);
    assert_eq!(before.x_client_base_hex, after.x_client_base_hex);
    assert_eq!(before.x_server_base_hex, after.x_server_base_hex);
    assert_eq!(before.x_client_point_hex, after.x_client_point_hex);
    assert_eq!(before.x_server_point_hex, after.x_server_point_hex);
    assert_eq!(before.public_key_hex, after.public_key_hex);
}

fn synthetic_roots_v1() -> KdfSyntheticRootsV1 {
    KdfSyntheticRootsV1 {
        client_root_hex: encode_hex(&SYNTHETIC_CLIENT_ROOT_V1),
        deriver_a_root_hex: encode_hex(&SYNTHETIC_DERIVER_A_ROOT_V1),
        deriver_b_root_hex: encode_hex(&SYNTHETIC_DERIVER_B_ROOT_V1),
    }
}

fn current_role_epochs_v1() -> RoleEpochPairV1 {
    RoleEpochPairV1 {
        deriver_a: RoleEpochV1 {
            role_root_epoch: epoch_v1(DERIVER_A_ROOT_EPOCH_V1),
            role_input_state_epoch: epoch_v1(DERIVER_A_CURRENT_INPUT_EPOCH_V1),
        },
        deriver_b: RoleEpochV1 {
            role_root_epoch: epoch_v1(DERIVER_B_ROOT_EPOCH_V1),
            role_input_state_epoch: epoch_v1(DERIVER_B_CURRENT_INPUT_EPOCH_V1),
        },
    }
}

fn next_role_epochs_v1() -> RoleEpochPairV1 {
    RoleEpochPairV1 {
        deriver_a: RoleEpochV1 {
            role_root_epoch: epoch_v1(DERIVER_A_ROOT_EPOCH_V1),
            role_input_state_epoch: epoch_v1(DERIVER_A_NEXT_INPUT_EPOCH_V1),
        },
        deriver_b: RoleEpochV1 {
            role_root_epoch: epoch_v1(DERIVER_B_ROOT_EPOCH_V1),
            role_input_state_epoch: epoch_v1(DERIVER_B_NEXT_INPUT_EPOCH_V1),
        },
    }
}

fn epoch_v1(value: u64) -> NonZeroEpochV1 {
    NonZeroEpochV1::new(value).expect("canonical lifecycle epoch is nonzero")
}

const fn registration_metadata_reference_operation_counts_v1() -> ReferenceOperationCountsV1 {
    ReferenceOperationCountsV1 {
        deriver_a_invocations: 0,
        deriver_b_invocations: 0,
        client_kdf_derivations_a: 0,
        client_kdf_derivations_b: 0,
        server_kdf_derivations_a: 0,
        server_kdf_derivations_b: 0,
        activation_family_evaluations: 0,
        export_family_evaluations: 0,
        pending_activation_consumptions: 0,
    }
}

const fn recovery_reference_operation_counts_v1() -> ReferenceOperationCountsV1 {
    ReferenceOperationCountsV1 {
        deriver_a_invocations: 1,
        deriver_b_invocations: 1,
        client_kdf_derivations_a: 1,
        client_kdf_derivations_b: 1,
        server_kdf_derivations_a: 0,
        server_kdf_derivations_b: 0,
        activation_family_evaluations: 1,
        export_family_evaluations: 0,
        pending_activation_consumptions: 0,
    }
}

const fn refresh_reference_operation_counts_v1() -> ReferenceOperationCountsV1 {
    ReferenceOperationCountsV1 {
        deriver_a_invocations: 1,
        deriver_b_invocations: 1,
        client_kdf_derivations_a: 0,
        client_kdf_derivations_b: 0,
        server_kdf_derivations_a: 0,
        server_kdf_derivations_b: 0,
        activation_family_evaluations: 1,
        export_family_evaluations: 0,
        pending_activation_consumptions: 0,
    }
}

const fn activation_reference_operation_counts_v1() -> ReferenceOperationCountsV1 {
    ReferenceOperationCountsV1 {
        deriver_a_invocations: 0,
        deriver_b_invocations: 0,
        client_kdf_derivations_a: 0,
        client_kdf_derivations_b: 0,
        server_kdf_derivations_a: 0,
        server_kdf_derivations_b: 0,
        activation_family_evaluations: 0,
        export_family_evaluations: 0,
        pending_activation_consumptions: 1,
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}
