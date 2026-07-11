//! Host-only proof-system-neutral role-input provenance encodings.
//!
//! This module implements only the canonical outer statement contract. It does
//! not implement production root custody, commitment proofs, anti-bias,
//! transcript construction, authorization, persistence, or active Yao.

use core::fmt;
use core::marker::PhantomData;
use core::num::NonZeroU64;

use ed25519_yao::{CircuitDigest32, InputSchemaDigest32};
use sha2::{Digest, Sha256};

use crate::{
    RegisteredEd25519PublicKey32V1, RegisteredEd25519PublicKeyErrorV1, StableKeyDerivationContext,
};

pub use crate::ceremony_context::{
    CeremonyAuthorizationDigest32V1 as AuthorizationDigest32V1,
    CeremonyPublicRequestContextDigest32V1 as PublicRequestContextDigest32V1,
    CeremonyTranscriptDigest32V1,
};
use crate::ceremony_context::{
    CeremonyContextErrorV1, CeremonyRequestKindV1, CeremonyValidatedDagV1,
};

/// Domain for the stable KDF scope encoding.
pub const PROVENANCE_STABLE_SCOPE_ENCODING_DOMAIN_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/provenance/stable-scope/v1";
/// Domain for the ceremony-binding encoding.
pub const PROVENANCE_CEREMONY_BINDING_ENCODING_DOMAIN_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/provenance/ceremony-binding/v1";
/// Domain for a role-input snapshot encoding.
pub const PROVENANCE_ROLE_INPUT_SNAPSHOT_ENCODING_DOMAIN_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/provenance/role-input-snapshot/v1";
/// Domain for the registration branch encoding.
pub const PROVENANCE_REGISTRATION_BRANCH_ENCODING_DOMAIN_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/provenance/registration-branch/v1";
/// Domain for the recovery branch encoding.
pub const PROVENANCE_RECOVERY_BRANCH_ENCODING_DOMAIN_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/provenance/recovery-branch/v1";
/// Domain for the refresh branch encoding.
pub const PROVENANCE_REFRESH_BRANCH_ENCODING_DOMAIN_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/provenance/refresh-branch/v1";
/// Domain for the export branch encoding.
pub const PROVENANCE_EXPORT_BRANCH_ENCODING_DOMAIN_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/provenance/export-branch/v1";
/// Domain for a complete role-input provenance statement encoding.
pub const PROVENANCE_STATEMENT_ENCODING_DOMAIN_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/role-input-provenance-statement/v1";
/// Domain for a complete role-input provenance statement digest.
pub const PROVENANCE_STATEMENT_DIGEST_DOMAIN_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/role-input-provenance-statement-digest/v1";
/// Domain for the ordered A/B statement-pair encoding.
pub const PROVENANCE_PAIR_ENCODING_DOMAIN_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/role-input-provenance-pair/v1";
/// Domain for the ordered A/B statement-pair digest.
pub const PROVENANCE_PAIR_DIGEST_DOMAIN_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/role-input-provenance-pair-digest/v1";
/// Domain for the fixed-order A/B client-envelope set digest.
pub const PROVENANCE_CLIENT_ENVELOPE_SET_DIGEST_DOMAIN_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/client-envelope-commitment-set/v1";
/// Domain for proof-system-specific artifact byte wrappers.
pub const PROVENANCE_ARTIFACT_DIGEST_DOMAIN_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/provenance-artifact-digest/v1";

/// Registration evaluation request tag.
pub const PROVENANCE_REGISTRATION_REQUEST_TAG_V1: u8 = 0x01;
/// Reserved activation request tag, which is invalid for provenance statements.
pub const PROVENANCE_ACTIVATION_REQUEST_TAG_V1: u8 = 0x02;
/// Recovery evaluation request tag.
pub const PROVENANCE_RECOVERY_REQUEST_TAG_V1: u8 = 0x03;
/// Refresh evaluation request tag.
pub const PROVENANCE_REFRESH_REQUEST_TAG_V1: u8 = 0x04;
/// Authorized export evaluation request tag.
pub const PROVENANCE_EXPORT_REQUEST_TAG_V1: u8 = 0x05;
/// Deriver A role tag.
pub const PROVENANCE_DERIVER_A_ROLE_TAG_V1: u8 = 0x01;
/// Deriver B role tag.
pub const PROVENANCE_DERIVER_B_ROLE_TAG_V1: u8 = 0x02;
/// Activation-family circuit tag.
pub const PROVENANCE_ACTIVATION_FAMILY_TAG_V1: u8 = 0x01;
/// Export-family circuit tag.
pub const PROVENANCE_EXPORT_FAMILY_TAG_V1: u8 = 0x02;

/// Error while constructing or encoding host-only provenance evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProvenanceEncodingErrorV1 {
    /// One LP32 value exceeded the version-one U32 length limit.
    ValueTooLong,
}

impl fmt::Display for ProvenanceEncodingErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ValueTooLong => formatter.write_str("provenance LP32 value exceeds U32 length"),
        }
    }
}

impl std::error::Error for ProvenanceEncodingErrorV1 {}

/// Validation error for a role-scoped epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProvenanceEpochErrorV1 {
    /// Epoch zero is invalid.
    Zero,
    /// A proposed next epoch did not strictly advance.
    DidNotStrictlyAdvance,
}

impl fmt::Display for ProvenanceEpochErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Zero => formatter.write_str("provenance epoch must be nonzero"),
            Self::DidNotStrictlyAdvance => {
                formatter.write_str("role-input-state epoch must strictly advance")
            }
        }
    }
}

impl std::error::Error for ProvenanceEpochErrorV1 {}

/// Validation error for one synthetic refresh branch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshProvenanceErrorV1 {
    /// The before and after snapshots referenced different role-root records.
    RoleRootRecordChanged,
    /// The before and after snapshots changed the role-root epoch.
    RoleRootEpochChanged,
    /// The before and after snapshots changed the root-binding artifact.
    RootBindingArtifactChanged,
    /// The role-input-state epoch failed to advance.
    InputStateEpoch(ProvenanceEpochErrorV1),
}

impl fmt::Display for RefreshProvenanceErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RoleRootRecordChanged => {
                formatter.write_str("refresh changed the role-root record")
            }
            Self::RoleRootEpochChanged => {
                formatter.write_str("refresh changed the role-root epoch")
            }
            Self::RootBindingArtifactChanged => {
                formatter.write_str("refresh changed the root-binding artifact")
            }
            Self::InputStateEpoch(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for RefreshProvenanceErrorV1 {}

/// Failure while narrowing a coherent ceremony DAG into evaluation provenance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CeremonyProvenanceErrorV1 {
    /// Activation control has no evaluation provenance statement.
    ActivationHasNoEvaluationProvenance,
    /// A statement common surface received another ceremony branch.
    StatementRequestKindMismatch,
    /// Canonical ceremony encoding or hashing failed.
    Ceremony(CeremonyContextErrorV1),
}

impl fmt::Display for CeremonyProvenanceErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ActivationHasNoEvaluationProvenance => {
                formatter.write_str("activation control has no evaluation provenance")
            }
            Self::StatementRequestKindMismatch => {
                formatter.write_str("ceremony request kind does not match statement branch")
            }
            Self::Ceremony(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for CeremonyProvenanceErrorV1 {}

impl From<CeremonyContextErrorV1> for CeremonyProvenanceErrorV1 {
    fn from(error: CeremonyContextErrorV1) -> Self {
        Self::Ceremony(error)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct Digest32([u8; 32]);

impl Digest32 {
    const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

macro_rules! define_fixture_digest {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name(Digest32);

        impl $name {
            /// Creates a digest slot from public synthetic fixture bytes.
            ///
            /// This host-only constructor is not production provenance evidence.
            pub const fn from_synthetic_fixture_bytes(bytes: [u8; 32]) -> Self {
                Self(Digest32::from_bytes(bytes))
            }

            /// Returns the exact digest bytes.
            pub const fn as_bytes(&self) -> &[u8; 32] {
                self.0.as_bytes()
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "([synthetic digest])"))
            }
        }
    };
}

define_fixture_digest!(/// Synthetic registration-intent digest slot.
    RegistrationIntentDigest32V1);

mod sealed {
    pub trait Sealed {}
}

/// Sealed Deriver role accepted by role-scoped provenance types.
pub trait ProvenanceRoleV1:
    sealed::Sealed + Copy + Clone + fmt::Debug + PartialEq + Eq + 'static
{
    /// Fixed version-one role tag.
    const TAG: u8;
    /// Public role discriminant.
    const KIND: ProvenanceRoleKindV1;
}

/// Deriver A role marker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DeriverAProvenanceRoleV1;

impl sealed::Sealed for DeriverAProvenanceRoleV1 {}

impl ProvenanceRoleV1 for DeriverAProvenanceRoleV1 {
    const TAG: u8 = PROVENANCE_DERIVER_A_ROLE_TAG_V1;
    const KIND: ProvenanceRoleKindV1 = ProvenanceRoleKindV1::DeriverA;
}

/// Deriver B role marker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DeriverBProvenanceRoleV1;

impl sealed::Sealed for DeriverBProvenanceRoleV1 {}

impl ProvenanceRoleV1 for DeriverBProvenanceRoleV1 {
    const TAG: u8 = PROVENANCE_DERIVER_B_ROLE_TAG_V1;
    const KIND: ProvenanceRoleKindV1 = ProvenanceRoleKindV1::DeriverB;
}

/// Public Deriver role discriminant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProvenanceRoleKindV1 {
    /// Deriver A.
    DeriverA,
    /// Deriver B.
    DeriverB,
}

/// Evaluation request kind represented by a provenance statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProvenanceRequestKindV1 {
    /// New-key registration.
    Registration,
    /// Same-root recovery.
    Recovery,
    /// Opposite-delta refresh.
    Refresh,
    /// Explicitly authorized seed export.
    Export,
}

impl ProvenanceRequestKindV1 {
    /// Returns the fixed request tag.
    pub const fn tag(self) -> u8 {
        match self {
            Self::Registration => PROVENANCE_REGISTRATION_REQUEST_TAG_V1,
            Self::Recovery => PROVENANCE_RECOVERY_REQUEST_TAG_V1,
            Self::Refresh => PROVENANCE_REFRESH_REQUEST_TAG_V1,
            Self::Export => PROVENANCE_EXPORT_REQUEST_TAG_V1,
        }
    }

    fn from_ceremony(
        request_kind: CeremonyRequestKindV1,
    ) -> Result<Self, CeremonyProvenanceErrorV1> {
        match request_kind {
            CeremonyRequestKindV1::Registration => Ok(Self::Registration),
            CeremonyRequestKindV1::Recovery => Ok(Self::Recovery),
            CeremonyRequestKindV1::Refresh => Ok(Self::Refresh),
            CeremonyRequestKindV1::Export => Ok(Self::Export),
            CeremonyRequestKindV1::Activation => {
                Err(CeremonyProvenanceErrorV1::ActivationHasNoEvaluationProvenance)
            }
        }
    }
}

/// Circuit family derived from the lifecycle branch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProvenanceCircuitFamilyV1 {
    /// Activation-family circuit.
    Activation,
    /// Export-family circuit.
    Export,
}

impl ProvenanceCircuitFamilyV1 {
    /// Returns the fixed family tag.
    pub const fn tag(self) -> u8 {
        match self {
            Self::Activation => PROVENANCE_ACTIVATION_FAMILY_TAG_V1,
            Self::Export => PROVENANCE_EXPORT_FAMILY_TAG_V1,
        }
    }

    const fn circuit_id(self) -> &'static str {
        match self {
            Self::Activation => ed25519_yao::ACTIVATION_CIRCUIT_ID_STR,
            Self::Export => ed25519_yao::EXPORT_CIRCUIT_ID_STR,
        }
    }
}

/// Proof-system-neutral artifact kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProvenanceArtifactKindV1 {
    /// Role-root binding artifact.
    RoleRootBinding,
    /// Client-input binding artifact.
    ClientInputBinding,
    /// Server-input binding artifact.
    ServerInputBinding,
    /// Combined role-input binding artifact.
    CombinedRoleInputBinding,
    /// Client-envelope commitment artifact.
    ClientEnvelopeCommitment,
    /// Registration anti-bias evidence artifact.
    RegistrationAntiBiasEvidence,
    /// Recovery same-root continuity artifact.
    RecoverySameRootContinuity,
    /// Refresh opposite-delta transition artifact.
    RefreshOppositeDeltaTransition,
}

impl ProvenanceArtifactKindV1 {
    /// Returns the fixed artifact-kind tag.
    pub const fn tag(self) -> u8 {
        match self {
            Self::RoleRootBinding => 0x01,
            Self::ClientInputBinding => 0x02,
            Self::ServerInputBinding => 0x03,
            Self::CombinedRoleInputBinding => 0x04,
            Self::ClientEnvelopeCommitment => 0x05,
            Self::RegistrationAntiBiasEvidence => 0x06,
            Self::RecoverySameRootContinuity => 0x07,
            Self::RefreshOppositeDeltaTransition => 0x08,
        }
    }
}

/// Computed SHA-256 wrapper for public synthetic artifact bytes.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ComputedProvenanceArtifactDigestV1 {
    kind: ProvenanceArtifactKindV1,
    digest: Digest32,
}

impl ComputedProvenanceArtifactDigestV1 {
    /// Computes the frozen artifact wrapper over public synthetic bytes.
    ///
    /// The wrapper provides byte binding only and is not a hiding commitment or proof.
    pub fn compute(
        kind: ProvenanceArtifactKindV1,
        canonical_artifact_bytes: &[u8],
    ) -> Result<Self, ProvenanceEncodingErrorV1> {
        let mut encoding = Vec::new();
        push_lp32(&mut encoding, PROVENANCE_ARTIFACT_DIGEST_DOMAIN_V1)?;
        push_lp32(&mut encoding, &[kind.tag()])?;
        push_lp32(&mut encoding, canonical_artifact_bytes)?;
        Ok(Self {
            kind,
            digest: Digest32::from_bytes(Sha256::digest(&encoding).into()),
        })
    }

    /// Returns the bound artifact kind.
    pub const fn kind(&self) -> ProvenanceArtifactKindV1 {
        self.kind
    }

    /// Returns the computed digest bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        self.digest.as_bytes()
    }
}

impl fmt::Debug for ComputedProvenanceArtifactDigestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ComputedProvenanceArtifactDigestV1")
            .field("kind", &self.kind)
            .field("digest", &"[computed SHA-256]")
            .finish()
    }
}

macro_rules! define_role_fixture_digest {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name<Role: ProvenanceRoleV1>(Digest32, PhantomData<Role>);

        impl<Role: ProvenanceRoleV1> $name<Role> {
            /// Creates a role-scoped digest slot from public synthetic fixture bytes.
            pub const fn from_synthetic_fixture_bytes(bytes: [u8; 32]) -> Self {
                Self(Digest32::from_bytes(bytes), PhantomData)
            }

            /// Returns the exact digest bytes.
            pub const fn as_bytes(&self) -> &[u8; 32] {
                self.0.as_bytes()
            }
        }

        impl<Role: ProvenanceRoleV1> fmt::Debug for $name<Role> {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "([role-scoped fixture digest])"))
            }
        }
    };
}

define_role_fixture_digest!(/// Authenticated role-root record digest slot.
    RoleRootRecordDigest32V1);
define_role_fixture_digest!(/// Authenticated role-input-state record digest slot.
    RoleInputStateRecordDigest32V1);

macro_rules! define_role_artifact_digest {
    ($(#[$meta:meta])* $name:ident, $kind:expr) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name<Role: ProvenanceRoleV1>(Digest32, PhantomData<Role>);

        impl<Role: ProvenanceRoleV1> $name<Role> {
            /// Computes this role-scoped slot from public synthetic artifact bytes.
            pub fn from_synthetic_artifact_bytes(
                canonical_artifact_bytes: &[u8],
            ) -> Result<Self, ProvenanceEncodingErrorV1> {
                let computed = ComputedProvenanceArtifactDigestV1::compute(
                    $kind,
                    canonical_artifact_bytes,
                )?;
                Ok(Self(computed.digest, PhantomData))
            }

            /// Returns the computed artifact-wrapper digest bytes.
            pub const fn as_bytes(&self) -> &[u8; 32] {
                self.0.as_bytes()
            }
        }

        impl<Role: ProvenanceRoleV1> fmt::Debug for $name<Role> {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "([computed artifact digest])"))
            }
        }
    };
}

define_role_artifact_digest!(
    /// Role-root binding artifact digest.
    RootBindingArtifactDigest32V1,
    ProvenanceArtifactKindV1::RoleRootBinding
);
define_role_artifact_digest!(
    /// Client-input binding artifact digest.
    ClientInputArtifactDigest32V1,
    ProvenanceArtifactKindV1::ClientInputBinding
);
define_role_artifact_digest!(
    /// Server-input binding artifact digest.
    ServerInputArtifactDigest32V1,
    ProvenanceArtifactKindV1::ServerInputBinding
);
define_role_artifact_digest!(
    /// Combined role-input binding artifact digest.
    CombinedInputArtifactDigest32V1,
    ProvenanceArtifactKindV1::CombinedRoleInputBinding
);
define_role_artifact_digest!(
    /// Client-envelope commitment artifact digest.
    ClientEnvelopeArtifactDigest32V1,
    ProvenanceArtifactKindV1::ClientEnvelopeCommitment
);

macro_rules! define_artifact_digest {
    ($(#[$meta:meta])* $name:ident, $kind:expr) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name(Digest32);

        impl $name {
            /// Computes this slot from public synthetic artifact bytes.
            pub fn from_synthetic_artifact_bytes(
                canonical_artifact_bytes: &[u8],
            ) -> Result<Self, ProvenanceEncodingErrorV1> {
                ComputedProvenanceArtifactDigestV1::compute($kind, canonical_artifact_bytes)
                    .map(|computed| Self(computed.digest))
            }

            /// Returns the computed artifact-wrapper digest bytes.
            pub const fn as_bytes(&self) -> &[u8; 32] {
                self.0.as_bytes()
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "([computed artifact digest])"))
            }
        }
    };
}

define_artifact_digest!(
    /// Registration anti-bias artifact digest.
    RegistrationAntiBiasArtifactDigest32V1,
    ProvenanceArtifactKindV1::RegistrationAntiBiasEvidence
);
define_artifact_digest!(
    /// Recovery same-root continuity artifact digest.
    RecoveryContinuityArtifactDigest32V1,
    ProvenanceArtifactKindV1::RecoverySameRootContinuity
);
define_artifact_digest!(
    /// Refresh opposite-delta continuity artifact digest.
    RefreshContinuityArtifactDigest32V1,
    ProvenanceArtifactKindV1::RefreshOppositeDeltaTransition
);

/// Fixed-order A/B client-envelope-set digest.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ClientEnvelopeSetDigest32V1(Digest32);

impl ClientEnvelopeSetDigest32V1 {
    /// Computes the set digest in fixed Deriver A then Deriver B order.
    pub fn compute(
        deriver_a: &ClientEnvelopeArtifactDigest32V1<DeriverAProvenanceRoleV1>,
        deriver_b: &ClientEnvelopeArtifactDigest32V1<DeriverBProvenanceRoleV1>,
    ) -> Result<Self, ProvenanceEncodingErrorV1> {
        let mut encoding = Vec::new();
        push_lp32(
            &mut encoding,
            PROVENANCE_CLIENT_ENVELOPE_SET_DIGEST_DOMAIN_V1,
        )?;
        push_lp32(&mut encoding, deriver_a.as_bytes())?;
        push_lp32(&mut encoding, deriver_b.as_bytes())?;
        Ok(Self(Digest32::from_bytes(Sha256::digest(&encoding).into())))
    }

    /// Returns the computed digest bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}

impl fmt::Debug for ClientEnvelopeSetDigest32V1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ClientEnvelopeSetDigest32V1([computed SHA-256])")
    }
}

/// Nonzero role-root epoch with a sealed role type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct RoleRootEpochV1<Role: ProvenanceRoleV1>(NonZeroU64, PhantomData<Role>);

impl<Role: ProvenanceRoleV1> RoleRootEpochV1<Role> {
    /// Validates a nonzero role-root epoch.
    pub const fn new(value: u64) -> Result<Self, ProvenanceEpochErrorV1> {
        match NonZeroU64::new(value) {
            Some(value) => Ok(Self(value, PhantomData)),
            None => Err(ProvenanceEpochErrorV1::Zero),
        }
    }

    /// Returns the epoch number.
    pub const fn value(self) -> u64 {
        self.0.get()
    }
}

/// Nonzero role-input-state epoch with a sealed role type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct RoleInputStateEpochV1<Role: ProvenanceRoleV1>(NonZeroU64, PhantomData<Role>);

impl<Role: ProvenanceRoleV1> RoleInputStateEpochV1<Role> {
    /// Validates a nonzero role-input-state epoch.
    pub const fn new(value: u64) -> Result<Self, ProvenanceEpochErrorV1> {
        match NonZeroU64::new(value) {
            Some(value) => Ok(Self(value, PhantomData)),
            None => Err(ProvenanceEpochErrorV1::Zero),
        }
    }

    /// Returns the epoch number.
    pub const fn value(self) -> u64 {
        self.0.get()
    }

    const fn is_strictly_after(self, before: Self) -> bool {
        self.0.get() > before.0.get()
    }
}

/// Exact immutable stable KDF scope copied from the frozen context constructor.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct StableKdfScopeV1 {
    application_binding_digest: Digest32,
    participant_ids: [u16; 2],
    stable_context_binding_digest: Digest32,
}

impl fmt::Debug for StableKdfScopeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StableKdfScopeV1")
            .field("application_binding_digest", &"[public digest]")
            .field("participant_ids", &self.participant_ids)
            .field("stable_context_binding_digest", &"[public digest]")
            .finish()
    }
}

impl StableKdfScopeV1 {
    /// Constructs the scope from the validated stable-context owner.
    pub fn from_context(context: &StableKeyDerivationContext) -> Self {
        Self {
            application_binding_digest: Digest32::from_bytes(
                *context.application_binding_digest().as_bytes(),
            ),
            participant_ids: context.participant_ids().as_array(),
            stable_context_binding_digest: Digest32::from_bytes(
                *context.binding_digest().as_bytes(),
            ),
        }
    }

    /// Returns the immutable application-binding digest.
    pub const fn application_binding_digest(&self) -> &[u8; 32] {
        self.application_binding_digest.as_bytes()
    }

    /// Returns the canonical ascending participant identifiers.
    pub const fn participant_ids(&self) -> [u16; 2] {
        self.participant_ids
    }

    /// Returns the frozen stable-context binding digest.
    pub const fn stable_context_binding_digest(&self) -> &[u8; 32] {
        self.stable_context_binding_digest.as_bytes()
    }

    /// Encodes the canonical LP32 stable scope.
    pub fn encode(&self) -> Result<Vec<u8>, ProvenanceEncodingErrorV1> {
        let mut output = Vec::new();
        push_lp32(&mut output, PROVENANCE_STABLE_SCOPE_ENCODING_DOMAIN_V1)?;
        push_lp32(&mut output, self.application_binding_digest.as_bytes())?;
        push_lp32(&mut output, &self.participant_ids[0].to_be_bytes())?;
        push_lp32(&mut output, &self.participant_ids[1].to_be_bytes())?;
        push_lp32(&mut output, self.stable_context_binding_digest.as_bytes())?;
        Ok(output)
    }
}

/// Role-specific ceremony digest slots for a synthetic outer statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CeremonyProvenanceBindingV1<Role: ProvenanceRoleV1> {
    request_kind: ProvenanceRequestKindV1,
    public_request_context_digest: PublicRequestContextDigest32V1,
    transcript_digest: CeremonyTranscriptDigest32V1,
    authorization_digest: AuthorizationDigest32V1,
    client_envelope_artifact_digest: ClientEnvelopeArtifactDigest32V1<Role>,
    client_envelope_set_digest: ClientEnvelopeSetDigest32V1,
}

impl<Role: ProvenanceRoleV1> CeremonyProvenanceBindingV1<Role> {
    /// Creates an outer binding from one sealed coherent ceremony DAG.
    pub fn from_validated_ceremony(
        ceremony: CeremonyValidatedDagV1,
        client_envelope_artifact_digest: ClientEnvelopeArtifactDigest32V1<Role>,
        client_envelope_set_digest: ClientEnvelopeSetDigest32V1,
    ) -> Result<Self, CeremonyProvenanceErrorV1> {
        Ok(Self {
            request_kind: ProvenanceRequestKindV1::from_ceremony(ceremony.request_kind())?,
            public_request_context_digest: ceremony.request_context_digest(),
            transcript_digest: ceremony.transcript_digest(),
            authorization_digest: ceremony.authorization_digest(),
            client_envelope_artifact_digest,
            client_envelope_set_digest,
        })
    }

    /// Returns the evaluation request kind sealed by the ceremony DAG.
    pub const fn request_kind(&self) -> ProvenanceRequestKindV1 {
        self.request_kind
    }

    /// Encodes the canonical LP32 ceremony binding.
    pub fn encode(&self) -> Result<Vec<u8>, ProvenanceEncodingErrorV1> {
        let mut output = Vec::new();
        push_lp32(&mut output, PROVENANCE_CEREMONY_BINDING_ENCODING_DOMAIN_V1)?;
        push_lp32(&mut output, &[self.request_kind.tag()])?;
        push_lp32(&mut output, self.public_request_context_digest.as_bytes())?;
        push_lp32(&mut output, self.transcript_digest.as_bytes())?;
        push_lp32(&mut output, self.authorization_digest.as_bytes())?;
        push_lp32(&mut output, self.client_envelope_artifact_digest.as_bytes())?;
        push_lp32(&mut output, self.client_envelope_set_digest.as_bytes())?;
        Ok(output)
    }
}

/// Complete role-scoped snapshot digest surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoleInputSnapshotV1<Role: ProvenanceRoleV1> {
    role_root_record_digest: RoleRootRecordDigest32V1<Role>,
    root_binding_artifact_digest: RootBindingArtifactDigest32V1<Role>,
    role_root_epoch: RoleRootEpochV1<Role>,
    role_input_state_record_digest: RoleInputStateRecordDigest32V1<Role>,
    role_input_state_epoch: RoleInputStateEpochV1<Role>,
    client_input_artifact_digest: ClientInputArtifactDigest32V1<Role>,
    server_input_artifact_digest: ServerInputArtifactDigest32V1<Role>,
    combined_input_artifact_digest: CombinedInputArtifactDigest32V1<Role>,
}

impl<Role: ProvenanceRoleV1> RoleInputSnapshotV1<Role> {
    /// Constructs a role-typed synthetic snapshot.
    #[allow(clippy::too_many_arguments)]
    pub const fn from_synthetic_fixture(
        role_root_record_digest: RoleRootRecordDigest32V1<Role>,
        root_binding_artifact_digest: RootBindingArtifactDigest32V1<Role>,
        role_root_epoch: RoleRootEpochV1<Role>,
        role_input_state_record_digest: RoleInputStateRecordDigest32V1<Role>,
        role_input_state_epoch: RoleInputStateEpochV1<Role>,
        client_input_artifact_digest: ClientInputArtifactDigest32V1<Role>,
        server_input_artifact_digest: ServerInputArtifactDigest32V1<Role>,
        combined_input_artifact_digest: CombinedInputArtifactDigest32V1<Role>,
    ) -> Self {
        Self {
            role_root_record_digest,
            root_binding_artifact_digest,
            role_root_epoch,
            role_input_state_record_digest,
            role_input_state_epoch,
            client_input_artifact_digest,
            server_input_artifact_digest,
            combined_input_artifact_digest,
        }
    }

    /// Returns the role-root record digest.
    pub const fn role_root_record_digest(&self) -> &RoleRootRecordDigest32V1<Role> {
        &self.role_root_record_digest
    }

    /// Returns the role-root epoch.
    pub const fn role_root_epoch(&self) -> RoleRootEpochV1<Role> {
        self.role_root_epoch
    }

    /// Returns the role-input-state epoch.
    pub const fn role_input_state_epoch(&self) -> RoleInputStateEpochV1<Role> {
        self.role_input_state_epoch
    }

    /// Encodes the canonical LP32 role-input snapshot.
    pub fn encode(&self) -> Result<Vec<u8>, ProvenanceEncodingErrorV1> {
        let mut output = Vec::new();
        push_lp32(
            &mut output,
            PROVENANCE_ROLE_INPUT_SNAPSHOT_ENCODING_DOMAIN_V1,
        )?;
        push_lp32(&mut output, self.role_root_record_digest.as_bytes())?;
        push_lp32(&mut output, self.root_binding_artifact_digest.as_bytes())?;
        push_lp32(&mut output, &self.role_root_epoch.value().to_be_bytes())?;
        push_lp32(&mut output, self.role_input_state_record_digest.as_bytes())?;
        push_lp32(
            &mut output,
            &self.role_input_state_epoch.value().to_be_bytes(),
        )?;
        push_lp32(&mut output, self.client_input_artifact_digest.as_bytes())?;
        push_lp32(&mut output, self.server_input_artifact_digest.as_bytes())?;
        push_lp32(&mut output, self.combined_input_artifact_digest.as_bytes())?;
        Ok(output)
    }
}

/// Activation-family final circuit and input-schema binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActivationCircuitBindingV1 {
    circuit_digest: CircuitDigest32,
    input_schema_digest: InputSchemaDigest32,
}

impl ActivationCircuitBindingV1 {
    /// Constructs a typed activation-family binding.
    pub const fn new(
        circuit_digest: CircuitDigest32,
        input_schema_digest: InputSchemaDigest32,
    ) -> Self {
        Self {
            circuit_digest,
            input_schema_digest,
        }
    }
}

/// Export-family final circuit and input-schema binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExportCircuitBindingV1 {
    circuit_digest: CircuitDigest32,
    input_schema_digest: InputSchemaDigest32,
}

impl ExportCircuitBindingV1 {
    /// Constructs a typed export-family binding.
    pub const fn new(
        circuit_digest: CircuitDigest32,
        input_schema_digest: InputSchemaDigest32,
    ) -> Self {
        Self {
            circuit_digest,
            input_schema_digest,
        }
    }
}

/// Registration-specific role statement branch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegistrationBranchV1<Role: ProvenanceRoleV1> {
    initial_snapshot: RoleInputSnapshotV1<Role>,
    registration_intent_digest: RegistrationIntentDigest32V1,
    anti_bias_evidence_artifact_digest: RegistrationAntiBiasArtifactDigest32V1,
}

impl<Role: ProvenanceRoleV1> RegistrationBranchV1<Role> {
    /// Creates the mandatory registration branch slots.
    pub const fn new(
        initial_snapshot: RoleInputSnapshotV1<Role>,
        registration_intent_digest: RegistrationIntentDigest32V1,
        anti_bias_evidence_artifact_digest: RegistrationAntiBiasArtifactDigest32V1,
    ) -> Self {
        Self {
            initial_snapshot,
            registration_intent_digest,
            anti_bias_evidence_artifact_digest,
        }
    }

    /// Encodes the canonical LP32 registration branch.
    pub fn encode(&self) -> Result<Vec<u8>, ProvenanceEncodingErrorV1> {
        let mut output = Vec::new();
        push_lp32(
            &mut output,
            PROVENANCE_REGISTRATION_BRANCH_ENCODING_DOMAIN_V1,
        )?;
        push_lp32(&mut output, &self.initial_snapshot.encode()?)?;
        push_lp32(&mut output, self.registration_intent_digest.as_bytes())?;
        push_lp32(
            &mut output,
            self.anti_bias_evidence_artifact_digest.as_bytes(),
        )?;
        Ok(output)
    }
}

/// Recovery-specific role statement branch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryBranchV1<Role: ProvenanceRoleV1> {
    current_snapshot: RoleInputSnapshotV1<Role>,
    registered_public_key: RegisteredEd25519PublicKey32V1,
    same_root_evidence_artifact_digest: RecoveryContinuityArtifactDigest32V1,
}

impl<Role: ProvenanceRoleV1> RecoveryBranchV1<Role> {
    /// Creates the mandatory same-root recovery branch slots.
    pub const fn new(
        current_snapshot: RoleInputSnapshotV1<Role>,
        registered_public_key: RegisteredEd25519PublicKey32V1,
        same_root_evidence_artifact_digest: RecoveryContinuityArtifactDigest32V1,
    ) -> Self {
        Self {
            current_snapshot,
            registered_public_key,
            same_root_evidence_artifact_digest,
        }
    }

    /// Encodes the canonical LP32 recovery branch.
    pub fn encode(&self) -> Result<Vec<u8>, ProvenanceEncodingErrorV1> {
        let mut output = Vec::new();
        push_lp32(&mut output, PROVENANCE_RECOVERY_BRANCH_ENCODING_DOMAIN_V1)?;
        push_lp32(&mut output, &self.current_snapshot.encode()?)?;
        push_lp32(&mut output, self.registered_public_key.as_bytes())?;
        push_lp32(
            &mut output,
            self.same_root_evidence_artifact_digest.as_bytes(),
        )?;
        Ok(output)
    }
}

/// Refresh-specific before/after role statement branch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RefreshBranchV1<Role: ProvenanceRoleV1> {
    before_snapshot: RoleInputSnapshotV1<Role>,
    after_snapshot: RoleInputSnapshotV1<Role>,
    registered_public_key: RegisteredEd25519PublicKey32V1,
    continuity_evidence_artifact_digest: RefreshContinuityArtifactDigest32V1,
}

impl<Role: ProvenanceRoleV1> RefreshBranchV1<Role> {
    /// Validates the outer root/epoch continuity requirements for refresh.
    pub fn new(
        before_snapshot: RoleInputSnapshotV1<Role>,
        after_snapshot: RoleInputSnapshotV1<Role>,
        registered_public_key: RegisteredEd25519PublicKey32V1,
        continuity_evidence_artifact_digest: RefreshContinuityArtifactDigest32V1,
    ) -> Result<Self, RefreshProvenanceErrorV1> {
        if before_snapshot.role_root_record_digest != after_snapshot.role_root_record_digest {
            return Err(RefreshProvenanceErrorV1::RoleRootRecordChanged);
        }
        if before_snapshot.role_root_epoch != after_snapshot.role_root_epoch {
            return Err(RefreshProvenanceErrorV1::RoleRootEpochChanged);
        }
        if before_snapshot.root_binding_artifact_digest
            != after_snapshot.root_binding_artifact_digest
        {
            return Err(RefreshProvenanceErrorV1::RootBindingArtifactChanged);
        }
        if !after_snapshot
            .role_input_state_epoch
            .is_strictly_after(before_snapshot.role_input_state_epoch)
        {
            return Err(RefreshProvenanceErrorV1::InputStateEpoch(
                ProvenanceEpochErrorV1::DidNotStrictlyAdvance,
            ));
        }
        Ok(Self {
            before_snapshot,
            after_snapshot,
            registered_public_key,
            continuity_evidence_artifact_digest,
        })
    }

    /// Encodes the canonical LP32 refresh branch.
    pub fn encode(&self) -> Result<Vec<u8>, ProvenanceEncodingErrorV1> {
        let mut output = Vec::new();
        push_lp32(&mut output, PROVENANCE_REFRESH_BRANCH_ENCODING_DOMAIN_V1)?;
        push_lp32(&mut output, &self.before_snapshot.encode()?)?;
        push_lp32(&mut output, &self.after_snapshot.encode()?)?;
        push_lp32(&mut output, self.registered_public_key.as_bytes())?;
        push_lp32(
            &mut output,
            self.continuity_evidence_artifact_digest.as_bytes(),
        )?;
        Ok(output)
    }
}

/// Export-specific current-state role statement branch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExportBranchV1<Role: ProvenanceRoleV1> {
    current_snapshot: RoleInputSnapshotV1<Role>,
    registered_public_key: RegisteredEd25519PublicKey32V1,
}

impl<Role: ProvenanceRoleV1> ExportBranchV1<Role> {
    /// Creates the export branch without any transition-evidence slot.
    pub const fn new(
        current_snapshot: RoleInputSnapshotV1<Role>,
        registered_public_key: RegisteredEd25519PublicKey32V1,
    ) -> Self {
        Self {
            current_snapshot,
            registered_public_key,
        }
    }

    /// Encodes the canonical LP32 export branch.
    pub fn encode(&self) -> Result<Vec<u8>, ProvenanceEncodingErrorV1> {
        let mut output = Vec::new();
        push_lp32(&mut output, PROVENANCE_EXPORT_BRANCH_ENCODING_DOMAIN_V1)?;
        push_lp32(&mut output, &self.current_snapshot.encode()?)?;
        push_lp32(&mut output, self.registered_public_key.as_bytes())?;
        Ok(output)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EvaluationStatementCommonV1<Role: ProvenanceRoleV1> {
    stable_scope: StableKdfScopeV1,
    ceremony: CeremonyProvenanceBindingV1<Role>,
    circuit_digest: CircuitDigest32,
    input_schema_digest: InputSchemaDigest32,
}

/// Complete registration role-input statement with private fields.
///
/// ```compile_fail
/// use ed25519_yao_generator::provenance::{
///     DeriverAProvenanceRoleV1, RegistrationBranchV1,
///     RegistrationRoleInputStatementV1, RegistrationStatementCommonV1,
/// };
///
/// fn bypass_private_builder(
///     common: RegistrationStatementCommonV1<DeriverAProvenanceRoleV1>,
///     branch: RegistrationBranchV1<DeriverAProvenanceRoleV1>,
/// ) {
///     let _ = RegistrationRoleInputStatementV1 { common, branch };
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrationRoleInputStatementV1<Role: ProvenanceRoleV1> {
    common: RegistrationStatementCommonV1<Role>,
    branch: RegistrationBranchV1<Role>,
}

/// Complete recovery role-input statement with private fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryRoleInputStatementV1<Role: ProvenanceRoleV1> {
    common: RecoveryStatementCommonV1<Role>,
    branch: RecoveryBranchV1<Role>,
}

/// Complete refresh role-input statement with private fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshRoleInputStatementV1<Role: ProvenanceRoleV1> {
    common: RefreshStatementCommonV1<Role>,
    branch: RefreshBranchV1<Role>,
}

/// Complete export role-input statement with private fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportRoleInputStatementV1<Role: ProvenanceRoleV1> {
    common: ExportStatementCommonV1<Role>,
    branch: ExportBranchV1<Role>,
}

/// Branch-typed role-input provenance statement.
///
/// Activation consumes prior packages and has no evaluation statement variant.
///
/// ```compile_fail
/// use ed25519_yao_generator::provenance::{
///     DeriverAProvenanceRoleV1, RoleInputProvenanceStatementV1,
/// };
///
/// let _ = RoleInputProvenanceStatementV1::<DeriverAProvenanceRoleV1>::Activation;
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoleInputProvenanceStatementV1<Role: ProvenanceRoleV1> {
    /// Registration statement.
    Registration(Box<RegistrationRoleInputStatementV1<Role>>),
    /// Same-root recovery statement.
    Recovery(Box<RecoveryRoleInputStatementV1<Role>>),
    /// Opposite-delta refresh statement.
    Refresh(Box<RefreshRoleInputStatementV1<Role>>),
    /// Authorized export statement.
    Export(Box<ExportRoleInputStatementV1<Role>>),
}

macro_rules! define_statement_common {
    ($(#[$meta:meta])* $name:ident, $binding:ty, $request_kind:expr) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub struct $name<Role: ProvenanceRoleV1>(EvaluationStatementCommonV1<Role>);

        impl<Role: ProvenanceRoleV1> $name<Role> {
            /// Constructs the branch-specific common surface.
            pub fn new(
                stable_scope: StableKdfScopeV1,
                ceremony: CeremonyProvenanceBindingV1<Role>,
                circuit: $binding,
            ) -> Result<Self, CeremonyProvenanceErrorV1> {
                if ceremony.request_kind() != $request_kind {
                    return Err(CeremonyProvenanceErrorV1::StatementRequestKindMismatch);
                }
                Ok(Self(EvaluationStatementCommonV1 {
                    stable_scope,
                    ceremony,
                    circuit_digest: circuit.circuit_digest,
                    input_schema_digest: circuit.input_schema_digest,
                }))
            }
        }
    };
}

define_statement_common!(/// Registration activation-family common fields.
    RegistrationStatementCommonV1, ActivationCircuitBindingV1, ProvenanceRequestKindV1::Registration);
define_statement_common!(/// Recovery activation-family common fields.
    RecoveryStatementCommonV1, ActivationCircuitBindingV1, ProvenanceRequestKindV1::Recovery);
define_statement_common!(/// Refresh activation-family common fields.
    RefreshStatementCommonV1, ActivationCircuitBindingV1, ProvenanceRequestKindV1::Refresh);
define_statement_common!(/// Export-family common fields.
    ExportStatementCommonV1, ExportCircuitBindingV1, ProvenanceRequestKindV1::Export);

impl<Role: ProvenanceRoleV1> RoleInputProvenanceStatementV1<Role> {
    /// Constructs a registration statement and derives activation-family dispatch.
    pub fn registration(
        common: RegistrationStatementCommonV1<Role>,
        branch: RegistrationBranchV1<Role>,
    ) -> Self {
        Self::Registration(Box::new(RegistrationRoleInputStatementV1 {
            common,
            branch,
        }))
    }

    /// Constructs a same-root recovery statement and derives activation-family dispatch.
    pub fn recovery(
        common: RecoveryStatementCommonV1<Role>,
        branch: RecoveryBranchV1<Role>,
    ) -> Self {
        Self::Recovery(Box::new(RecoveryRoleInputStatementV1 { common, branch }))
    }

    /// Constructs an opposite-delta refresh statement and derives activation dispatch.
    pub fn refresh(common: RefreshStatementCommonV1<Role>, branch: RefreshBranchV1<Role>) -> Self {
        Self::Refresh(Box::new(RefreshRoleInputStatementV1 { common, branch }))
    }

    /// Constructs an authorized export statement and derives export-family dispatch.
    pub fn export(common: ExportStatementCommonV1<Role>, branch: ExportBranchV1<Role>) -> Self {
        Self::Export(Box::new(ExportRoleInputStatementV1 { common, branch }))
    }

    /// Returns the lifecycle request kind derived from the branch.
    pub const fn request_kind(&self) -> ProvenanceRequestKindV1 {
        match self {
            Self::Registration(_) => ProvenanceRequestKindV1::Registration,
            Self::Recovery(_) => ProvenanceRequestKindV1::Recovery,
            Self::Refresh(_) => ProvenanceRequestKindV1::Refresh,
            Self::Export(_) => ProvenanceRequestKindV1::Export,
        }
    }

    /// Returns the sealed role discriminant.
    pub const fn role(&self) -> ProvenanceRoleKindV1 {
        Role::KIND
    }

    /// Returns the circuit family derived from the branch.
    pub const fn circuit_family(&self) -> ProvenanceCircuitFamilyV1 {
        match self {
            Self::Registration(_) | Self::Recovery(_) | Self::Refresh(_) => {
                ProvenanceCircuitFamilyV1::Activation
            }
            Self::Export(_) => ProvenanceCircuitFamilyV1::Export,
        }
    }

    /// Encodes the exact version-one LP32 statement.
    pub fn encode(&self) -> Result<Vec<u8>, ProvenanceEncodingErrorV1> {
        let request = self.request_kind();
        let family = self.circuit_family();
        let common = self.common();
        let mut output = Vec::new();
        push_lp32(&mut output, PROVENANCE_STATEMENT_ENCODING_DOMAIN_V1)?;
        push_lp32(&mut output, ed25519_yao::PROTOCOL_ID_STR.as_bytes())?;
        push_lp32(&mut output, &[request.tag()])?;
        push_lp32(&mut output, &[Role::TAG])?;
        push_lp32(&mut output, &[family.tag()])?;
        push_lp32(&mut output, family.circuit_id().as_bytes())?;
        push_lp32(&mut output, common.circuit_digest.as_bytes())?;
        push_lp32(&mut output, common.input_schema_digest.as_bytes())?;
        push_lp32(&mut output, &common.stable_scope.encode()?)?;
        push_lp32(&mut output, &common.ceremony.encode()?)?;
        push_lp32(&mut output, &self.branch_encoding()?)?;
        Ok(output)
    }

    /// Computes the canonical statement digest.
    pub fn digest(
        &self,
    ) -> Result<RoleInputProvenanceStatementDigest32V1<Role>, ProvenanceEncodingErrorV1> {
        let encoding = self.encode()?;
        let mut digest_input = Vec::new();
        push_lp32(&mut digest_input, PROVENANCE_STATEMENT_DIGEST_DOMAIN_V1)?;
        push_lp32(&mut digest_input, &encoding)?;
        Ok(RoleInputProvenanceStatementDigest32V1(
            Digest32::from_bytes(Sha256::digest(&digest_input).into()),
            PhantomData,
        ))
    }

    fn common(&self) -> &EvaluationStatementCommonV1<Role> {
        match self {
            Self::Registration(statement) => &statement.common.0,
            Self::Recovery(statement) => &statement.common.0,
            Self::Refresh(statement) => &statement.common.0,
            Self::Export(statement) => &statement.common.0,
        }
    }

    fn branch_encoding(&self) -> Result<Vec<u8>, ProvenanceEncodingErrorV1> {
        match self {
            Self::Registration(statement) => statement.branch.encode(),
            Self::Recovery(statement) => statement.branch.encode(),
            Self::Refresh(statement) => statement.branch.encode(),
            Self::Export(statement) => statement.branch.encode(),
        }
    }
}

/// Internally computed statement digest with a sealed role type.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct RoleInputProvenanceStatementDigest32V1<Role: ProvenanceRoleV1>(
    Digest32,
    PhantomData<Role>,
);

impl<Role: ProvenanceRoleV1> RoleInputProvenanceStatementDigest32V1<Role> {
    /// Returns the computed statement digest bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}

impl<Role: ProvenanceRoleV1> fmt::Debug for RoleInputProvenanceStatementDigest32V1<Role> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RoleInputProvenanceStatementDigest32V1([computed SHA-256])")
    }
}

/// Pair field that failed the construction-independent A/B equality checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProvenancePairFieldV1 {
    /// Lifecycle branch kind.
    RequestKind,
    /// Stable KDF scope.
    StableScope,
    /// Final circuit digest.
    CircuitDigest,
    /// Final input-schema digest.
    InputSchemaDigest,
    /// Public request-context digest.
    PublicRequestContextDigest,
    /// Ceremony transcript digest.
    TranscriptDigest,
    /// Lifecycle authorization digest.
    AuthorizationDigest,
    /// Shared client-envelope-set digest.
    ClientEnvelopeSetDigest,
    /// The set digest did not match the ordered A/B envelope artifacts.
    ClientEnvelopeOrdering,
    /// Registration intent digest.
    RegistrationIntentDigest,
    /// Joint registration anti-bias evidence digest.
    RegistrationAntiBiasDigest,
    /// Registered Ed25519 public key.
    RegisteredPublicKey,
    /// Joint lifecycle continuity evidence digest.
    ContinuityEvidenceDigest,
}

/// Construction-independent A/B pair validation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProvenancePairErrorV1 {
    field: ProvenancePairFieldV1,
}

impl ProvenancePairErrorV1 {
    /// Returns the first mismatched field.
    pub const fn field(self) -> ProvenancePairFieldV1 {
        self.field
    }
}

impl fmt::Display for ProvenancePairErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "A/B provenance pair mismatch at {:?}",
            self.field
        )
    }
}

impl std::error::Error for ProvenancePairErrorV1 {}

/// Ordered, role-typed A/B provenance statement pair.
///
/// ```compile_fail
/// use ed25519_yao_generator::provenance::{
///     DeriverAProvenanceRoleV1, DeriverBProvenanceRoleV1,
///     RoleInputProvenancePairV1, RoleInputProvenanceStatementV1,
/// };
///
/// fn swapped_roles(
///     deriver_b: RoleInputProvenanceStatementV1<DeriverBProvenanceRoleV1>,
///     deriver_a: RoleInputProvenanceStatementV1<DeriverAProvenanceRoleV1>,
/// ) {
///     let _ = RoleInputProvenancePairV1::new(deriver_b, deriver_a);
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleInputProvenancePairV1 {
    deriver_a: RoleInputProvenanceStatementV1<DeriverAProvenanceRoleV1>,
    deriver_b: RoleInputProvenanceStatementV1<DeriverBProvenanceRoleV1>,
}

/// Role-typed input-state record and epoch resolved by provenance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProvenanceRoleStateBindingV1<Role: ProvenanceRoleV1> {
    role_root_record_digest: RoleRootRecordDigest32V1<Role>,
    root_binding_artifact_digest: RootBindingArtifactDigest32V1<Role>,
    role_root_epoch: RoleRootEpochV1<Role>,
    record_digest: RoleInputStateRecordDigest32V1<Role>,
    epoch: RoleInputStateEpochV1<Role>,
}

impl<Role: ProvenanceRoleV1> ProvenanceRoleStateBindingV1<Role> {
    /// Returns the role-root record digest.
    pub const fn role_root_record_digest(&self) -> RoleRootRecordDigest32V1<Role> {
        self.role_root_record_digest
    }

    /// Returns the root-binding artifact digest.
    pub const fn root_binding_artifact_digest(&self) -> RootBindingArtifactDigest32V1<Role> {
        self.root_binding_artifact_digest
    }

    /// Returns the role-root epoch.
    pub const fn role_root_epoch(&self) -> RoleRootEpochV1<Role> {
        self.role_root_epoch
    }

    /// Returns the role-scoped state-record digest.
    pub const fn record_digest(&self) -> RoleInputStateRecordDigest32V1<Role> {
        self.record_digest
    }

    /// Returns the role-scoped input-state epoch.
    pub const fn epoch(&self) -> RoleInputStateEpochV1<Role> {
        self.epoch
    }
}

/// Store-comparable registered-state authority committed by one provenance pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegisteredStateProvenanceBindingV1 {
    stable_scope: StableKdfScopeV1,
    registered_public_key: RegisteredEd25519PublicKey32V1,
    deriver_a: ProvenanceRoleStateBindingV1<DeriverAProvenanceRoleV1>,
    deriver_b: ProvenanceRoleStateBindingV1<DeriverBProvenanceRoleV1>,
}

/// Construction-independent registration fields accepted before evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegistrationProvenanceBindingV1 {
    stable_scope: StableKdfScopeV1,
    registration_intent_digest: RegistrationIntentDigest32V1,
    input_selection_evidence_digest: RegistrationAntiBiasArtifactDigest32V1,
    client_envelope_set_digest: ClientEnvelopeSetDigest32V1,
    deriver_a: ProvenanceRoleStateBindingV1<DeriverAProvenanceRoleV1>,
    deriver_b: ProvenanceRoleStateBindingV1<DeriverBProvenanceRoleV1>,
}

impl RegistrationProvenanceBindingV1 {
    /// Returns the frozen KDF scope shared by both role statements.
    pub const fn stable_scope(&self) -> StableKdfScopeV1 {
        self.stable_scope
    }

    /// Returns the registration intent shared by both role statements.
    pub const fn registration_intent_digest(&self) -> RegistrationIntentDigest32V1 {
        self.registration_intent_digest
    }

    /// Returns the profile-neutral input-selection evidence slot.
    pub const fn input_selection_evidence_digest(&self) -> RegistrationAntiBiasArtifactDigest32V1 {
        self.input_selection_evidence_digest
    }

    /// Returns the ordered A/B client-envelope-set commitment.
    pub const fn client_envelope_set_digest(&self) -> ClientEnvelopeSetDigest32V1 {
        self.client_envelope_set_digest
    }

    /// Returns Deriver A's initial role-state binding.
    pub const fn deriver_a(&self) -> ProvenanceRoleStateBindingV1<DeriverAProvenanceRoleV1> {
        self.deriver_a
    }

    /// Returns Deriver B's initial role-state binding.
    pub const fn deriver_b(&self) -> ProvenanceRoleStateBindingV1<DeriverBProvenanceRoleV1> {
        self.deriver_b
    }
}

impl RegisteredStateProvenanceBindingV1 {
    /// Returns the stable KDF scope committed by both role statements.
    pub const fn stable_scope(&self) -> StableKdfScopeV1 {
        self.stable_scope
    }

    /// Returns the registered key committed by both branch statements.
    pub const fn registered_public_key(&self) -> RegisteredEd25519PublicKey32V1 {
        self.registered_public_key
    }

    /// Returns Deriver A's state-record binding.
    pub const fn deriver_a(&self) -> ProvenanceRoleStateBindingV1<DeriverAProvenanceRoleV1> {
        self.deriver_a
    }

    /// Returns Deriver B's state-record binding.
    pub const fn deriver_b(&self) -> ProvenanceRoleStateBindingV1<DeriverBProvenanceRoleV1> {
        self.deriver_b
    }
}

/// Current and next registered-state bindings committed by refresh provenance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RefreshStateProvenanceBindingV1 {
    current: RegisteredStateProvenanceBindingV1,
    next_deriver_a: ProvenanceRoleStateBindingV1<DeriverAProvenanceRoleV1>,
    next_deriver_b: ProvenanceRoleStateBindingV1<DeriverBProvenanceRoleV1>,
}

impl RefreshStateProvenanceBindingV1 {
    /// Returns the current store-comparable state binding.
    pub const fn current(&self) -> RegisteredStateProvenanceBindingV1 {
        self.current
    }

    /// Returns Deriver A's proposed next state-record binding.
    pub const fn next_deriver_a(&self) -> ProvenanceRoleStateBindingV1<DeriverAProvenanceRoleV1> {
        self.next_deriver_a
    }

    /// Returns Deriver B's proposed next state-record binding.
    pub const fn next_deriver_b(&self) -> ProvenanceRoleStateBindingV1<DeriverBProvenanceRoleV1> {
        self.next_deriver_b
    }
}

/// Branch mismatch while extracting registered-state provenance authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegisteredStateProvenanceErrorV1 {
    /// The requested state relation does not match the provenance branch.
    RequestKindMismatch,
}

impl fmt::Display for RegisteredStateProvenanceErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RequestKindMismatch => {
                formatter.write_str("provenance branch has another registered-state relation")
            }
        }
    }
}

impl std::error::Error for RegisteredStateProvenanceErrorV1 {}

impl RoleInputProvenancePairV1 {
    /// Validates every construction-independent cross-role equality relation.
    pub fn new(
        deriver_a: RoleInputProvenanceStatementV1<DeriverAProvenanceRoleV1>,
        deriver_b: RoleInputProvenanceStatementV1<DeriverBProvenanceRoleV1>,
    ) -> Result<Self, ProvenancePairErrorV1> {
        validate_common_pair(&deriver_a, &deriver_b)?;
        validate_branch_pair(&deriver_a, &deriver_b)?;
        Ok(Self {
            deriver_a,
            deriver_b,
        })
    }

    /// Returns the Deriver A statement.
    pub const fn deriver_a(&self) -> &RoleInputProvenanceStatementV1<DeriverAProvenanceRoleV1> {
        &self.deriver_a
    }

    /// Returns the Deriver B statement.
    pub const fn deriver_b(&self) -> &RoleInputProvenanceStatementV1<DeriverBProvenanceRoleV1> {
        &self.deriver_b
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn ceremony_request_context_digest(&self) -> PublicRequestContextDigest32V1 {
        self.deriver_a
            .common()
            .ceremony
            .public_request_context_digest
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn ceremony_authorization_digest(&self) -> AuthorizationDigest32V1 {
        self.deriver_a.common().ceremony.authorization_digest
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn ceremony_transcript_digest(&self) -> CeremonyTranscriptDigest32V1 {
        self.deriver_a.common().ceremony.transcript_digest
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn registered_public_key(&self) -> Option<RegisteredEd25519PublicKey32V1> {
        match &self.deriver_a {
            RoleInputProvenanceStatementV1::Registration(_) => None,
            RoleInputProvenanceStatementV1::Recovery(statement) => {
                Some(statement.branch.registered_public_key)
            }
            RoleInputProvenanceStatementV1::Refresh(statement) => {
                Some(statement.branch.registered_public_key)
            }
            RoleInputProvenanceStatementV1::Export(statement) => {
                Some(statement.branch.registered_public_key)
            }
        }
    }

    /// Returns the exact common registration input-selection binding.
    pub(crate) fn registration_binding(
        &self,
    ) -> Result<RegistrationProvenanceBindingV1, RegisteredStateProvenanceErrorV1> {
        match (&self.deriver_a, &self.deriver_b) {
            (
                RoleInputProvenanceStatementV1::Registration(a),
                RoleInputProvenanceStatementV1::Registration(b),
            ) => Ok(RegistrationProvenanceBindingV1 {
                stable_scope: a.common.0.stable_scope,
                registration_intent_digest: a.branch.registration_intent_digest,
                input_selection_evidence_digest: a.branch.anti_bias_evidence_artifact_digest,
                client_envelope_set_digest: a.common.0.ceremony.client_envelope_set_digest,
                deriver_a: role_state_binding(&a.branch.initial_snapshot),
                deriver_b: role_state_binding(&b.branch.initial_snapshot),
            }),
            _ => Err(RegisteredStateProvenanceErrorV1::RequestKindMismatch),
        }
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn recovery_registered_state_binding(
        &self,
    ) -> Result<RegisteredStateProvenanceBindingV1, RegisteredStateProvenanceErrorV1> {
        match (&self.deriver_a, &self.deriver_b) {
            (
                RoleInputProvenanceStatementV1::Recovery(a),
                RoleInputProvenanceStatementV1::Recovery(b),
            ) => Ok(registered_state_binding(
                a.common.0.stable_scope,
                a.branch.registered_public_key,
                &a.branch.current_snapshot,
                &b.branch.current_snapshot,
            )),
            _ => Err(RegisteredStateProvenanceErrorV1::RequestKindMismatch),
        }
    }

    /// Returns the common same-root evidence artifact fixed by a recovery pair.
    pub(crate) fn recovery_same_root_evidence_artifact_digest(
        &self,
    ) -> Result<RecoveryContinuityArtifactDigest32V1, RegisteredStateProvenanceErrorV1> {
        match (&self.deriver_a, &self.deriver_b) {
            (
                RoleInputProvenanceStatementV1::Recovery(a),
                RoleInputProvenanceStatementV1::Recovery(_),
            ) => Ok(a.branch.same_root_evidence_artifact_digest),
            _ => Err(RegisteredStateProvenanceErrorV1::RequestKindMismatch),
        }
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn refresh_registered_state_binding(
        &self,
    ) -> Result<RefreshStateProvenanceBindingV1, RegisteredStateProvenanceErrorV1> {
        match (&self.deriver_a, &self.deriver_b) {
            (
                RoleInputProvenanceStatementV1::Refresh(a),
                RoleInputProvenanceStatementV1::Refresh(b),
            ) => Ok(RefreshStateProvenanceBindingV1 {
                current: registered_state_binding(
                    a.common.0.stable_scope,
                    a.branch.registered_public_key,
                    &a.branch.before_snapshot,
                    &b.branch.before_snapshot,
                ),
                next_deriver_a: role_state_binding(&a.branch.after_snapshot),
                next_deriver_b: role_state_binding(&b.branch.after_snapshot),
            }),
            _ => Err(RegisteredStateProvenanceErrorV1::RequestKindMismatch),
        }
    }

    /// Returns the common transition artifact fixed by a refresh pair.
    pub(crate) fn refresh_continuity_evidence_artifact_digest(
        &self,
    ) -> Result<RefreshContinuityArtifactDigest32V1, RegisteredStateProvenanceErrorV1> {
        match (&self.deriver_a, &self.deriver_b) {
            (
                RoleInputProvenanceStatementV1::Refresh(a),
                RoleInputProvenanceStatementV1::Refresh(_),
            ) => Ok(a.branch.continuity_evidence_artifact_digest),
            _ => Err(RegisteredStateProvenanceErrorV1::RequestKindMismatch),
        }
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn export_registered_state_binding(
        &self,
    ) -> Result<RegisteredStateProvenanceBindingV1, RegisteredStateProvenanceErrorV1> {
        match (&self.deriver_a, &self.deriver_b) {
            (
                RoleInputProvenanceStatementV1::Export(a),
                RoleInputProvenanceStatementV1::Export(b),
            ) => Ok(registered_state_binding(
                a.common.0.stable_scope,
                a.branch.registered_public_key,
                &a.branch.current_snapshot,
                &b.branch.current_snapshot,
            )),
            _ => Err(RegisteredStateProvenanceErrorV1::RequestKindMismatch),
        }
    }

    /// Encodes the fixed A-then-B statement-digest pair.
    pub fn encode(&self) -> Result<Vec<u8>, ProvenanceEncodingErrorV1> {
        let a_digest = self.deriver_a.digest()?;
        let b_digest = self.deriver_b.digest()?;
        let mut output = Vec::new();
        push_lp32(&mut output, PROVENANCE_PAIR_ENCODING_DOMAIN_V1)?;
        push_lp32(&mut output, a_digest.as_bytes())?;
        push_lp32(&mut output, b_digest.as_bytes())?;
        Ok(output)
    }

    /// Computes the canonical ordered pair digest.
    pub fn digest(&self) -> Result<RoleInputProvenancePairDigest32V1, ProvenanceEncodingErrorV1> {
        let encoding = self.encode()?;
        let mut digest_input = Vec::new();
        push_lp32(&mut digest_input, PROVENANCE_PAIR_DIGEST_DOMAIN_V1)?;
        push_lp32(&mut digest_input, &encoding)?;
        Ok(RoleInputProvenancePairDigest32V1(Digest32::from_bytes(
            Sha256::digest(&digest_input).into(),
        )))
    }
}

#[cfg_attr(not(test), allow(dead_code))]
fn role_state_binding<Role: ProvenanceRoleV1>(
    snapshot: &RoleInputSnapshotV1<Role>,
) -> ProvenanceRoleStateBindingV1<Role> {
    ProvenanceRoleStateBindingV1 {
        role_root_record_digest: snapshot.role_root_record_digest,
        root_binding_artifact_digest: snapshot.root_binding_artifact_digest,
        role_root_epoch: snapshot.role_root_epoch,
        record_digest: snapshot.role_input_state_record_digest,
        epoch: snapshot.role_input_state_epoch,
    }
}

#[cfg_attr(not(test), allow(dead_code))]
fn registered_state_binding(
    stable_scope: StableKdfScopeV1,
    registered_public_key: RegisteredEd25519PublicKey32V1,
    deriver_a: &RoleInputSnapshotV1<DeriverAProvenanceRoleV1>,
    deriver_b: &RoleInputSnapshotV1<DeriverBProvenanceRoleV1>,
) -> RegisteredStateProvenanceBindingV1 {
    RegisteredStateProvenanceBindingV1 {
        stable_scope,
        registered_public_key,
        deriver_a: role_state_binding(deriver_a),
        deriver_b: role_state_binding(deriver_b),
    }
}

/// Internally computed ordered A/B pair digest.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct RoleInputProvenancePairDigest32V1(Digest32);

impl RoleInputProvenancePairDigest32V1 {
    /// Returns the computed pair digest bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}

impl fmt::Debug for RoleInputProvenancePairDigest32V1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RoleInputProvenancePairDigest32V1([computed SHA-256])")
    }
}

fn validate_common_pair(
    deriver_a: &RoleInputProvenanceStatementV1<DeriverAProvenanceRoleV1>,
    deriver_b: &RoleInputProvenanceStatementV1<DeriverBProvenanceRoleV1>,
) -> Result<(), ProvenancePairErrorV1> {
    if deriver_a.request_kind() != deriver_b.request_kind() {
        return pair_mismatch(ProvenancePairFieldV1::RequestKind);
    }
    let a = deriver_a.common();
    let b = deriver_b.common();
    if a.stable_scope != b.stable_scope {
        return pair_mismatch(ProvenancePairFieldV1::StableScope);
    }
    if a.circuit_digest != b.circuit_digest {
        return pair_mismatch(ProvenancePairFieldV1::CircuitDigest);
    }
    if a.input_schema_digest != b.input_schema_digest {
        return pair_mismatch(ProvenancePairFieldV1::InputSchemaDigest);
    }
    if a.ceremony.public_request_context_digest != b.ceremony.public_request_context_digest {
        return pair_mismatch(ProvenancePairFieldV1::PublicRequestContextDigest);
    }
    if a.ceremony.transcript_digest != b.ceremony.transcript_digest {
        return pair_mismatch(ProvenancePairFieldV1::TranscriptDigest);
    }
    if a.ceremony.authorization_digest != b.ceremony.authorization_digest {
        return pair_mismatch(ProvenancePairFieldV1::AuthorizationDigest);
    }
    if a.ceremony.client_envelope_set_digest != b.ceremony.client_envelope_set_digest {
        return pair_mismatch(ProvenancePairFieldV1::ClientEnvelopeSetDigest);
    }
    let expected_set = ClientEnvelopeSetDigest32V1::compute(
        &a.ceremony.client_envelope_artifact_digest,
        &b.ceremony.client_envelope_artifact_digest,
    )
    .expect("fixed-size envelope digests always fit LP32");
    if expected_set != a.ceremony.client_envelope_set_digest {
        return pair_mismatch(ProvenancePairFieldV1::ClientEnvelopeOrdering);
    }
    Ok(())
}

fn validate_branch_pair(
    deriver_a: &RoleInputProvenanceStatementV1<DeriverAProvenanceRoleV1>,
    deriver_b: &RoleInputProvenanceStatementV1<DeriverBProvenanceRoleV1>,
) -> Result<(), ProvenancePairErrorV1> {
    match (deriver_a, deriver_b) {
        (
            RoleInputProvenanceStatementV1::Registration(a),
            RoleInputProvenanceStatementV1::Registration(b),
        ) => {
            if a.branch.registration_intent_digest != b.branch.registration_intent_digest {
                return pair_mismatch(ProvenancePairFieldV1::RegistrationIntentDigest);
            }
            if a.branch.anti_bias_evidence_artifact_digest
                != b.branch.anti_bias_evidence_artifact_digest
            {
                return pair_mismatch(ProvenancePairFieldV1::RegistrationAntiBiasDigest);
            }
        }
        (
            RoleInputProvenanceStatementV1::Recovery(a),
            RoleInputProvenanceStatementV1::Recovery(b),
        ) => {
            if a.branch.registered_public_key != b.branch.registered_public_key {
                return pair_mismatch(ProvenancePairFieldV1::RegisteredPublicKey);
            }
            if a.branch.same_root_evidence_artifact_digest
                != b.branch.same_root_evidence_artifact_digest
            {
                return pair_mismatch(ProvenancePairFieldV1::ContinuityEvidenceDigest);
            }
        }
        (
            RoleInputProvenanceStatementV1::Refresh(a),
            RoleInputProvenanceStatementV1::Refresh(b),
        ) => {
            if a.branch.registered_public_key != b.branch.registered_public_key {
                return pair_mismatch(ProvenancePairFieldV1::RegisteredPublicKey);
            }
            if a.branch.continuity_evidence_artifact_digest
                != b.branch.continuity_evidence_artifact_digest
            {
                return pair_mismatch(ProvenancePairFieldV1::ContinuityEvidenceDigest);
            }
        }
        (RoleInputProvenanceStatementV1::Export(a), RoleInputProvenanceStatementV1::Export(b)) => {
            if a.branch.registered_public_key != b.branch.registered_public_key {
                return pair_mismatch(ProvenancePairFieldV1::RegisteredPublicKey);
            }
        }
        _ => return pair_mismatch(ProvenancePairFieldV1::RequestKind),
    }
    Ok(())
}

fn pair_mismatch<T>(field: ProvenancePairFieldV1) -> Result<T, ProvenancePairErrorV1> {
    Err(ProvenancePairErrorV1 { field })
}

/// Strict structural decoding failure for canonical provenance bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProvenanceDecodingErrorV1 {
    /// An LP32 length or value was truncated.
    Truncated {
        /// Field being decoded.
        field: &'static str,
    },
    /// A fixed-width field had the wrong byte length.
    InvalidLength {
        /// Field being decoded.
        field: &'static str,
        /// Required byte length.
        expected: usize,
        /// Supplied byte length.
        actual: usize,
    },
    /// A domain, identifier, or tag was unsupported.
    UnexpectedValue {
        /// Field being decoded.
        field: &'static str,
    },
    /// A nonzero digest role from the circuit manifest was zero.
    ZeroManifestDigest {
        /// Digest field being decoded.
        field: &'static str,
    },
    /// Participant identifiers were zero, duplicated, or not ascending.
    InvalidParticipantOrder,
    /// The stable-context binding did not match its encoded inputs.
    StableContextBindingMismatch,
    /// An encoded epoch was zero.
    ZeroEpoch {
        /// Epoch field being decoded.
        field: &'static str,
    },
    /// A registered Ed25519 point failed public validation.
    InvalidRegisteredPublicKey(RegisteredEd25519PublicKeyErrorV1),
    /// A refresh snapshot violated root or epoch continuity.
    InvalidRefresh(RefreshProvenanceErrorV1),
    /// One nested encoding contained trailing bytes.
    TrailingBytes {
        /// Nested encoding being decoded.
        scope: &'static str,
    },
}

impl fmt::Display for ProvenanceDecodingErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated { field } => write!(formatter, "truncated provenance field {field}"),
            Self::InvalidLength {
                field,
                expected,
                actual,
            } => write!(
                formatter,
                "provenance field {field} requires {expected} bytes, received {actual}"
            ),
            Self::UnexpectedValue { field } => {
                write!(formatter, "unsupported provenance value at {field}")
            }
            Self::ZeroManifestDigest { field } => {
                write!(formatter, "provenance manifest digest {field} is zero")
            }
            Self::InvalidParticipantOrder => {
                formatter.write_str("provenance participant identifiers are not canonical")
            }
            Self::StableContextBindingMismatch => {
                formatter.write_str("provenance stable-context binding does not match")
            }
            Self::ZeroEpoch { field } => write!(formatter, "provenance epoch {field} is zero"),
            Self::InvalidRegisteredPublicKey(error) => error.fmt(formatter),
            Self::InvalidRefresh(error) => error.fmt(formatter),
            Self::TrailingBytes { scope } => {
                write!(formatter, "provenance {scope} contains trailing bytes")
            }
        }
    }
}

impl std::error::Error for ProvenanceDecodingErrorV1 {}

/// Structurally parsed canonical statement bytes with no proof-verification claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedCanonicalProvenanceStatementV1 {
    request_kind: ProvenanceRequestKindV1,
    role: ProvenanceRoleKindV1,
    circuit_family: ProvenanceCircuitFamilyV1,
    encoding: Vec<u8>,
    digest: [u8; 32],
}

impl ParsedCanonicalProvenanceStatementV1 {
    /// Returns the decoded request branch.
    pub const fn request_kind(&self) -> ProvenanceRequestKindV1 {
        self.request_kind
    }

    /// Returns the decoded role.
    pub const fn role(&self) -> ProvenanceRoleKindV1 {
        self.role
    }

    /// Returns the decoded circuit family.
    pub const fn circuit_family(&self) -> ProvenanceCircuitFamilyV1 {
        self.circuit_family
    }

    /// Returns the exact canonical input bytes.
    pub fn encoding(&self) -> &[u8] {
        &self.encoding
    }

    /// Returns the digest recomputed over the canonical bytes.
    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
}

/// Structurally parsed canonical A/B pair bytes with no statement lookup claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedCanonicalProvenancePairV1 {
    deriver_a_statement_digest: [u8; 32],
    deriver_b_statement_digest: [u8; 32],
    encoding: Vec<u8>,
    digest: [u8; 32],
}

impl ParsedCanonicalProvenancePairV1 {
    /// Returns the first encoded statement digest slot.
    pub const fn deriver_a_statement_digest(&self) -> &[u8; 32] {
        &self.deriver_a_statement_digest
    }

    /// Returns the second encoded statement digest slot.
    pub const fn deriver_b_statement_digest(&self) -> &[u8; 32] {
        &self.deriver_b_statement_digest
    }

    /// Returns the exact canonical input bytes.
    pub fn encoding(&self) -> &[u8] {
        &self.encoding
    }

    /// Returns the digest recomputed over the canonical pair bytes.
    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ParsedSnapshotV1 {
    role_root_record_digest: [u8; 32],
    role_root_epoch: u64,
    role_input_state_epoch: u64,
}

/// Strictly parses and structurally validates one canonical statement encoding.
///
/// Artifact and record digests remain unverified opaque slots. Production code
/// must authenticate their preimages and proof relations before acceptance.
pub fn parse_canonical_provenance_statement_v1(
    encoding: &[u8],
) -> Result<ParsedCanonicalProvenanceStatementV1, ProvenanceDecodingErrorV1> {
    let mut cursor = Lp32Cursor::new(encoding, "statement");
    require_exact(
        cursor.read("statement.domain")?,
        PROVENANCE_STATEMENT_ENCODING_DOMAIN_V1,
        "statement.domain",
    )?;
    require_exact(
        cursor.read("statement.protocol_id")?,
        ed25519_yao::PROTOCOL_ID_STR.as_bytes(),
        "statement.protocol_id",
    )?;
    let request_kind = parse_request_kind(cursor.read_fixed("statement.request_kind")?)?;
    let role = parse_role(cursor.read_fixed("statement.role")?)?;
    let circuit_family = parse_family(cursor.read_fixed("statement.circuit_family")?)?;
    let circuit_id = cursor.read("statement.circuit_id")?;
    validate_request_family_mapping(request_kind, circuit_family, circuit_id)?;
    let circuit_digest = cursor.read_fixed::<32>("statement.circuit_digest")?;
    if circuit_digest.iter().all(|byte| *byte == 0) {
        return Err(ProvenanceDecodingErrorV1::ZeroManifestDigest {
            field: "statement.circuit_digest",
        });
    }
    let input_schema_digest = cursor.read_fixed::<32>("statement.input_schema_digest")?;
    if input_schema_digest.iter().all(|byte| *byte == 0) {
        return Err(ProvenanceDecodingErrorV1::ZeroManifestDigest {
            field: "statement.input_schema_digest",
        });
    }
    parse_stable_scope(cursor.read("statement.stable_scope")?)?;
    let ceremony_request_kind = parse_ceremony_binding(cursor.read("statement.ceremony")?)?;
    if ceremony_request_kind != request_kind {
        return Err(ProvenanceDecodingErrorV1::UnexpectedValue {
            field: "ceremony.request_kind",
        });
    }
    parse_branch(request_kind, cursor.read("statement.branch")?)?;
    cursor.finish()?;

    let mut digest_input = Vec::new();
    push_lp32_decode_infallible(&mut digest_input, PROVENANCE_STATEMENT_DIGEST_DOMAIN_V1);
    push_lp32_decode_infallible(&mut digest_input, encoding);
    Ok(ParsedCanonicalProvenanceStatementV1 {
        request_kind,
        role,
        circuit_family,
        encoding: encoding.to_vec(),
        digest: Sha256::digest(&digest_input).into(),
    })
}

/// Strictly parses one canonical pair encoding and recomputes its digest.
///
/// Role ordering and shared-field relations require the referenced statements;
/// use `RoleInputProvenancePairV1::new` when those typed values are available.
pub fn parse_canonical_provenance_pair_v1(
    encoding: &[u8],
) -> Result<ParsedCanonicalProvenancePairV1, ProvenanceDecodingErrorV1> {
    let mut cursor = Lp32Cursor::new(encoding, "pair");
    require_exact(
        cursor.read("pair.domain")?,
        PROVENANCE_PAIR_ENCODING_DOMAIN_V1,
        "pair.domain",
    )?;
    let deriver_a_statement_digest = cursor.read_fixed("pair.deriver_a_statement_digest")?;
    let deriver_b_statement_digest = cursor.read_fixed("pair.deriver_b_statement_digest")?;
    cursor.finish()?;
    let mut digest_input = Vec::new();
    push_lp32_decode_infallible(&mut digest_input, PROVENANCE_PAIR_DIGEST_DOMAIN_V1);
    push_lp32_decode_infallible(&mut digest_input, encoding);
    Ok(ParsedCanonicalProvenancePairV1 {
        deriver_a_statement_digest,
        deriver_b_statement_digest,
        encoding: encoding.to_vec(),
        digest: Sha256::digest(&digest_input).into(),
    })
}

fn parse_request_kind(tag: [u8; 1]) -> Result<ProvenanceRequestKindV1, ProvenanceDecodingErrorV1> {
    match tag[0] {
        PROVENANCE_REGISTRATION_REQUEST_TAG_V1 => Ok(ProvenanceRequestKindV1::Registration),
        PROVENANCE_RECOVERY_REQUEST_TAG_V1 => Ok(ProvenanceRequestKindV1::Recovery),
        PROVENANCE_REFRESH_REQUEST_TAG_V1 => Ok(ProvenanceRequestKindV1::Refresh),
        PROVENANCE_EXPORT_REQUEST_TAG_V1 => Ok(ProvenanceRequestKindV1::Export),
        PROVENANCE_ACTIVATION_REQUEST_TAG_V1 => Err(ProvenanceDecodingErrorV1::UnexpectedValue {
            field: "statement.request_kind",
        }),
        _ => Err(ProvenanceDecodingErrorV1::UnexpectedValue {
            field: "statement.request_kind",
        }),
    }
}

fn parse_role(tag: [u8; 1]) -> Result<ProvenanceRoleKindV1, ProvenanceDecodingErrorV1> {
    match tag[0] {
        PROVENANCE_DERIVER_A_ROLE_TAG_V1 => Ok(ProvenanceRoleKindV1::DeriverA),
        PROVENANCE_DERIVER_B_ROLE_TAG_V1 => Ok(ProvenanceRoleKindV1::DeriverB),
        _ => Err(ProvenanceDecodingErrorV1::UnexpectedValue {
            field: "statement.role",
        }),
    }
}

fn parse_family(tag: [u8; 1]) -> Result<ProvenanceCircuitFamilyV1, ProvenanceDecodingErrorV1> {
    match tag[0] {
        PROVENANCE_ACTIVATION_FAMILY_TAG_V1 => Ok(ProvenanceCircuitFamilyV1::Activation),
        PROVENANCE_EXPORT_FAMILY_TAG_V1 => Ok(ProvenanceCircuitFamilyV1::Export),
        _ => Err(ProvenanceDecodingErrorV1::UnexpectedValue {
            field: "statement.circuit_family",
        }),
    }
}

fn validate_request_family_mapping(
    request_kind: ProvenanceRequestKindV1,
    circuit_family: ProvenanceCircuitFamilyV1,
    circuit_id: &[u8],
) -> Result<(), ProvenanceDecodingErrorV1> {
    let expected_family = match request_kind {
        ProvenanceRequestKindV1::Registration
        | ProvenanceRequestKindV1::Recovery
        | ProvenanceRequestKindV1::Refresh => ProvenanceCircuitFamilyV1::Activation,
        ProvenanceRequestKindV1::Export => ProvenanceCircuitFamilyV1::Export,
    };
    if circuit_family != expected_family {
        return Err(ProvenanceDecodingErrorV1::UnexpectedValue {
            field: "statement.circuit_family",
        });
    }
    require_exact(
        circuit_id,
        expected_family.circuit_id().as_bytes(),
        "statement.circuit_id",
    )
}

fn parse_stable_scope(encoding: &[u8]) -> Result<(), ProvenanceDecodingErrorV1> {
    let mut cursor = Lp32Cursor::new(encoding, "stable_scope");
    require_exact(
        cursor.read("stable_scope.domain")?,
        PROVENANCE_STABLE_SCOPE_ENCODING_DOMAIN_V1,
        "stable_scope.domain",
    )?;
    let application_binding_digest =
        cursor.read_fixed::<32>("stable_scope.application_binding_digest")?;
    let participant_low =
        u16::from_be_bytes(cursor.read_fixed::<2>("stable_scope.participant_low")?);
    let participant_high =
        u16::from_be_bytes(cursor.read_fixed::<2>("stable_scope.participant_high")?);
    if participant_low == 0 || participant_low >= participant_high {
        return Err(ProvenanceDecodingErrorV1::InvalidParticipantOrder);
    }
    let stable_context_binding =
        cursor.read_fixed::<32>("stable_scope.stable_context_binding_digest")?;
    cursor.finish()?;
    let context = StableKeyDerivationContext::new(
        application_binding_digest,
        participant_low,
        participant_high,
    )
    .map_err(|_| ProvenanceDecodingErrorV1::InvalidParticipantOrder)?;
    if context.binding_digest().as_bytes() != &stable_context_binding {
        return Err(ProvenanceDecodingErrorV1::StableContextBindingMismatch);
    }
    Ok(())
}

fn parse_ceremony_binding(
    encoding: &[u8],
) -> Result<ProvenanceRequestKindV1, ProvenanceDecodingErrorV1> {
    let mut cursor = Lp32Cursor::new(encoding, "ceremony");
    require_exact(
        cursor.read("ceremony.domain")?,
        PROVENANCE_CEREMONY_BINDING_ENCODING_DOMAIN_V1,
        "ceremony.domain",
    )?;
    let request_kind = parse_request_kind(cursor.read_fixed("ceremony.request_kind")?)?;
    cursor.read_fixed::<32>("ceremony.public_request_context_digest")?;
    cursor.read_fixed::<32>("ceremony.transcript_digest")?;
    cursor.read_fixed::<32>("ceremony.authorization_digest")?;
    cursor.read_fixed::<32>("ceremony.client_envelope_artifact_digest")?;
    cursor.read_fixed::<32>("ceremony.client_envelope_set_digest")?;
    cursor.finish()?;
    Ok(request_kind)
}

fn parse_branch(
    request_kind: ProvenanceRequestKindV1,
    encoding: &[u8],
) -> Result<(), ProvenanceDecodingErrorV1> {
    let mut cursor = Lp32Cursor::new(encoding, "branch");
    match request_kind {
        ProvenanceRequestKindV1::Registration => {
            require_exact(
                cursor.read("registration.domain")?,
                PROVENANCE_REGISTRATION_BRANCH_ENCODING_DOMAIN_V1,
                "registration.domain",
            )?;
            parse_snapshot(cursor.read("registration.initial_snapshot")?)?;
            cursor.read_fixed::<32>("registration.intent_digest")?;
            cursor.read_fixed::<32>("registration.anti_bias_artifact_digest")?;
        }
        ProvenanceRequestKindV1::Recovery => {
            require_exact(
                cursor.read("recovery.domain")?,
                PROVENANCE_RECOVERY_BRANCH_ENCODING_DOMAIN_V1,
                "recovery.domain",
            )?;
            parse_snapshot(cursor.read("recovery.current_snapshot")?)?;
            parse_registered_public_key(cursor.read_fixed("recovery.registered_public_key")?)?;
            cursor.read_fixed::<32>("recovery.continuity_artifact_digest")?;
        }
        ProvenanceRequestKindV1::Refresh => {
            require_exact(
                cursor.read("refresh.domain")?,
                PROVENANCE_REFRESH_BRANCH_ENCODING_DOMAIN_V1,
                "refresh.domain",
            )?;
            let before = parse_snapshot(cursor.read("refresh.before_snapshot")?)?;
            let after = parse_snapshot(cursor.read("refresh.after_snapshot")?)?;
            validate_parsed_refresh(before, after)?;
            parse_registered_public_key(cursor.read_fixed("refresh.registered_public_key")?)?;
            cursor.read_fixed::<32>("refresh.continuity_artifact_digest")?;
        }
        ProvenanceRequestKindV1::Export => {
            require_exact(
                cursor.read("export.domain")?,
                PROVENANCE_EXPORT_BRANCH_ENCODING_DOMAIN_V1,
                "export.domain",
            )?;
            parse_snapshot(cursor.read("export.current_snapshot")?)?;
            parse_registered_public_key(cursor.read_fixed("export.registered_public_key")?)?;
        }
    }
    cursor.finish()
}

fn parse_snapshot(encoding: &[u8]) -> Result<ParsedSnapshotV1, ProvenanceDecodingErrorV1> {
    let mut cursor = Lp32Cursor::new(encoding, "snapshot");
    require_exact(
        cursor.read("snapshot.domain")?,
        PROVENANCE_ROLE_INPUT_SNAPSHOT_ENCODING_DOMAIN_V1,
        "snapshot.domain",
    )?;
    let role_root_record_digest = cursor.read_fixed("snapshot.role_root_record_digest")?;
    cursor.read_fixed::<32>("snapshot.root_binding_artifact_digest")?;
    let role_root_epoch = parse_nonzero_epoch(
        cursor.read_fixed("snapshot.role_root_epoch")?,
        "snapshot.role_root_epoch",
    )?;
    cursor.read_fixed::<32>("snapshot.role_input_state_record_digest")?;
    let role_input_state_epoch = parse_nonzero_epoch(
        cursor.read_fixed("snapshot.role_input_state_epoch")?,
        "snapshot.role_input_state_epoch",
    )?;
    cursor.read_fixed::<32>("snapshot.client_input_artifact_digest")?;
    cursor.read_fixed::<32>("snapshot.server_input_artifact_digest")?;
    cursor.read_fixed::<32>("snapshot.combined_input_artifact_digest")?;
    cursor.finish()?;
    Ok(ParsedSnapshotV1 {
        role_root_record_digest,
        role_root_epoch,
        role_input_state_epoch,
    })
}

fn validate_parsed_refresh(
    before: ParsedSnapshotV1,
    after: ParsedSnapshotV1,
) -> Result<(), ProvenanceDecodingErrorV1> {
    if before.role_root_record_digest != after.role_root_record_digest {
        return Err(ProvenanceDecodingErrorV1::InvalidRefresh(
            RefreshProvenanceErrorV1::RoleRootRecordChanged,
        ));
    }
    if before.role_root_epoch != after.role_root_epoch {
        return Err(ProvenanceDecodingErrorV1::InvalidRefresh(
            RefreshProvenanceErrorV1::RoleRootEpochChanged,
        ));
    }
    if after.role_input_state_epoch <= before.role_input_state_epoch {
        return Err(ProvenanceDecodingErrorV1::InvalidRefresh(
            RefreshProvenanceErrorV1::InputStateEpoch(
                ProvenanceEpochErrorV1::DidNotStrictlyAdvance,
            ),
        ));
    }
    Ok(())
}

fn parse_registered_public_key(bytes: [u8; 32]) -> Result<(), ProvenanceDecodingErrorV1> {
    RegisteredEd25519PublicKey32V1::parse(bytes)
        .map(|_| ())
        .map_err(ProvenanceDecodingErrorV1::InvalidRegisteredPublicKey)
}

fn parse_nonzero_epoch(
    bytes: [u8; 8],
    field: &'static str,
) -> Result<u64, ProvenanceDecodingErrorV1> {
    let value = u64::from_be_bytes(bytes);
    if value == 0 {
        return Err(ProvenanceDecodingErrorV1::ZeroEpoch { field });
    }
    Ok(value)
}

fn require_exact(
    actual: &[u8],
    expected: &[u8],
    field: &'static str,
) -> Result<(), ProvenanceDecodingErrorV1> {
    if actual != expected {
        return Err(ProvenanceDecodingErrorV1::UnexpectedValue { field });
    }
    Ok(())
}

struct Lp32Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
    scope: &'static str,
}

impl<'a> Lp32Cursor<'a> {
    const fn new(bytes: &'a [u8], scope: &'static str) -> Self {
        Self {
            bytes,
            offset: 0,
            scope,
        }
    }

    fn read(&mut self, field: &'static str) -> Result<&'a [u8], ProvenanceDecodingErrorV1> {
        let length_end = self
            .offset
            .checked_add(4)
            .filter(|end| *end <= self.bytes.len())
            .ok_or(ProvenanceDecodingErrorV1::Truncated { field })?;
        let length_bytes: [u8; 4] = self.bytes[self.offset..length_end]
            .try_into()
            .expect("validated four-byte LP32 length");
        let length = u32::from_be_bytes(length_bytes) as usize;
        let value_end = length_end
            .checked_add(length)
            .filter(|end| *end <= self.bytes.len())
            .ok_or(ProvenanceDecodingErrorV1::Truncated { field })?;
        self.offset = value_end;
        Ok(&self.bytes[length_end..value_end])
    }

    fn read_fixed<const N: usize>(
        &mut self,
        field: &'static str,
    ) -> Result<[u8; N], ProvenanceDecodingErrorV1> {
        let value = self.read(field)?;
        if value.len() != N {
            return Err(ProvenanceDecodingErrorV1::InvalidLength {
                field,
                expected: N,
                actual: value.len(),
            });
        }
        Ok(value.try_into().expect("validated fixed-width field"))
    }

    fn finish(self) -> Result<(), ProvenanceDecodingErrorV1> {
        if self.offset != self.bytes.len() {
            return Err(ProvenanceDecodingErrorV1::TrailingBytes { scope: self.scope });
        }
        Ok(())
    }
}

fn push_lp32_decode_infallible(output: &mut Vec<u8>, value: &[u8]) {
    let length = u32::try_from(value.len()).expect("decoded provenance value fit LP32");
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
}

fn push_lp32(output: &mut Vec<u8>, value: &[u8]) -> Result<(), ProvenanceEncodingErrorV1> {
    let length = u32::try_from(value.len()).map_err(|_| ProvenanceEncodingErrorV1::ValueTooLong)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}
