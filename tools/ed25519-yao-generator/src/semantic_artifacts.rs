//! Profile-neutral semantic package and receipt encodings.
//!
//! These host-only types freeze public descriptor relations over synthetic
//! reference shares. The construction-independent A/B provenance pair is tied
//! to the exact ceremony DAG before its digest is derived. A move-only typed
//! ceremony context runs its branch-specific host reference and output sharing
//! internally, then immediately constructs packages; no package API accepts a
//! separately precomputed success. Remaining opaque digest slots name where the
//! Phase 6A-selected recipient protection, output binding, package
//! authentication, and protocol evidence will be committed.
//! Supplying one of those opaque digests does not authenticate or prove the
//! referenced artifact. The computed provenance-pair digest likewise does not
//! authenticate the pair's opaque record or proof-artifact slots, and the
//! call-local binding does not authenticate synthetic inputs against those
//! slots. This module contains no cipher format, HPKE, AEAD, signature, proof,
//! MAC, OT, garbled-circuit, or timing-equivalence implementation.
//!
//! Zero additive scalar shares remain valid. Their identity commitments are
//! encoded without retry. The final joined client and SigningWorker points must
//! each be nonidentity, and their registered-key relation must hold.

use core::{fmt, marker::PhantomData, num::NonZeroU64};

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::IsIdentity;
use sha2::{Digest, Sha256};

use crate::ceremony_context::{
    CeremonyActivationEpochV1, CeremonyArtifactSuiteDigest32V1, CeremonyAuthorizationDigest32V1,
    CeremonyAuthorizationV1, CeremonyContextErrorV1, CeremonyExportAuthorizationV1,
    CeremonyPackageSetDigest32V1, CeremonyPublicRequestContextDigest32V1,
    CeremonyPublicRequestContextV1, CeremonyRecoveryAuthorizationV1,
    CeremonyRefreshAuthorizationV1, CeremonyRegistrationAuthorizationV1, CeremonyRequestKindV1,
    CeremonyTranscriptDigest32V1, CeremonyTranscriptV1, CeremonyTransportBindingDigest32V1,
    CeremonyValidatedDagV1,
};
use crate::lifecycle_domain::ActivationPackageOriginV1;
use crate::output_sharing::{
    HostOnlyActivationOutputSharesV1, HostOnlyDeriverAClientScalarShareV1,
    HostOnlyDeriverASeedExportShareV1, HostOnlyDeriverASigningWorkerScalarShareV1,
    HostOnlyDeriverBClientScalarShareV1, HostOnlyDeriverBSeedExportShareV1,
    HostOnlyDeriverBSigningWorkerScalarShareV1, HostOnlySeedExportSharesV1,
};
use crate::provenance::{
    DeriverAProvenanceRoleV1, DeriverBProvenanceRoleV1, ProvenanceEncodingErrorV1,
    ProvenanceRequestKindV1, ProvenanceRoleV1, RoleInputProvenancePairV1,
};
use crate::{
    evaluate_host_only_export_output_sharing_v1, evaluate_host_only_recovery_output_sharing_v1,
    evaluate_host_only_refresh_output_sharing_v1,
    evaluate_host_only_registration_output_sharing_v1, prepare_host_only_export_reference_v1,
    prepare_host_only_recovery_reference_v1, prepare_host_only_refresh_reference_v1,
    prepare_host_only_registration_reference_v1, HostOnlyExportIdealCoinV1,
    HostOnlyExportReferenceErrorV1, HostOnlyExportReferenceInputsV1, HostOnlyRecoveryIdealCoinsV1,
    HostOnlyRecoveryReferenceErrorV1, HostOnlyRecoveryReferenceInputsV1,
    HostOnlyRefreshIdealCoinsV1, HostOnlyRefreshReferenceErrorV1, HostOnlyRefreshReferenceInputsV1,
    HostOnlyRegistrationIdealCoinsV1, HostOnlyRegistrationReferenceInputsV1,
    RegisteredEd25519PublicKey32V1, RegisteredEd25519PublicKeyErrorV1,
};

/// Deriver A client-scalar activation descriptor domain.
pub const ACTIVATION_DERIVER_A_CLIENT_DESCRIPTOR_DOMAIN_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/semantic-package/activation/deriver-a/client-scalar/v1";
/// Deriver B client-scalar activation descriptor domain.
pub const ACTIVATION_DERIVER_B_CLIENT_DESCRIPTOR_DOMAIN_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/semantic-package/activation/deriver-b/client-scalar/v1";
/// Deriver A SigningWorker-scalar activation descriptor domain.
pub const ACTIVATION_DERIVER_A_SIGNING_WORKER_DESCRIPTOR_DOMAIN_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/semantic-package/activation/deriver-a/signing-worker-scalar/v1";
/// Deriver B SigningWorker-scalar activation descriptor domain.
pub const ACTIVATION_DERIVER_B_SIGNING_WORKER_DESCRIPTOR_DOMAIN_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/semantic-package/activation/deriver-b/signing-worker-scalar/v1";
/// Deriver A client seed-export descriptor domain.
pub const EXPORT_DERIVER_A_CLIENT_DESCRIPTOR_DOMAIN_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/semantic-package/export/deriver-a/client-seed/v1";
/// Deriver B client seed-export descriptor domain.
pub const EXPORT_DERIVER_B_CLIENT_DESCRIPTOR_DOMAIN_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/semantic-package/export/deriver-b/client-seed/v1";
/// Typed client recipient/key-binding derivation domain.
pub const CLIENT_RECIPIENT_KEY_BINDING_DOMAIN_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/semantic-recipient-key-binding/client/v1";
/// Typed SigningWorker recipient/key-binding derivation domain.
pub const SIGNING_WORKER_RECIPIENT_KEY_BINDING_DOMAIN_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/semantic-recipient-key-binding/signing-worker/v1";
/// Fixed four-member activation package-set encoding domain.
pub const ACTIVATION_PACKAGE_SET_ENCODING_DOMAIN_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/semantic-package-set/activation/v1";
/// Activation package-set digest domain.
pub const ACTIVATION_PACKAGE_SET_DIGEST_DOMAIN_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/semantic-package-set/activation-digest/v1";
/// Fixed two-member export package-set encoding domain.
pub const EXPORT_PACKAGE_SET_ENCODING_DOMAIN_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/semantic-package-set/export/v1";
/// Export package-set digest domain.
pub const EXPORT_PACKAGE_SET_DIGEST_DOMAIN_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/semantic-package-set/export-digest/v1";
/// Activation output-committed receipt-body encoding domain.
pub const ACTIVATION_OUTPUT_COMMITTED_RECEIPT_ENCODING_DOMAIN_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/semantic-receipt/activation-output-committed/v1";
/// Activation output-committed receipt-body digest domain.
pub const ACTIVATION_OUTPUT_COMMITTED_RECEIPT_DIGEST_DOMAIN_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/semantic-receipt/activation-output-committed-digest/v1";
/// Export output-committed receipt-body encoding domain.
pub const EXPORT_OUTPUT_COMMITTED_RECEIPT_ENCODING_DOMAIN_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/semantic-receipt/export-output-committed/v1";
/// Export output-committed receipt-body digest domain.
pub const EXPORT_OUTPUT_COMMITTED_RECEIPT_DIGEST_DOMAIN_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/semantic-receipt/export-output-committed-digest/v1";
/// Export released receipt-body encoding domain.
pub const EXPORT_RELEASED_RECEIPT_ENCODING_DOMAIN_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/semantic-receipt/export-released/v1";
/// Export released receipt-body digest domain.
pub const EXPORT_RELEASED_RECEIPT_DIGEST_DOMAIN_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/semantic-receipt/export-released-digest/v1";

const CLIENT_RECIPIENT_TAG_V1: u8 = 0x01;
pub(crate) const SIGNING_WORKER_RECIPIENT_TAG_V1: u8 = 0x02;
const CLIENT_SCALAR_OUTPUT_TAG_V1: u8 = 0x01;
pub(crate) const SIGNING_WORKER_SCALAR_OUTPUT_TAG_V1: u8 = 0x02;
const CLIENT_SEED_OUTPUT_TAG_V1: u8 = 0x03;
const OUTPUT_COMMITTED_RECEIPT_TAG_V1: u8 = 0x01;
const EXPORT_RELEASED_RECEIPT_TAG_V1: u8 = 0x02;
const OUTPUT_COMMITTED_TERMINAL_STATUS_TAG_V1: u8 = 0x01;
const EXPORT_RELEASED_TERMINAL_STATUS_TAG_V1: u8 = 0x02;

/// Opaque host-reference slot rejected because it was all zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SemanticArtifactOpaqueDigestFieldV1 {
    /// Selected protocol execution evidence, including any OT/GC evidence.
    EvaluationEvidence,
    /// Selected recipient cipher, HPKE/AEAD, and AAD binding.
    RecipientProtection,
    /// Selected private-output proof, MAC, or authenticated-output binding.
    OutputBinding,
    /// Selected signature, MAC, or other package-authentication binding.
    PackageAuthentication,
    /// Opaque recipient ciphertext bytes.
    RecipientCiphertext,
    /// Deriver A's selected receipt evidence.
    DeriverAReceiptEvidence,
    /// Deriver B's selected receipt evidence.
    DeriverBReceiptEvidence,
    /// Export authorization consumption and replay binding.
    ConsumedExportAuthorization,
    /// Client delivery and release binding.
    ClientDeliveryEvidence,
    /// Activation Client delivery and release binding.
    ActivationClientDeliveryEvidence,
    /// Activation SigningWorker delivery and release binding.
    ActivationSigningWorkerDeliveryEvidence,
}

/// Failure while constructing profile-neutral semantic artifacts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SemanticArtifactErrorV1 {
    /// A ceremony encoding or digest edge was invalid.
    Ceremony(CeremonyContextErrorV1),
    /// The validated provenance pair could not be encoded.
    ProvenanceEncoding(ProvenanceEncodingErrorV1),
    /// The ceremony-bound recovery reference rejected its raw inputs.
    RecoveryReference(HostOnlyRecoveryReferenceErrorV1),
    /// The ceremony-bound refresh reference rejected its raw inputs.
    RefreshReference(HostOnlyRefreshReferenceErrorV1),
    /// The ceremony-bound export reference rejected its raw inputs or registered key.
    ExportReference(HostOnlyExportReferenceErrorV1),
    /// The provenance branch did not match the ceremony branch.
    InputProvenanceRequestKindMismatch,
    /// The provenance pair named a different public request context.
    InputProvenanceRequestContextMismatch,
    /// The provenance pair named a different authorization.
    InputProvenanceAuthorizationMismatch,
    /// The provenance pair named a different ceremony transcript.
    InputProvenanceTranscriptMismatch,
    /// Registration inputs used a different stable KDF scope than admission.
    RegistrationStableScopeMismatch,
    /// Recovery inputs used a different stable KDF scope than admission.
    RecoveryStableScopeMismatch,
    /// Committed registration output did not preserve its sealed admission.
    RegistrationCandidateBindingMismatch,
    /// Committed recovery output did not preserve its sealed admission.
    RecoveryCommittedOutputBindingMismatch,
    /// Committed refresh output did not preserve its sealed admission.
    RefreshCommittedOutputBindingMismatch,
    /// Export provenance named a different registered key than authorization.
    InputProvenanceRegisteredPublicKeyMismatch,
    /// A registered-state branch lacked its mandatory registered key.
    InputProvenanceRegisteredPublicKeyMissing,
    /// A mandatory opaque host-reference digest was all zero.
    ZeroOpaqueDigest(SemanticArtifactOpaqueDigestFieldV1),
    /// A one-use execution identifier was all zero.
    ZeroOneUseExecutionId,
    /// A recipient ciphertext length was zero.
    ZeroCiphertextLength,
    /// The joined client signing point was the identity.
    JoinedClientPointIdentity,
    /// The joined SigningWorker signing point was the identity.
    JoinedSigningWorkerPointIdentity,
    /// A registration candidate did not encode a valid registered public key.
    DerivedRegisteredPublicKey(RegisteredEd25519PublicKeyErrorV1),
    /// The joined public points did not satisfy the Ed25519 output relation.
    Ed25519OutputRelationMismatch,
}

impl fmt::Display for SemanticArtifactErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ceremony(error) => error.fmt(formatter),
            Self::ProvenanceEncoding(error) => error.fmt(formatter),
            Self::RecoveryReference(error) => error.fmt(formatter),
            Self::RefreshReference(error) => error.fmt(formatter),
            Self::ExportReference(error) => error.fmt(formatter),
            Self::InputProvenanceRequestKindMismatch => {
                formatter.write_str("input provenance request kind does not match the ceremony")
            }
            Self::InputProvenanceRequestContextMismatch => {
                formatter.write_str("input provenance request context does not match the ceremony")
            }
            Self::InputProvenanceAuthorizationMismatch => {
                formatter.write_str("input provenance authorization does not match the ceremony")
            }
            Self::InputProvenanceTranscriptMismatch => {
                formatter.write_str("input provenance transcript does not match the ceremony")
            }
            Self::RegistrationStableScopeMismatch => {
                formatter.write_str("registration evaluator stable scope does not match admission")
            }
            Self::RecoveryStableScopeMismatch => {
                formatter.write_str("recovery evaluator stable scope does not match admission")
            }
            Self::RegistrationCandidateBindingMismatch => {
                formatter.write_str("registration candidate output does not match admission")
            }
            Self::RecoveryCommittedOutputBindingMismatch => {
                formatter.write_str("recovery committed output does not match admission")
            }
            Self::RefreshCommittedOutputBindingMismatch => {
                formatter.write_str("refresh committed output does not match admission")
            }
            Self::InputProvenanceRegisteredPublicKeyMismatch => formatter
                .write_str("input provenance registered key does not match export authorization"),
            Self::InputProvenanceRegisteredPublicKeyMissing => formatter
                .write_str("registered-state provenance branch is missing its registered key"),
            Self::ZeroOpaqueDigest(field) => write!(formatter, "{field:?} digest must be nonzero"),
            Self::ZeroOneUseExecutionId => {
                formatter.write_str("one-use execution identifier must be nonzero")
            }
            Self::ZeroCiphertextLength => {
                formatter.write_str("recipient ciphertext length must be nonzero")
            }
            Self::JoinedClientPointIdentity => {
                formatter.write_str("joined client signing point must be nonidentity")
            }
            Self::JoinedSigningWorkerPointIdentity => {
                formatter.write_str("joined SigningWorker point must be nonidentity")
            }
            Self::DerivedRegisteredPublicKey(error) => error.fmt(formatter),
            Self::Ed25519OutputRelationMismatch => {
                formatter.write_str("activation points violate 2*X_client-X_server=A_pub")
            }
        }
    }
}

impl std::error::Error for SemanticArtifactErrorV1 {}

impl From<CeremonyContextErrorV1> for SemanticArtifactErrorV1 {
    fn from(value: CeremonyContextErrorV1) -> Self {
        Self::Ceremony(value)
    }
}

impl From<ProvenanceEncodingErrorV1> for SemanticArtifactErrorV1 {
    fn from(value: ProvenanceEncodingErrorV1) -> Self {
        Self::ProvenanceEncoding(value)
    }
}

impl From<HostOnlyRecoveryReferenceErrorV1> for SemanticArtifactErrorV1 {
    fn from(value: HostOnlyRecoveryReferenceErrorV1) -> Self {
        Self::RecoveryReference(value)
    }
}

impl From<HostOnlyRefreshReferenceErrorV1> for SemanticArtifactErrorV1 {
    fn from(value: HostOnlyRefreshReferenceErrorV1) -> Self {
        Self::RefreshReference(value)
    }
}

impl From<HostOnlyExportReferenceErrorV1> for SemanticArtifactErrorV1 {
    fn from(value: HostOnlyExportReferenceErrorV1) -> Self {
        Self::ExportReference(value)
    }
}

fn validate_nonzero_digest(
    bytes: [u8; 32],
    field: SemanticArtifactOpaqueDigestFieldV1,
) -> Result<[u8; 32], SemanticArtifactErrorV1> {
    if bytes == [0; 32] {
        return Err(SemanticArtifactErrorV1::ZeroOpaqueDigest(field));
    }
    Ok(bytes)
}

/// Nonzero one-use execution identifier shared by one fixed package set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OneUseExecutionId32V1([u8; 32]);

impl OneUseExecutionId32V1 {
    /// Validates an exact nonzero execution identifier.
    pub fn new(bytes: [u8; 32]) -> Result<Self, SemanticArtifactErrorV1> {
        if bytes == [0; 32] {
            return Err(SemanticArtifactErrorV1::ZeroOneUseExecutionId);
        }
        Ok(Self(bytes))
    }

    /// Returns the exact execution identifier bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Nonzero recipient ciphertext length encoded as BE64.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SemanticCiphertextLengthV1(NonZeroU64);

impl SemanticCiphertextLengthV1 {
    /// Validates a nonzero ciphertext length.
    pub const fn new(value: u64) -> Result<Self, SemanticArtifactErrorV1> {
        match NonZeroU64::new(value) {
            Some(value) => Ok(Self(value)),
            None => Err(SemanticArtifactErrorV1::ZeroCiphertextLength),
        }
    }

    /// Returns the length encoded as BE64 by package descriptors.
    pub const fn value(self) -> u64 {
        self.0.get()
    }
}

/// Typed client recipient/key binding derived from the canonical request context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ClientRecipientKeyBindingDigest32V1([u8; 32]);

impl ClientRecipientKeyBindingDigest32V1 {
    fn derive(request_context_digest: &CeremonyPublicRequestContextDigest32V1) -> Self {
        Self(digest_encoding(
            CLIENT_RECIPIENT_KEY_BINDING_DOMAIN_V1,
            request_context_digest.as_bytes(),
        ))
    }

    /// Returns the computed client recipient/key-binding digest.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Typed SigningWorker recipient/key binding derived from the canonical request context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SigningWorkerRecipientKeyBindingDigest32V1([u8; 32]);

impl SigningWorkerRecipientKeyBindingDigest32V1 {
    pub(crate) fn derive(request_context_digest: &CeremonyPublicRequestContextDigest32V1) -> Self {
        Self(digest_encoding(
            SIGNING_WORKER_RECIPIENT_KEY_BINDING_DOMAIN_V1,
            request_context_digest.as_bytes(),
        ))
    }

    /// Returns the computed SigningWorker recipient/key-binding digest.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

macro_rules! define_opaque_host_reference_digest {
    ($(#[$meta:meta])* $name:ident, $field:expr) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name([u8; 32]);

        impl $name {
            /// Validates a nonzero opaque host-reference digest.
            ///
            /// This constructor records a semantic slot. It does not verify the
            /// referenced cryptographic artifact.
            pub fn new(bytes: [u8; 32]) -> Result<Self, SemanticArtifactErrorV1> {
                validate_nonzero_digest(bytes, $field).map(Self)
            }

            /// Returns the exact opaque digest bytes.
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "([opaque host-reference digest])"))
            }
        }
    };
}

define_opaque_host_reference_digest!(
    /// Opaque selected-protocol execution evidence binding.
    OpaqueHostReferenceEvaluationEvidenceDigest32V1,
    SemanticArtifactOpaqueDigestFieldV1::EvaluationEvidence
);
define_opaque_host_reference_digest!(
    /// Opaque selected recipient-protection binding.
    OpaqueHostReferenceRecipientProtectionDigest32V1,
    SemanticArtifactOpaqueDigestFieldV1::RecipientProtection
);
define_opaque_host_reference_digest!(
    /// Opaque selected private-output binding.
    OpaqueHostReferenceOutputBindingDigest32V1,
    SemanticArtifactOpaqueDigestFieldV1::OutputBinding
);
define_opaque_host_reference_digest!(
    /// Opaque selected package-authentication binding.
    OpaqueHostReferencePackageAuthenticationDigest32V1,
    SemanticArtifactOpaqueDigestFieldV1::PackageAuthentication
);
define_opaque_host_reference_digest!(
    /// Opaque recipient ciphertext digest.
    OpaqueHostReferenceRecipientCiphertextDigest32V1,
    SemanticArtifactOpaqueDigestFieldV1::RecipientCiphertext
);
define_opaque_host_reference_digest!(
    /// Opaque Deriver A receipt-evidence digest.
    OpaqueHostReferenceDeriverAReceiptEvidenceDigest32V1,
    SemanticArtifactOpaqueDigestFieldV1::DeriverAReceiptEvidence
);
define_opaque_host_reference_digest!(
    /// Opaque Deriver B receipt-evidence digest.
    OpaqueHostReferenceDeriverBReceiptEvidenceDigest32V1,
    SemanticArtifactOpaqueDigestFieldV1::DeriverBReceiptEvidence
);
define_opaque_host_reference_digest!(
    /// Opaque consumed export-authorization and replay-binding digest.
    OpaqueHostReferenceConsumedExportAuthorizationDigest32V1,
    SemanticArtifactOpaqueDigestFieldV1::ConsumedExportAuthorization
);
define_opaque_host_reference_digest!(
    /// Opaque client delivery and release evidence digest.
    OpaqueHostReferenceClientDeliveryEvidenceDigest32V1,
    SemanticArtifactOpaqueDigestFieldV1::ClientDeliveryEvidence
);
define_opaque_host_reference_digest!(
    /// Opaque activation Client delivery and release evidence digest.
    OpaqueHostReferenceActivationClientDeliveryEvidenceDigest32V1,
    SemanticArtifactOpaqueDigestFieldV1::ActivationClientDeliveryEvidence
);
define_opaque_host_reference_digest!(
    /// Opaque activation SigningWorker delivery and release evidence digest.
    OpaqueHostReferenceActivationSigningWorkerDeliveryEvidenceDigest32V1,
    SemanticArtifactOpaqueDigestFieldV1::ActivationSigningWorkerDeliveryEvidence
);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct ComputedInputProvenanceDigest32V1([u8; 32]);

impl ComputedInputProvenanceDigest32V1 {
    const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct OpaqueHostReferencePackageBindingsCoreV1 {
    recipient_protection_digest: OpaqueHostReferenceRecipientProtectionDigest32V1,
    recipient_ciphertext_digest: OpaqueHostReferenceRecipientCiphertextDigest32V1,
    ciphertext_length: SemanticCiphertextLengthV1,
    output_binding_digest: OpaqueHostReferenceOutputBindingDigest32V1,
    package_authentication_digest: OpaqueHostReferencePackageAuthenticationDigest32V1,
}

impl OpaqueHostReferencePackageBindingsCoreV1 {
    const fn new(
        recipient_protection_digest: OpaqueHostReferenceRecipientProtectionDigest32V1,
        recipient_ciphertext_digest: OpaqueHostReferenceRecipientCiphertextDigest32V1,
        ciphertext_length: SemanticCiphertextLengthV1,
        output_binding_digest: OpaqueHostReferenceOutputBindingDigest32V1,
        package_authentication_digest: OpaqueHostReferencePackageAuthenticationDigest32V1,
    ) -> Self {
        Self {
            recipient_protection_digest,
            recipient_ciphertext_digest,
            ciphertext_length,
            output_binding_digest,
            package_authentication_digest,
        }
    }
}

macro_rules! define_role_recipient_package_bindings {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub struct $name(OpaqueHostReferencePackageBindingsCoreV1);

        impl $name {
            /// Creates all required role- and recipient-typed package bindings.
            pub const fn new(
                recipient_protection_digest: OpaqueHostReferenceRecipientProtectionDigest32V1,
                recipient_ciphertext_digest: OpaqueHostReferenceRecipientCiphertextDigest32V1,
                ciphertext_length: SemanticCiphertextLengthV1,
                output_binding_digest: OpaqueHostReferenceOutputBindingDigest32V1,
                package_authentication_digest: OpaqueHostReferencePackageAuthenticationDigest32V1,
            ) -> Self {
                Self(OpaqueHostReferencePackageBindingsCoreV1::new(
                    recipient_protection_digest,
                    recipient_ciphertext_digest,
                    ciphertext_length,
                    output_binding_digest,
                    package_authentication_digest,
                ))
            }
        }
    };
}

define_role_recipient_package_bindings!(
    /// Exact mandatory opaque slots for Deriver A's activation client package.
    OpaqueHostReferenceActivationDeriverAClientPackageBindingsV1
);
define_role_recipient_package_bindings!(
    /// Exact mandatory opaque slots for Deriver B's activation client package.
    OpaqueHostReferenceActivationDeriverBClientPackageBindingsV1
);
define_role_recipient_package_bindings!(
    /// Exact mandatory opaque slots for Deriver A's SigningWorker package.
    OpaqueHostReferenceDeriverASigningWorkerPackageBindingsV1
);
define_role_recipient_package_bindings!(
    /// Exact mandatory opaque slots for Deriver B's SigningWorker package.
    OpaqueHostReferenceDeriverBSigningWorkerPackageBindingsV1
);
define_role_recipient_package_bindings!(
    /// Exact mandatory opaque slots for Deriver A's export client package.
    OpaqueHostReferenceExportDeriverAClientPackageBindingsV1
);
define_role_recipient_package_bindings!(
    /// Exact mandatory opaque slots for Deriver B's export client package.
    OpaqueHostReferenceExportDeriverBClientPackageBindingsV1
);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SemanticCeremonyBindingV1 {
    request_kind: CeremonyRequestKindV1,
    request_context_digest: CeremonyPublicRequestContextDigest32V1,
    authorization_digest: CeremonyAuthorizationDigest32V1,
    transcript_digest: CeremonyTranscriptDigest32V1,
    transport_binding_digest: CeremonyTransportBindingDigest32V1,
    artifact_suite_digest: CeremonyArtifactSuiteDigest32V1,
    one_use_execution_id: OneUseExecutionId32V1,
    input_provenance_digest: ComputedInputProvenanceDigest32V1,
    evaluation_evidence_digest: OpaqueHostReferenceEvaluationEvidenceDigest32V1,
}

impl SemanticCeremonyBindingV1 {
    #[cfg_attr(not(test), allow(dead_code))]
    fn new(
        request: &CeremonyPublicRequestContextV1,
        authorization: &CeremonyAuthorizationV1,
        transcript: &CeremonyTranscriptV1,
        one_use_execution_id: OneUseExecutionId32V1,
        input_provenance: &RoleInputProvenancePairV1,
        evaluation_evidence_digest: OpaqueHostReferenceEvaluationEvidenceDigest32V1,
    ) -> Result<Self, SemanticArtifactErrorV1> {
        let ceremony = CeremonyValidatedDagV1::from_components(request, authorization, transcript)?;
        let input_provenance_digest =
            validate_input_provenance_for_ceremony(ceremony, input_provenance)?;
        Ok(Self {
            request_kind: ceremony.request_kind(),
            request_context_digest: ceremony.request_context_digest(),
            authorization_digest: ceremony.authorization_digest(),
            transcript_digest: ceremony.transcript_digest(),
            transport_binding_digest: transcript.transport_binding_digest(),
            artifact_suite_digest: transcript.artifact_suite_digest(),
            one_use_execution_id,
            input_provenance_digest,
            evaluation_evidence_digest,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActivationRegisteredIdentityV1 {
    RegistrationCandidate,
    Preserve(RegisteredEd25519PublicKey32V1),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ActivationSemanticArtifactContextCoreV1 {
    ceremony: SemanticCeremonyBindingV1,
    origin: ActivationPackageOriginV1,
    activation_epoch: CeremonyActivationEpochV1,
    registered_identity: ActivationRegisteredIdentityV1,
}

/// Move-owned activation packages retaining the exact shares from one evaluation.
pub struct HostOnlyPackagedActivationV1 {
    packages: ActivationPackageSetV1,
    shares: HostOnlyActivationOutputSharesV1,
}

impl HostOnlyPackagedActivationV1 {
    /// Returns the exact ceremony-bound activation package set.
    pub const fn packages(&self) -> &ActivationPackageSetV1 {
        &self.packages
    }

    pub(crate) fn into_parts(self) -> (ActivationPackageSetV1, HostOnlyActivationOutputSharesV1) {
        (self.packages, self.shares)
    }
}

fn package_activation_output(
    context: ActivationSemanticArtifactContextCoreV1,
    shares: HostOnlyActivationOutputSharesV1,
    bindings: OpaqueHostReferenceActivationPackageBindingsV1,
) -> Result<HostOnlyPackagedActivationV1, SemanticArtifactErrorV1> {
    let packages = ActivationPackageSetV1::from_ceremony_bound_host_reference(
        CeremonyBoundActivationHostReferenceV1::new(context, &shares, bindings),
    )?;
    Ok(HostOnlyPackagedActivationV1 { packages, shares })
}

/// Move-only registration session for ceremony-bound host-reference packages.
///
/// ```compile_fail
/// use ed25519_yao_generator::{
///     HostOnlyRegistrationIdealCoinsV1, HostOnlyRegistrationReferenceSuccessV1,
/// };
/// use ed25519_yao_generator::semantic_artifacts::{
///     OpaqueHostReferenceActivationPackageBindingsV1,
///     RegistrationActivationSemanticArtifactContextV1,
/// };
///
/// fn reject_precomputed_success(
///     session: RegistrationActivationSemanticArtifactContextV1,
///     success: HostOnlyRegistrationReferenceSuccessV1,
///     coins: HostOnlyRegistrationIdealCoinsV1,
///     bindings: OpaqueHostReferenceActivationPackageBindingsV1,
/// ) {
///     let _ = session.evaluate_and_package_host_reference(success, coins, bindings);
/// }
/// ```
///
/// ```compile_fail
/// use ed25519_yao_generator::semantic_artifacts::RegistrationActivationSemanticArtifactContextV1;
///
/// fn reject_session_clone(session: RegistrationActivationSemanticArtifactContextV1) {
///     let _ = session.clone();
/// }
/// ```
#[derive(Debug, PartialEq, Eq)]
pub struct RegistrationActivationSemanticArtifactContextV1(ActivationSemanticArtifactContextCoreV1);

impl RegistrationActivationSemanticArtifactContextV1 {
    /// Ties registration provenance to the exact registration ceremony DAG.
    #[allow(clippy::too_many_arguments)]
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn new(
        request: &CeremonyPublicRequestContextV1,
        authorization: &CeremonyRegistrationAuthorizationV1,
        transcript: &CeremonyTranscriptV1,
        activation_epoch: CeremonyActivationEpochV1,
        one_use_execution_id: OneUseExecutionId32V1,
        input_provenance: &RoleInputProvenancePairV1,
        evaluation_evidence_digest: OpaqueHostReferenceEvaluationEvidenceDigest32V1,
    ) -> Result<Self, SemanticArtifactErrorV1> {
        let authorization = CeremonyAuthorizationV1::from(*authorization);
        Ok(Self(ActivationSemanticArtifactContextCoreV1 {
            ceremony: SemanticCeremonyBindingV1::new(
                request,
                &authorization,
                transcript,
                one_use_execution_id,
                input_provenance,
                evaluation_evidence_digest,
            )?,
            origin: ActivationPackageOriginV1::Registration,
            activation_epoch,
            registered_identity: ActivationRegisteredIdentityV1::RegistrationCandidate,
        }))
    }

    /// Consumes this ceremony session, evaluates registration, and immediately packages its shares.
    ///
    /// The single call prevents a precomputed reference success from being mixed
    /// with another ceremony. Opaque provenance and evidence slots still do not
    /// authenticate the supplied synthetic inputs.
    pub fn evaluate_and_package_host_reference(
        self,
        inputs: HostOnlyRegistrationReferenceInputsV1<'_>,
        coins: HostOnlyRegistrationIdealCoinsV1,
        bindings: OpaqueHostReferenceActivationPackageBindingsV1,
    ) -> Result<HostOnlyPackagedActivationV1, SemanticArtifactErrorV1> {
        let prepared = prepare_host_only_registration_reference_v1(inputs);
        let success = evaluate_host_only_registration_output_sharing_v1(prepared, coins);
        package_activation_output(self.0, success.into_output_shares(), bindings)
    }
}

/// Move-only recovery session for ceremony-bound host-reference packages.
#[derive(Debug, PartialEq, Eq)]
pub struct RecoveryActivationSemanticArtifactContextV1(ActivationSemanticArtifactContextCoreV1);

impl RecoveryActivationSemanticArtifactContextV1 {
    /// Ties same-root recovery provenance to the exact recovery ceremony DAG.
    #[allow(clippy::too_many_arguments)]
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn new(
        request: &CeremonyPublicRequestContextV1,
        authorization: &CeremonyRecoveryAuthorizationV1,
        transcript: &CeremonyTranscriptV1,
        activation_epoch: CeremonyActivationEpochV1,
        one_use_execution_id: OneUseExecutionId32V1,
        input_provenance: &RoleInputProvenancePairV1,
        evaluation_evidence_digest: OpaqueHostReferenceEvaluationEvidenceDigest32V1,
    ) -> Result<Self, SemanticArtifactErrorV1> {
        let authorization = CeremonyAuthorizationV1::from(*authorization);
        let ceremony = SemanticCeremonyBindingV1::new(
            request,
            &authorization,
            transcript,
            one_use_execution_id,
            input_provenance,
            evaluation_evidence_digest,
        )?;
        let registered_public_key = input_provenance
            .registered_public_key()
            .ok_or(SemanticArtifactErrorV1::InputProvenanceRegisteredPublicKeyMissing)?;
        Ok(Self(ActivationSemanticArtifactContextCoreV1 {
            ceremony,
            origin: ActivationPackageOriginV1::Recovery,
            activation_epoch,
            registered_identity: ActivationRegisteredIdentityV1::Preserve(registered_public_key),
        }))
    }

    /// Consumes this ceremony session, validates recovery, and immediately packages its shares.
    pub fn evaluate_and_package_host_reference(
        self,
        inputs: HostOnlyRecoveryReferenceInputsV1<'_>,
        coins: HostOnlyRecoveryIdealCoinsV1,
        bindings: OpaqueHostReferenceActivationPackageBindingsV1,
    ) -> Result<HostOnlyPackagedActivationV1, SemanticArtifactErrorV1> {
        let prepared = prepare_host_only_recovery_reference_v1(inputs)?;
        let success = evaluate_host_only_recovery_output_sharing_v1(prepared, coins);
        package_activation_output(self.0, success.into_output_shares(), bindings)
    }
}

/// Move-only refresh session for ceremony-bound host-reference packages.
#[derive(Debug, PartialEq, Eq)]
pub struct RefreshActivationSemanticArtifactContextV1(ActivationSemanticArtifactContextCoreV1);

impl RefreshActivationSemanticArtifactContextV1 {
    /// Ties opposite-delta refresh provenance to the exact refresh ceremony DAG.
    #[allow(clippy::too_many_arguments)]
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn new(
        request: &CeremonyPublicRequestContextV1,
        authorization: &CeremonyRefreshAuthorizationV1,
        transcript: &CeremonyTranscriptV1,
        activation_epoch: CeremonyActivationEpochV1,
        one_use_execution_id: OneUseExecutionId32V1,
        input_provenance: &RoleInputProvenancePairV1,
        evaluation_evidence_digest: OpaqueHostReferenceEvaluationEvidenceDigest32V1,
    ) -> Result<Self, SemanticArtifactErrorV1> {
        let authorization = CeremonyAuthorizationV1::from(*authorization);
        let ceremony = SemanticCeremonyBindingV1::new(
            request,
            &authorization,
            transcript,
            one_use_execution_id,
            input_provenance,
            evaluation_evidence_digest,
        )?;
        let registered_public_key = input_provenance
            .registered_public_key()
            .ok_or(SemanticArtifactErrorV1::InputProvenanceRegisteredPublicKeyMissing)?;
        Ok(Self(ActivationSemanticArtifactContextCoreV1 {
            ceremony,
            origin: ActivationPackageOriginV1::Refresh,
            activation_epoch,
            registered_identity: ActivationRegisteredIdentityV1::Preserve(registered_public_key),
        }))
    }

    /// Consumes this ceremony session, validates refresh, and immediately packages its shares.
    pub fn evaluate_and_package_host_reference(
        self,
        inputs: HostOnlyRefreshReferenceInputsV1<'_>,
        coins: HostOnlyRefreshIdealCoinsV1,
        bindings: OpaqueHostReferenceActivationPackageBindingsV1,
    ) -> Result<HostOnlyPackagedActivationV1, SemanticArtifactErrorV1> {
        let prepared = prepare_host_only_refresh_reference_v1(inputs)?;
        let success = evaluate_host_only_refresh_output_sharing_v1(prepared, coins);
        package_activation_output(self.0, success.into_output_shares(), bindings)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ExportSemanticArtifactContextCoreV1 {
    ceremony: SemanticCeremonyBindingV1,
    registered_public_key: RegisteredEd25519PublicKey32V1,
}

/// Move-only export session for ceremony-bound host-reference packages.
#[derive(Debug, PartialEq, Eq)]
pub struct ExportSemanticArtifactContextV1(ExportSemanticArtifactContextCoreV1);

/// Move-owned export packages retaining the exact shares produced by the same evaluation.
pub struct HostOnlyPackagedExportV1 {
    packages: ExportPackageSetV1,
    shares: HostOnlySeedExportSharesV1,
}

impl HostOnlyPackagedExportV1 {
    /// Returns the exact ceremony-bound export package set.
    pub const fn packages(&self) -> &ExportPackageSetV1 {
        &self.packages
    }

    pub(crate) fn into_parts(self) -> (ExportPackageSetV1, HostOnlySeedExportSharesV1) {
        (self.packages, self.shares)
    }
}

impl ExportSemanticArtifactContextV1 {
    /// Validates an export ceremony binding.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn new(
        request: &CeremonyPublicRequestContextV1,
        authorization: &CeremonyExportAuthorizationV1,
        transcript: &CeremonyTranscriptV1,
        one_use_execution_id: OneUseExecutionId32V1,
        input_provenance: &RoleInputProvenancePairV1,
        evaluation_evidence_digest: OpaqueHostReferenceEvaluationEvidenceDigest32V1,
    ) -> Result<Self, SemanticArtifactErrorV1> {
        let authorization_union = CeremonyAuthorizationV1::from(*authorization);
        let ceremony = SemanticCeremonyBindingV1::new(
            request,
            &authorization_union,
            transcript,
            one_use_execution_id,
            input_provenance,
            evaluation_evidence_digest,
        )?;
        let provenance_public_key = input_provenance
            .registered_public_key()
            .ok_or(SemanticArtifactErrorV1::InputProvenanceRegisteredPublicKeyMissing)?;
        if provenance_public_key != authorization.registered_public_key() {
            return Err(SemanticArtifactErrorV1::InputProvenanceRegisteredPublicKeyMismatch);
        }
        Ok(Self(ExportSemanticArtifactContextCoreV1 {
            ceremony,
            registered_public_key: authorization.registered_public_key(),
        }))
    }

    /// Consumes this ceremony session, validates export, and immediately packages its shares.
    ///
    /// The expected registered key comes exclusively from this authorization-
    /// and provenance-bound context.
    pub fn evaluate_and_package_host_reference(
        self,
        inputs: HostOnlyExportReferenceInputsV1<'_>,
        coin: HostOnlyExportIdealCoinV1,
        bindings: OpaqueHostReferenceExportPackageBindingsV1,
    ) -> Result<HostOnlyPackagedExportV1, SemanticArtifactErrorV1> {
        let prepared =
            prepare_host_only_export_reference_v1(inputs, &self.0.registered_public_key)?;
        let success = evaluate_host_only_export_output_sharing_v1(prepared, coin);
        let packages = ExportPackageSetV1::from_ceremony_bound_host_reference(
            CeremonyBoundExportHostReferenceV1::new(self.0, success.output_shares(), bindings),
        );
        Ok(HostOnlyPackagedExportV1 {
            packages,
            shares: success.into_output_shares(),
        })
    }
}

#[cfg_attr(not(test), allow(dead_code))]
fn validate_input_provenance_for_ceremony(
    ceremony: CeremonyValidatedDagV1,
    input_provenance: &RoleInputProvenancePairV1,
) -> Result<ComputedInputProvenanceDigest32V1, SemanticArtifactErrorV1> {
    let expected_request_kind = match ceremony.request_kind() {
        CeremonyRequestKindV1::Registration => ProvenanceRequestKindV1::Registration,
        CeremonyRequestKindV1::Recovery => ProvenanceRequestKindV1::Recovery,
        CeremonyRequestKindV1::Refresh => ProvenanceRequestKindV1::Refresh,
        CeremonyRequestKindV1::Export => ProvenanceRequestKindV1::Export,
        CeremonyRequestKindV1::Activation => {
            return Err(SemanticArtifactErrorV1::InputProvenanceRequestKindMismatch)
        }
    };
    if input_provenance.deriver_a().request_kind() != expected_request_kind {
        return Err(SemanticArtifactErrorV1::InputProvenanceRequestKindMismatch);
    }
    if input_provenance.ceremony_request_context_digest() != ceremony.request_context_digest() {
        return Err(SemanticArtifactErrorV1::InputProvenanceRequestContextMismatch);
    }
    if input_provenance.ceremony_authorization_digest() != ceremony.authorization_digest() {
        return Err(SemanticArtifactErrorV1::InputProvenanceAuthorizationMismatch);
    }
    if input_provenance.ceremony_transcript_digest() != ceremony.transcript_digest() {
        return Err(SemanticArtifactErrorV1::InputProvenanceTranscriptMismatch);
    }
    let digest = input_provenance.digest()?;
    Ok(ComputedInputProvenanceDigest32V1(*digest.as_bytes()))
}

#[derive(Clone, PartialEq, Eq)]
struct ActivationScalarPackageDescriptorCoreV1<Role: ProvenanceRoleV1> {
    context: ActivationSemanticArtifactContextCoreV1,
    recipient_tag: u8,
    output_tag: u8,
    recipient_key_binding: [u8; 32],
    scalar_share_point: [u8; 32],
    bindings: OpaqueHostReferencePackageBindingsCoreV1,
    role: PhantomData<Role>,
}

impl<Role: ProvenanceRoleV1> fmt::Debug for ActivationScalarPackageDescriptorCoreV1<Role> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ActivationScalarPackageDescriptorCoreV1")
            .field("origin", &self.context.origin)
            .field("role", &Role::KIND)
            .field("recipient_tag", &self.recipient_tag)
            .field("output_tag", &self.output_tag)
            .field("recipient_key_binding", &"[computed public digest]")
            .field("scalar_share_point", &"[validated public point]")
            .field("bindings", &self.bindings)
            .finish()
    }
}

impl<Role: ProvenanceRoleV1> ActivationScalarPackageDescriptorCoreV1<Role> {
    fn new(
        context: ActivationSemanticArtifactContextCoreV1,
        recipient_tag: u8,
        output_tag: u8,
        recipient_key_binding: [u8; 32],
        scalar_share_bytes: [u8; 32],
        bindings: OpaqueHostReferencePackageBindingsCoreV1,
    ) -> Self {
        let scalar = Option::<Scalar>::from(Scalar::from_canonical_bytes(scalar_share_bytes))
            .expect("host-only typed scalar share must remain canonical");
        let point = ED25519_BASEPOINT_POINT * scalar;
        Self {
            context,
            recipient_tag,
            output_tag,
            recipient_key_binding,
            scalar_share_point: point.compress().to_bytes(),
            bindings,
            role: PhantomData,
        }
    }

    fn encode(&self, domain: &[u8]) -> Vec<u8> {
        let mut output = Vec::new();
        push_lp32(&mut output, domain);
        push_lp32(&mut output, &[self.context.ceremony.request_kind.tag()]);
        push_lp32(&mut output, &[Role::TAG]);
        push_lp32(&mut output, &[self.recipient_tag]);
        push_lp32(&mut output, &[self.output_tag]);
        encode_ceremony_binding(&mut output, &self.context.ceremony);
        push_lp32(
            &mut output,
            &self.context.activation_epoch.value().to_be_bytes(),
        );
        push_lp32(&mut output, &self.recipient_key_binding);
        push_lp32(&mut output, &self.scalar_share_point);
        encode_package_bindings(&mut output, &self.bindings);
        output
    }

    fn point(&self) -> EdwardsPoint {
        CompressedEdwardsY(self.scalar_share_point)
            .decompress()
            .expect("internally generated scalar-share point must decompress")
    }
}

/// Client-scalar activation package descriptor for one sealed Deriver role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientScalarActivationPackageDescriptorV1<Role: ProvenanceRoleV1>(
    ActivationScalarPackageDescriptorCoreV1<Role>,
);

/// SigningWorker-scalar activation package descriptor for one sealed Deriver role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningWorkerScalarActivationPackageDescriptorV1<Role: ProvenanceRoleV1>(
    ActivationScalarPackageDescriptorCoreV1<Role>,
);

/// Deriver A client-scalar activation descriptor.
pub type DeriverAClientScalarActivationPackageDescriptorV1 =
    ClientScalarActivationPackageDescriptorV1<DeriverAProvenanceRoleV1>;
/// Deriver B client-scalar activation descriptor.
pub type DeriverBClientScalarActivationPackageDescriptorV1 =
    ClientScalarActivationPackageDescriptorV1<DeriverBProvenanceRoleV1>;
/// Deriver A SigningWorker-scalar activation descriptor.
pub type DeriverASigningWorkerScalarActivationPackageDescriptorV1 =
    SigningWorkerScalarActivationPackageDescriptorV1<DeriverAProvenanceRoleV1>;
/// Deriver B SigningWorker-scalar activation descriptor.
pub type DeriverBSigningWorkerScalarActivationPackageDescriptorV1 =
    SigningWorkerScalarActivationPackageDescriptorV1<DeriverBProvenanceRoleV1>;

macro_rules! activation_descriptor_api {
    ($descriptor:ident, $role:ty, $domain:ident) => {
        impl $descriptor<$role> {
            #[allow(dead_code)]
            pub(crate) const fn scalar_share_point(&self) -> &[u8; 32] {
                &self.0.scalar_share_point
            }

            #[allow(dead_code)]
            pub(crate) const fn recipient_tag(&self) -> u8 {
                self.0.recipient_tag
            }

            #[allow(dead_code)]
            pub(crate) const fn output_tag(&self) -> u8 {
                self.0.output_tag
            }

            #[allow(dead_code)]
            pub(crate) const fn recipient_key_binding(&self) -> &[u8; 32] {
                &self.0.recipient_key_binding
            }

            #[allow(dead_code)]
            pub(crate) const fn activation_epoch(&self) -> CeremonyActivationEpochV1 {
                self.0.context.activation_epoch
            }

            #[allow(dead_code)]
            pub(crate) const fn request_context_digest(
                &self,
            ) -> CeremonyPublicRequestContextDigest32V1 {
                self.0.context.ceremony.request_context_digest
            }

            #[allow(dead_code)]
            pub(crate) const fn package_authentication_digest(
                &self,
            ) -> OpaqueHostReferencePackageAuthenticationDigest32V1 {
                self.0.bindings.package_authentication_digest
            }

            /// Encodes the exact ordered LP32 semantic descriptor.
            pub fn encode(&self) -> Vec<u8> {
                self.0.encode($domain)
            }
        }
    };
}

activation_descriptor_api!(
    ClientScalarActivationPackageDescriptorV1,
    DeriverAProvenanceRoleV1,
    ACTIVATION_DERIVER_A_CLIENT_DESCRIPTOR_DOMAIN_V1
);
activation_descriptor_api!(
    ClientScalarActivationPackageDescriptorV1,
    DeriverBProvenanceRoleV1,
    ACTIVATION_DERIVER_B_CLIENT_DESCRIPTOR_DOMAIN_V1
);
activation_descriptor_api!(
    SigningWorkerScalarActivationPackageDescriptorV1,
    DeriverAProvenanceRoleV1,
    ACTIVATION_DERIVER_A_SIGNING_WORKER_DESCRIPTOR_DOMAIN_V1
);
activation_descriptor_api!(
    SigningWorkerScalarActivationPackageDescriptorV1,
    DeriverBProvenanceRoleV1,
    ACTIVATION_DERIVER_B_SIGNING_WORKER_DESCRIPTOR_DOMAIN_V1
);

#[derive(Debug, Clone, PartialEq, Eq)]
struct ClientSeedExportPackageDescriptorCoreV1<Role: ProvenanceRoleV1> {
    context: ExportSemanticArtifactContextCoreV1,
    recipient_key_binding: ClientRecipientKeyBindingDigest32V1,
    bindings: OpaqueHostReferencePackageBindingsCoreV1,
    role: PhantomData<Role>,
}

impl<Role: ProvenanceRoleV1> ClientSeedExportPackageDescriptorCoreV1<Role> {
    fn new(
        context: ExportSemanticArtifactContextCoreV1,
        bindings: OpaqueHostReferencePackageBindingsCoreV1,
    ) -> Self {
        Self {
            context,
            recipient_key_binding: ClientRecipientKeyBindingDigest32V1::derive(
                &context.ceremony.request_context_digest,
            ),
            bindings,
            role: PhantomData,
        }
    }

    fn encode(&self, domain: &[u8]) -> Vec<u8> {
        let mut output = Vec::new();
        push_lp32(&mut output, domain);
        push_lp32(&mut output, &[CeremonyRequestKindV1::Export.tag()]);
        push_lp32(&mut output, &[Role::TAG]);
        push_lp32(&mut output, &[CLIENT_RECIPIENT_TAG_V1]);
        push_lp32(&mut output, &[CLIENT_SEED_OUTPUT_TAG_V1]);
        encode_ceremony_binding(&mut output, &self.context.ceremony);
        push_lp32(&mut output, self.recipient_key_binding.as_bytes());
        encode_package_bindings(&mut output, &self.bindings);
        output
    }
}

/// Client-only seed-export package descriptor for one sealed Deriver role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientSeedExportPackageDescriptorV1<Role: ProvenanceRoleV1>(
    ClientSeedExportPackageDescriptorCoreV1<Role>,
);

/// Deriver A client-only seed-export descriptor.
pub type DeriverAClientSeedExportPackageDescriptorV1 =
    ClientSeedExportPackageDescriptorV1<DeriverAProvenanceRoleV1>;
/// Deriver B client-only seed-export descriptor.
pub type DeriverBClientSeedExportPackageDescriptorV1 =
    ClientSeedExportPackageDescriptorV1<DeriverBProvenanceRoleV1>;

impl ClientSeedExportPackageDescriptorV1<DeriverAProvenanceRoleV1> {
    fn from_deriver_a_host_reference_share(
        context: ExportSemanticArtifactContextCoreV1,
        _share: &HostOnlyDeriverASeedExportShareV1,
        bindings: OpaqueHostReferenceExportDeriverAClientPackageBindingsV1,
    ) -> Self {
        Self(ClientSeedExportPackageDescriptorCoreV1::new(
            context, bindings.0,
        ))
    }

    /// Encodes the exact ordered LP32 semantic descriptor.
    pub fn encode(&self) -> Vec<u8> {
        self.0.encode(EXPORT_DERIVER_A_CLIENT_DESCRIPTOR_DOMAIN_V1)
    }
}

impl ClientSeedExportPackageDescriptorV1<DeriverBProvenanceRoleV1> {
    fn from_deriver_b_host_reference_share(
        context: ExportSemanticArtifactContextCoreV1,
        _share: &HostOnlyDeriverBSeedExportShareV1,
        bindings: OpaqueHostReferenceExportDeriverBClientPackageBindingsV1,
    ) -> Self {
        Self(ClientSeedExportPackageDescriptorCoreV1::new(
            context, bindings.0,
        ))
    }

    /// Encodes the exact ordered LP32 semantic descriptor.
    pub fn encode(&self) -> Vec<u8> {
        self.0.encode(EXPORT_DERIVER_B_CLIENT_DESCRIPTOR_DOMAIN_V1)
    }
}

/// Exact opaque bindings for the fixed four-member activation package set.
///
/// ```compile_fail
/// use ed25519_yao_generator::semantic_artifacts::{
///     OpaqueHostReferenceActivationPackageBindingsV1,
///     OpaqueHostReferenceActivationDeriverAClientPackageBindingsV1,
///     OpaqueHostReferenceActivationDeriverBClientPackageBindingsV1,
///     OpaqueHostReferenceDeriverASigningWorkerPackageBindingsV1,
///     OpaqueHostReferenceDeriverBSigningWorkerPackageBindingsV1,
/// };
///
/// fn reject_recipient_swap(
///     a_client: OpaqueHostReferenceActivationDeriverAClientPackageBindingsV1,
///     b_client: OpaqueHostReferenceActivationDeriverBClientPackageBindingsV1,
///     a_worker: OpaqueHostReferenceDeriverASigningWorkerPackageBindingsV1,
///     b_worker: OpaqueHostReferenceDeriverBSigningWorkerPackageBindingsV1,
/// ) {
///     let _ = OpaqueHostReferenceActivationPackageBindingsV1::new(
///         a_worker, b_client, a_client, b_worker,
///     );
/// }
/// ```
///
/// ```compile_fail
/// use ed25519_yao_generator::semantic_artifacts::{
///     OpaqueHostReferenceActivationPackageBindingsV1,
///     OpaqueHostReferenceActivationDeriverAClientPackageBindingsV1,
///     OpaqueHostReferenceActivationDeriverBClientPackageBindingsV1,
///     OpaqueHostReferenceDeriverASigningWorkerPackageBindingsV1,
///     OpaqueHostReferenceDeriverBSigningWorkerPackageBindingsV1,
/// };
///
/// fn reject_role_swap(
///     a_client: OpaqueHostReferenceActivationDeriverAClientPackageBindingsV1,
///     b_client: OpaqueHostReferenceActivationDeriverBClientPackageBindingsV1,
///     a_worker: OpaqueHostReferenceDeriverASigningWorkerPackageBindingsV1,
///     b_worker: OpaqueHostReferenceDeriverBSigningWorkerPackageBindingsV1,
/// ) {
///     let _ = OpaqueHostReferenceActivationPackageBindingsV1::new(
///         b_client, a_client, b_worker, a_worker,
///     );
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpaqueHostReferenceActivationPackageBindingsV1 {
    deriver_a_client: OpaqueHostReferenceActivationDeriverAClientPackageBindingsV1,
    deriver_b_client: OpaqueHostReferenceActivationDeriverBClientPackageBindingsV1,
    deriver_a_signing_worker: OpaqueHostReferenceDeriverASigningWorkerPackageBindingsV1,
    deriver_b_signing_worker: OpaqueHostReferenceDeriverBSigningWorkerPackageBindingsV1,
}

impl OpaqueHostReferenceActivationPackageBindingsV1 {
    /// Creates all mandatory activation package bindings in fixed order.
    pub const fn new(
        deriver_a_client: OpaqueHostReferenceActivationDeriverAClientPackageBindingsV1,
        deriver_b_client: OpaqueHostReferenceActivationDeriverBClientPackageBindingsV1,
        deriver_a_signing_worker: OpaqueHostReferenceDeriverASigningWorkerPackageBindingsV1,
        deriver_b_signing_worker: OpaqueHostReferenceDeriverBSigningWorkerPackageBindingsV1,
    ) -> Self {
        Self {
            deriver_a_client,
            deriver_b_client,
            deriver_a_signing_worker,
            deriver_b_signing_worker,
        }
    }
}

/// Exact opaque bindings for the fixed two-member export package set.
///
/// ```compile_fail
/// use ed25519_yao_generator::semantic_artifacts::{
///     OpaqueHostReferenceActivationDeriverAClientPackageBindingsV1,
///     OpaqueHostReferenceActivationDeriverBClientPackageBindingsV1,
///     OpaqueHostReferenceExportPackageBindingsV1,
/// };
///
/// fn reject_activation_bindings_in_export(
///     a: OpaqueHostReferenceActivationDeriverAClientPackageBindingsV1,
///     b: OpaqueHostReferenceActivationDeriverBClientPackageBindingsV1,
/// ) {
///     let _ = OpaqueHostReferenceExportPackageBindingsV1::new(a, b);
/// }
/// ```
///
/// ```compile_fail
/// use ed25519_yao_generator::semantic_artifacts::{
///     OpaqueHostReferenceActivationPackageBindingsV1,
///     OpaqueHostReferenceDeriverASigningWorkerPackageBindingsV1,
///     OpaqueHostReferenceDeriverBSigningWorkerPackageBindingsV1,
///     OpaqueHostReferenceExportDeriverAClientPackageBindingsV1,
///     OpaqueHostReferenceExportDeriverBClientPackageBindingsV1,
/// };
///
/// fn reject_export_bindings_in_activation(
///     a: OpaqueHostReferenceExportDeriverAClientPackageBindingsV1,
///     b: OpaqueHostReferenceExportDeriverBClientPackageBindingsV1,
///     a_worker: OpaqueHostReferenceDeriverASigningWorkerPackageBindingsV1,
///     b_worker: OpaqueHostReferenceDeriverBSigningWorkerPackageBindingsV1,
/// ) {
///     let _ = OpaqueHostReferenceActivationPackageBindingsV1::new(
///         a, b, a_worker, b_worker,
///     );
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpaqueHostReferenceExportPackageBindingsV1 {
    deriver_a_client: OpaqueHostReferenceExportDeriverAClientPackageBindingsV1,
    deriver_b_client: OpaqueHostReferenceExportDeriverBClientPackageBindingsV1,
}

impl OpaqueHostReferenceExportPackageBindingsV1 {
    /// Creates both mandatory client-only export package bindings.
    pub const fn new(
        deriver_a_client: OpaqueHostReferenceExportDeriverAClientPackageBindingsV1,
        deriver_b_client: OpaqueHostReferenceExportDeriverBClientPackageBindingsV1,
    ) -> Self {
        Self {
            deriver_a_client,
            deriver_b_client,
        }
    }
}

struct CeremonyBoundActivationHostReferenceV1<'a> {
    context: ActivationSemanticArtifactContextCoreV1,
    shares: &'a HostOnlyActivationOutputSharesV1,
    bindings: OpaqueHostReferenceActivationPackageBindingsV1,
}

impl<'a> CeremonyBoundActivationHostReferenceV1<'a> {
    fn new(
        context: ActivationSemanticArtifactContextCoreV1,
        shares: &'a HostOnlyActivationOutputSharesV1,
        bindings: OpaqueHostReferenceActivationPackageBindingsV1,
    ) -> Self {
        Self {
            context,
            shares,
            bindings,
        }
    }
}

struct CeremonyBoundExportHostReferenceV1<'a> {
    context: ExportSemanticArtifactContextCoreV1,
    shares: &'a HostOnlySeedExportSharesV1,
    bindings: OpaqueHostReferenceExportPackageBindingsV1,
}

impl<'a> CeremonyBoundExportHostReferenceV1<'a> {
    fn new(
        context: ExportSemanticArtifactContextCoreV1,
        shares: &'a HostOnlySeedExportSharesV1,
        bindings: OpaqueHostReferenceExportPackageBindingsV1,
    ) -> Self {
        Self {
            context,
            shares,
            bindings,
        }
    }
}

/// Fixed A-client, B-client, A-worker, B-worker activation package set.
///
/// ```compile_fail
/// use ed25519_yao_generator::HostOnlyRegistrationReferenceSuccessV1;
/// use ed25519_yao_generator::semantic_artifacts::{
///     ActivationPackageSetV1, OpaqueHostReferenceActivationPackageBindingsV1,
///     RegistrationActivationSemanticArtifactContextV1,
/// };
///
/// fn reject_precomputed_success(
///     context: RegistrationActivationSemanticArtifactContextV1,
///     success: HostOnlyRegistrationReferenceSuccessV1,
///     bindings: OpaqueHostReferenceActivationPackageBindingsV1,
/// ) {
///     let _ = ActivationPackageSetV1::from_registration_host_reference(
///         context, success, bindings,
///     );
/// }
/// ```
#[derive(Debug, PartialEq, Eq)]
pub struct ActivationPackageSetV1 {
    context: ActivationSemanticArtifactContextCoreV1,
    deriver_a_client: DeriverAClientScalarActivationPackageDescriptorV1,
    deriver_b_client: DeriverBClientScalarActivationPackageDescriptorV1,
    deriver_a_signing_worker: DeriverASigningWorkerScalarActivationPackageDescriptorV1,
    deriver_b_signing_worker: DeriverBSigningWorkerScalarActivationPackageDescriptorV1,
    x_client: [u8; 32],
    x_server: [u8; 32],
    registered_public_key: RegisteredEd25519PublicKey32V1,
}

impl ActivationPackageSetV1 {
    fn from_ceremony_bound_host_reference(
        bound: CeremonyBoundActivationHostReferenceV1<'_>,
    ) -> Result<Self, SemanticArtifactErrorV1> {
        let CeremonyBoundActivationHostReferenceV1 {
            context,
            shares,
            bindings,
        } = bound;
        let client_key_binding =
            ClientRecipientKeyBindingDigest32V1::derive(&context.ceremony.request_context_digest);
        let signing_worker_key_binding = SigningWorkerRecipientKeyBindingDigest32V1::derive(
            &context.ceremony.request_context_digest,
        );
        let deriver_a_client = ClientScalarActivationPackageDescriptorV1(
            ActivationScalarPackageDescriptorCoreV1::new(
                context,
                CLIENT_RECIPIENT_TAG_V1,
                CLIENT_SCALAR_OUTPUT_TAG_V1,
                *client_key_binding.as_bytes(),
                deriver_a_client_share_bytes(shares.deriver_a().client()),
                bindings.deriver_a_client.0,
            ),
        );
        let deriver_b_client = ClientScalarActivationPackageDescriptorV1(
            ActivationScalarPackageDescriptorCoreV1::new(
                context,
                CLIENT_RECIPIENT_TAG_V1,
                CLIENT_SCALAR_OUTPUT_TAG_V1,
                *client_key_binding.as_bytes(),
                deriver_b_client_share_bytes(shares.deriver_b().client()),
                bindings.deriver_b_client.0,
            ),
        );
        let deriver_a_signing_worker = SigningWorkerScalarActivationPackageDescriptorV1(
            ActivationScalarPackageDescriptorCoreV1::new(
                context,
                SIGNING_WORKER_RECIPIENT_TAG_V1,
                SIGNING_WORKER_SCALAR_OUTPUT_TAG_V1,
                *signing_worker_key_binding.as_bytes(),
                deriver_a_signing_worker_share_bytes(shares.deriver_a().signing_worker()),
                bindings.deriver_a_signing_worker.0,
            ),
        );
        let deriver_b_signing_worker = SigningWorkerScalarActivationPackageDescriptorV1(
            ActivationScalarPackageDescriptorCoreV1::new(
                context,
                SIGNING_WORKER_RECIPIENT_TAG_V1,
                SIGNING_WORKER_SCALAR_OUTPUT_TAG_V1,
                *signing_worker_key_binding.as_bytes(),
                deriver_b_signing_worker_share_bytes(shares.deriver_b().signing_worker()),
                bindings.deriver_b_signing_worker.0,
            ),
        );
        let x_client = deriver_a_client.0.point() + deriver_b_client.0.point();
        let x_server = deriver_a_signing_worker.0.point() + deriver_b_signing_worker.0.point();
        let validated =
            validate_activation_public_output(x_client, x_server, context.registered_identity)?;
        Ok(Self {
            context,
            deriver_a_client,
            deriver_b_client,
            deriver_a_signing_worker,
            deriver_b_signing_worker,
            x_client: validated.x_client,
            x_server: validated.x_server,
            registered_public_key: validated.registered_public_key,
        })
    }

    /// Returns Deriver A's client descriptor.
    pub const fn deriver_a_client(&self) -> &DeriverAClientScalarActivationPackageDescriptorV1 {
        &self.deriver_a_client
    }

    /// Returns Deriver B's client descriptor.
    pub const fn deriver_b_client(&self) -> &DeriverBClientScalarActivationPackageDescriptorV1 {
        &self.deriver_b_client
    }

    /// Returns Deriver A's SigningWorker descriptor.
    pub const fn deriver_a_signing_worker(
        &self,
    ) -> &DeriverASigningWorkerScalarActivationPackageDescriptorV1 {
        &self.deriver_a_signing_worker
    }

    /// Returns Deriver B's SigningWorker descriptor.
    pub const fn deriver_b_signing_worker(
        &self,
    ) -> &DeriverBSigningWorkerScalarActivationPackageDescriptorV1 {
        &self.deriver_b_signing_worker
    }

    /// Returns the validated joined client point.
    pub const fn x_client(&self) -> &[u8; 32] {
        &self.x_client
    }

    /// Returns the validated joined SigningWorker point.
    pub const fn x_server(&self) -> &[u8; 32] {
        &self.x_server
    }

    /// Returns the registered identity established or preserved by this package set.
    pub const fn registered_public_key(&self) -> RegisteredEd25519PublicKey32V1 {
        self.registered_public_key
    }

    /// Encodes the fixed four descriptors in A-client, B-client, A-worker, B-worker order.
    pub fn encode(&self) -> Vec<u8> {
        let mut output = Vec::new();
        push_lp32(&mut output, ACTIVATION_PACKAGE_SET_ENCODING_DOMAIN_V1);
        push_lp32(&mut output, &self.deriver_a_client.encode());
        push_lp32(&mut output, &self.deriver_b_client.encode());
        push_lp32(&mut output, &self.deriver_a_signing_worker.encode());
        push_lp32(&mut output, &self.deriver_b_signing_worker.encode());
        output
    }

    /// Computes the domain-separated SHA-256 package-set digest.
    pub fn digest(&self) -> ActivationPackageSetDigest32V1 {
        ActivationPackageSetDigest32V1(digest_encoding(
            ACTIVATION_PACKAGE_SET_DIGEST_DOMAIN_V1,
            &self.encode(),
        ))
    }

    fn activation_binding(&self) -> Result<ActivationArtifactBindingV1, SemanticArtifactErrorV1> {
        ActivationArtifactBindingV1::from_package_set(self)
    }
}

/// Fixed A-client and B-client export package set.
///
/// ```compile_fail
/// use ed25519_yao_generator::HostOnlyExportReferenceSuccessV1;
/// use ed25519_yao_generator::semantic_artifacts::{
///     ExportPackageSetV1, ExportSemanticArtifactContextV1,
///     OpaqueHostReferenceExportPackageBindingsV1,
/// };
///
/// fn reject_precomputed_success(
///     context: ExportSemanticArtifactContextV1,
///     success: HostOnlyExportReferenceSuccessV1,
///     bindings: OpaqueHostReferenceExportPackageBindingsV1,
/// ) {
///     let _ = ExportPackageSetV1::from_host_reference_success(context, success, bindings);
/// }
/// ```
#[derive(Debug, PartialEq, Eq)]
pub struct ExportPackageSetV1 {
    context: ExportSemanticArtifactContextCoreV1,
    deriver_a_client: DeriverAClientSeedExportPackageDescriptorV1,
    deriver_b_client: DeriverBClientSeedExportPackageDescriptorV1,
}

impl ExportPackageSetV1 {
    fn from_ceremony_bound_host_reference(bound: CeremonyBoundExportHostReferenceV1<'_>) -> Self {
        let CeremonyBoundExportHostReferenceV1 {
            context,
            shares,
            bindings,
        } = bound;
        Self {
            context,
            deriver_a_client:
                ClientSeedExportPackageDescriptorV1::from_deriver_a_host_reference_share(
                    context,
                    shares.deriver_a(),
                    bindings.deriver_a_client,
                ),
            deriver_b_client:
                ClientSeedExportPackageDescriptorV1::from_deriver_b_host_reference_share(
                    context,
                    shares.deriver_b(),
                    bindings.deriver_b_client,
                ),
        }
    }

    /// Returns Deriver A's client seed descriptor.
    pub const fn deriver_a_client(&self) -> &DeriverAClientSeedExportPackageDescriptorV1 {
        &self.deriver_a_client
    }

    /// Returns Deriver B's client seed descriptor.
    pub const fn deriver_b_client(&self) -> &DeriverBClientSeedExportPackageDescriptorV1 {
        &self.deriver_b_client
    }

    /// Encodes the fixed descriptors in Deriver A then Deriver B order.
    pub fn encode(&self) -> Vec<u8> {
        let mut output = Vec::new();
        push_lp32(&mut output, EXPORT_PACKAGE_SET_ENCODING_DOMAIN_V1);
        push_lp32(&mut output, &self.deriver_a_client.encode());
        push_lp32(&mut output, &self.deriver_b_client.encode());
        output
    }

    /// Computes the domain-separated SHA-256 package-set digest.
    pub fn digest(&self) -> ExportPackageSetDigest32V1 {
        ExportPackageSetDigest32V1(digest_encoding(
            EXPORT_PACKAGE_SET_DIGEST_DOMAIN_V1,
            &self.encode(),
        ))
    }
}

struct ValidatedActivationPublicOutputV1 {
    x_client: [u8; 32],
    x_server: [u8; 32],
    registered_public_key: RegisteredEd25519PublicKey32V1,
}

fn validate_activation_public_output(
    x_client: EdwardsPoint,
    x_server: EdwardsPoint,
    registered_identity: ActivationRegisteredIdentityV1,
) -> Result<ValidatedActivationPublicOutputV1, SemanticArtifactErrorV1> {
    if x_client.is_identity() {
        return Err(SemanticArtifactErrorV1::JoinedClientPointIdentity);
    }
    if x_server.is_identity() {
        return Err(SemanticArtifactErrorV1::JoinedSigningWorkerPointIdentity);
    }
    let derived_public_key = RegisteredEd25519PublicKey32V1::parse(
        (x_client + x_client - x_server).compress().to_bytes(),
    )
    .map_err(SemanticArtifactErrorV1::DerivedRegisteredPublicKey)?;
    if let ActivationRegisteredIdentityV1::Preserve(expected) = registered_identity {
        if expected != derived_public_key {
            return Err(SemanticArtifactErrorV1::Ed25519OutputRelationMismatch);
        }
    }
    Ok(ValidatedActivationPublicOutputV1 {
        x_client: x_client.compress().to_bytes(),
        x_server: x_server.compress().to_bytes(),
        registered_public_key: derived_public_key,
    })
}

macro_rules! define_computed_digest {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name([u8; 32]);

        impl $name {
            /// Returns the internally computed SHA-256 digest bytes.
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "([computed SHA-256])"))
            }
        }
    };
}

define_computed_digest!(/// SHA-256 identity of the fixed activation package set.
    ActivationPackageSetDigest32V1);
define_computed_digest!(/// SHA-256 identity of the fixed export package set.
    ExportPackageSetDigest32V1);
#[cfg(test)]
impl ExportPackageSetDigest32V1 {
    pub(crate) const fn from_fixture_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}
define_computed_digest!(/// SHA-256 identity of an activation output-committed receipt body.
    ActivationOutputCommittedReceiptDigest32V1);
define_computed_digest!(/// SHA-256 identity of an export output-committed receipt body.
    ExportOutputCommittedReceiptDigest32V1);
define_computed_digest!(/// SHA-256 identity of an export released receipt body.
    ExportReleasedReceiptDigest32V1);

/// Canonical activation-continuation binding derived from one semantic package set.
///
/// The private fields prevent callers from pairing an origin ceremony with an
/// independently supplied package digest, epoch, execution identifier, or key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActivationArtifactBindingV1 {
    origin: ActivationPackageOriginV1,
    origin_request_kind: CeremonyRequestKindV1,
    origin_request_context_digest: CeremonyPublicRequestContextDigest32V1,
    origin_authorization_digest: CeremonyAuthorizationDigest32V1,
    origin_transcript_digest: CeremonyTranscriptDigest32V1,
    one_use_execution_id: OneUseExecutionId32V1,
    package_set_digest: CeremonyPackageSetDigest32V1,
    activation_epoch: CeremonyActivationEpochV1,
    registered_public_key: RegisteredEd25519PublicKey32V1,
}

impl ActivationArtifactBindingV1 {
    fn from_package_set(
        packages: &ActivationPackageSetV1,
    ) -> Result<Self, SemanticArtifactErrorV1> {
        let context = packages.context;
        let package_set_digest = CeremonyPackageSetDigest32V1::new(*packages.digest().as_bytes())?;
        Ok(Self {
            origin: context.origin,
            origin_request_kind: context.ceremony.request_kind,
            origin_request_context_digest: context.ceremony.request_context_digest,
            origin_authorization_digest: context.ceremony.authorization_digest,
            origin_transcript_digest: context.ceremony.transcript_digest,
            one_use_execution_id: context.ceremony.one_use_execution_id,
            package_set_digest,
            activation_epoch: context.activation_epoch,
            registered_public_key: packages.registered_public_key,
        })
    }

    /// Returns the evaluation branch that created the package set.
    pub const fn origin(&self) -> ActivationPackageOriginV1 {
        self.origin
    }

    /// Returns the canonical request kind committed by the origin ceremony.
    pub const fn origin_request_kind(&self) -> CeremonyRequestKindV1 {
        self.origin_request_kind
    }

    /// Returns the exact origin request-context digest.
    pub const fn origin_request_context_digest(&self) -> CeremonyPublicRequestContextDigest32V1 {
        self.origin_request_context_digest
    }

    /// Returns the exact origin authorization digest.
    pub const fn origin_authorization_digest(&self) -> CeremonyAuthorizationDigest32V1 {
        self.origin_authorization_digest
    }

    /// Returns the exact origin transcript digest.
    pub const fn origin_transcript_digest(&self) -> CeremonyTranscriptDigest32V1 {
        self.origin_transcript_digest
    }

    /// Returns the one-use execution identifier already committed by every package.
    pub const fn one_use_execution_id(&self) -> OneUseExecutionId32V1 {
        self.one_use_execution_id
    }

    /// Returns the nonzero canonical package-set digest used by activation control.
    pub const fn package_set_digest(&self) -> CeremonyPackageSetDigest32V1 {
        self.package_set_digest
    }

    /// Returns the activation epoch committed by every package descriptor.
    pub const fn activation_epoch(&self) -> CeremonyActivationEpochV1 {
        self.activation_epoch
    }

    /// Returns the registered key established or preserved by the evaluation.
    pub const fn registered_public_key(&self) -> RegisteredEd25519PublicKey32V1 {
        self.registered_public_key
    }

    /// Checks that a sealed origin DAG is the exact ceremony bound by the artifacts.
    pub fn matches_origin_dag(&self, origin: CeremonyValidatedDagV1) -> bool {
        self.origin_request_kind == origin.request_kind()
            && self.origin_request_context_digest == origin.request_context_digest()
            && self.origin_authorization_digest == origin.authorization_digest()
            && self.origin_transcript_digest == origin.transcript_digest()
    }
}

/// Move-owned activation package set and its exact output-committed receipt.
///
/// Construction derives both the continuation binding and receipt from the
/// supplied package set before taking ownership. No independent receipt or
/// package digest can be injected.
///
/// ```compile_fail
/// use ed25519_yao_generator::semantic_artifacts::ActivationPackageSetV1;
///
/// fn bypass_binding(packages: &ActivationPackageSetV1) {
///     let _ = packages.activation_binding();
/// }
/// ```
#[derive(Debug, PartialEq, Eq)]
pub struct CommittedActivationArtifactsV1 {
    binding: ActivationArtifactBindingV1,
    packages: ActivationPackageSetV1,
    receipt: ActivationOutputCommittedReceiptBodyV1,
}

impl CommittedActivationArtifactsV1 {
    /// Commits one move-only host-reference package set with separate A/B evidence.
    pub(crate) fn new(
        packages: ActivationPackageSetV1,
        deriver_a_receipt_evidence_digest: OpaqueHostReferenceDeriverAReceiptEvidenceDigest32V1,
        deriver_b_receipt_evidence_digest: OpaqueHostReferenceDeriverBReceiptEvidenceDigest32V1,
    ) -> Result<Self, SemanticArtifactErrorV1> {
        let binding = packages.activation_binding()?;
        let receipt = ActivationOutputCommittedReceiptBodyV1::new(
            &packages,
            deriver_a_receipt_evidence_digest,
            deriver_b_receipt_evidence_digest,
        );
        Ok(Self {
            binding,
            packages,
            receipt,
        })
    }

    /// Returns the sealed activation-continuation binding.
    pub const fn binding(&self) -> ActivationArtifactBindingV1 {
        self.binding
    }

    /// Returns the exact semantic package set retained for delivery or redelivery.
    pub const fn packages(&self) -> &ActivationPackageSetV1 {
        &self.packages
    }

    /// Returns the receipt derived from this exact package set.
    pub const fn receipt(&self) -> &ActivationOutputCommittedReceiptBodyV1 {
        &self.receipt
    }
}

/// Public activation receipt body at the semantic output-committed boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActivationOutputCommittedReceiptBodyV1 {
    context: ActivationSemanticArtifactContextCoreV1,
    package_set_digest: ActivationPackageSetDigest32V1,
    x_client: [u8; 32],
    x_server: [u8; 32],
    registered_public_key: RegisteredEd25519PublicKey32V1,
    deriver_a_receipt_evidence_digest: OpaqueHostReferenceDeriverAReceiptEvidenceDigest32V1,
    deriver_b_receipt_evidence_digest: OpaqueHostReferenceDeriverBReceiptEvidenceDigest32V1,
}

impl ActivationOutputCommittedReceiptBodyV1 {
    /// Freezes an output-committed body from an already validated package set.
    fn new(
        packages: &ActivationPackageSetV1,
        deriver_a_receipt_evidence_digest: OpaqueHostReferenceDeriverAReceiptEvidenceDigest32V1,
        deriver_b_receipt_evidence_digest: OpaqueHostReferenceDeriverBReceiptEvidenceDigest32V1,
    ) -> Self {
        Self {
            context: packages.context,
            package_set_digest: packages.digest(),
            x_client: packages.x_client,
            x_server: packages.x_server,
            registered_public_key: packages.registered_public_key,
            deriver_a_receipt_evidence_digest,
            deriver_b_receipt_evidence_digest,
        }
    }

    /// Returns the validated joined client point.
    pub const fn x_client(&self) -> &[u8; 32] {
        &self.x_client
    }

    /// Returns the validated joined server/SigningWorker point.
    pub const fn x_server(&self) -> &[u8; 32] {
        &self.x_server
    }

    /// Returns the complete fixed package-set digest.
    pub const fn package_set_digest(&self) -> ActivationPackageSetDigest32V1 {
        self.package_set_digest
    }

    /// Returns the established or preserved registered public key.
    pub const fn registered_public_key(&self) -> RegisteredEd25519PublicKey32V1 {
        self.registered_public_key
    }

    /// Returns the evaluator-admission evidence bound by every package.
    pub const fn evaluation_evidence_digest(
        &self,
    ) -> OpaqueHostReferenceEvaluationEvidenceDigest32V1 {
        self.context.ceremony.evaluation_evidence_digest
    }

    /// Encodes the exact ordered LP32 public receipt body.
    pub fn encode(&self) -> Vec<u8> {
        let mut output = Vec::new();
        push_lp32(
            &mut output,
            ACTIVATION_OUTPUT_COMMITTED_RECEIPT_ENCODING_DOMAIN_V1,
        );
        push_lp32(&mut output, &[OUTPUT_COMMITTED_RECEIPT_TAG_V1]);
        push_lp32(&mut output, &[OUTPUT_COMMITTED_TERMINAL_STATUS_TAG_V1]);
        push_lp32(&mut output, &[self.context.ceremony.request_kind.tag()]);
        encode_ceremony_binding(&mut output, &self.context.ceremony);
        push_lp32(
            &mut output,
            &self.context.activation_epoch.value().to_be_bytes(),
        );
        push_lp32(&mut output, self.package_set_digest.as_bytes());
        push_lp32(&mut output, &self.x_client);
        push_lp32(&mut output, &self.x_server);
        push_lp32(&mut output, self.registered_public_key.as_bytes());
        push_lp32(
            &mut output,
            self.deriver_a_receipt_evidence_digest.as_bytes(),
        );
        push_lp32(
            &mut output,
            self.deriver_b_receipt_evidence_digest.as_bytes(),
        );
        output
    }

    /// Computes the domain-separated SHA-256 receipt-body digest.
    pub fn digest(&self) -> ActivationOutputCommittedReceiptDigest32V1 {
        ActivationOutputCommittedReceiptDigest32V1(digest_encoding(
            ACTIVATION_OUTPUT_COMMITTED_RECEIPT_DIGEST_DOMAIN_V1,
            &self.encode(),
        ))
    }
}

/// Public export output-committed receipt body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExportOutputCommittedReceiptBodyV1 {
    context: ExportSemanticArtifactContextCoreV1,
    package_set_digest: ExportPackageSetDigest32V1,
    registered_public_key: RegisteredEd25519PublicKey32V1,
    deriver_a_receipt_evidence_digest: OpaqueHostReferenceDeriverAReceiptEvidenceDigest32V1,
    deriver_b_receipt_evidence_digest: OpaqueHostReferenceDeriverBReceiptEvidenceDigest32V1,
}

impl ExportOutputCommittedReceiptBodyV1 {
    fn new(
        packages: &ExportPackageSetV1,
        deriver_a_receipt_evidence_digest: OpaqueHostReferenceDeriverAReceiptEvidenceDigest32V1,
        deriver_b_receipt_evidence_digest: OpaqueHostReferenceDeriverBReceiptEvidenceDigest32V1,
    ) -> Self {
        Self {
            context: packages.context,
            package_set_digest: packages.digest(),
            registered_public_key: packages.context.registered_public_key,
            deriver_a_receipt_evidence_digest,
            deriver_b_receipt_evidence_digest,
        }
    }

    /// Returns the complete fixed package-set digest.
    pub const fn package_set_digest(&self) -> ExportPackageSetDigest32V1 {
        self.package_set_digest
    }

    /// Returns the authorization- and provenance-bound registered public key.
    pub const fn registered_public_key(&self) -> RegisteredEd25519PublicKey32V1 {
        self.registered_public_key
    }

    /// Returns the verified A/B evaluation-evidence binding.
    pub const fn evaluation_evidence_digest(
        &self,
    ) -> OpaqueHostReferenceEvaluationEvidenceDigest32V1 {
        self.context.ceremony.evaluation_evidence_digest
    }

    /// Returns Deriver A's opaque output-commitment evidence slot.
    pub const fn deriver_a_receipt_evidence_digest(
        &self,
    ) -> OpaqueHostReferenceDeriverAReceiptEvidenceDigest32V1 {
        self.deriver_a_receipt_evidence_digest
    }

    /// Returns Deriver B's opaque output-commitment evidence slot.
    pub const fn deriver_b_receipt_evidence_digest(
        &self,
    ) -> OpaqueHostReferenceDeriverBReceiptEvidenceDigest32V1 {
        self.deriver_b_receipt_evidence_digest
    }

    /// Encodes the exact ordered LP32 output-committed receipt body.
    pub fn encode(&self) -> Vec<u8> {
        let mut output = Vec::new();
        push_lp32(
            &mut output,
            EXPORT_OUTPUT_COMMITTED_RECEIPT_ENCODING_DOMAIN_V1,
        );
        push_lp32(&mut output, &[OUTPUT_COMMITTED_RECEIPT_TAG_V1]);
        push_lp32(&mut output, &[OUTPUT_COMMITTED_TERMINAL_STATUS_TAG_V1]);
        push_lp32(&mut output, &[CeremonyRequestKindV1::Export.tag()]);
        encode_ceremony_binding(&mut output, &self.context.ceremony);
        push_lp32(&mut output, self.package_set_digest.as_bytes());
        push_lp32(&mut output, self.registered_public_key.as_bytes());
        push_lp32(
            &mut output,
            self.deriver_a_receipt_evidence_digest.as_bytes(),
        );
        push_lp32(
            &mut output,
            self.deriver_b_receipt_evidence_digest.as_bytes(),
        );
        output
    }

    /// Computes the domain-separated SHA-256 receipt-body digest.
    pub fn digest(&self) -> ExportOutputCommittedReceiptDigest32V1 {
        ExportOutputCommittedReceiptDigest32V1(digest_encoding(
            EXPORT_OUTPUT_COMMITTED_RECEIPT_DIGEST_DOMAIN_V1,
            &self.encode(),
        ))
    }
}

/// Move-owned export package set committed before client release.
#[derive(Debug, PartialEq, Eq)]
pub struct OutputCommittedExportArtifactsV1 {
    packages: ExportPackageSetV1,
    receipt: ExportOutputCommittedReceiptBodyV1,
}

impl OutputCommittedExportArtifactsV1 {
    /// Commits one export package set without consuming release authorization.
    pub(crate) fn new(
        packages: ExportPackageSetV1,
        deriver_a_receipt_evidence_digest: OpaqueHostReferenceDeriverAReceiptEvidenceDigest32V1,
        deriver_b_receipt_evidence_digest: OpaqueHostReferenceDeriverBReceiptEvidenceDigest32V1,
    ) -> Self {
        let receipt = ExportOutputCommittedReceiptBodyV1::new(
            &packages,
            deriver_a_receipt_evidence_digest,
            deriver_b_receipt_evidence_digest,
        );
        Self { packages, receipt }
    }

    /// Returns the exact move-owned export package set.
    pub const fn packages(&self) -> &ExportPackageSetV1 {
        &self.packages
    }

    /// Returns the host-reference receipt derived from this exact set.
    pub const fn receipt(&self) -> &ExportOutputCommittedReceiptBodyV1 {
        &self.receipt
    }

    pub(crate) fn into_released(
        self,
        client_delivery_evidence_digest: OpaqueHostReferenceClientDeliveryEvidenceDigest32V1,
        consumed_authorization_digest: OpaqueHostReferenceConsumedExportAuthorizationDigest32V1,
    ) -> ReleasedExportArtifactsV1 {
        let receipt = ExportReleasedReceiptBodyV1::new(
            &self,
            client_delivery_evidence_digest,
            consumed_authorization_digest,
        );
        ReleasedExportArtifactsV1 {
            packages: self.packages,
            output_committed_receipt: self.receipt,
            receipt,
        }
    }
}

/// Public receipt proving the output-committed export advanced through client release.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExportReleasedReceiptBodyV1 {
    context: ExportSemanticArtifactContextCoreV1,
    package_set_digest: ExportPackageSetDigest32V1,
    registered_public_key: RegisteredEd25519PublicKey32V1,
    output_committed_receipt_digest: ExportOutputCommittedReceiptDigest32V1,
    client_delivery_evidence_digest: OpaqueHostReferenceClientDeliveryEvidenceDigest32V1,
    consumed_authorization_digest: OpaqueHostReferenceConsumedExportAuthorizationDigest32V1,
}

impl ExportReleasedReceiptBodyV1 {
    fn new(
        committed: &OutputCommittedExportArtifactsV1,
        client_delivery_evidence_digest: OpaqueHostReferenceClientDeliveryEvidenceDigest32V1,
        consumed_authorization_digest: OpaqueHostReferenceConsumedExportAuthorizationDigest32V1,
    ) -> Self {
        Self {
            context: committed.packages.context,
            package_set_digest: committed.packages.digest(),
            registered_public_key: committed.packages.context.registered_public_key,
            output_committed_receipt_digest: committed.receipt.digest(),
            client_delivery_evidence_digest,
            consumed_authorization_digest,
        }
    }

    /// Returns the exact released package-set digest.
    pub const fn package_set_digest(&self) -> ExportPackageSetDigest32V1 {
        self.package_set_digest
    }

    /// Returns the authorization- and provenance-bound registered key.
    pub const fn registered_public_key(&self) -> RegisteredEd25519PublicKey32V1 {
        self.registered_public_key
    }

    /// Returns the exact A/B evaluation-evidence binding retained from commitment.
    pub const fn evaluation_evidence_digest(
        &self,
    ) -> OpaqueHostReferenceEvaluationEvidenceDigest32V1 {
        self.context.ceremony.evaluation_evidence_digest
    }

    /// Returns the exact preceding output-committed receipt digest.
    pub const fn output_committed_receipt_digest(&self) -> ExportOutputCommittedReceiptDigest32V1 {
        self.output_committed_receipt_digest
    }

    /// Returns the opaque Client delivery evidence slot.
    pub const fn client_delivery_evidence_digest(
        &self,
    ) -> OpaqueHostReferenceClientDeliveryEvidenceDigest32V1 {
        self.client_delivery_evidence_digest
    }

    /// Returns the opaque consumed-authorization evidence slot.
    pub const fn consumed_authorization_digest(
        &self,
    ) -> OpaqueHostReferenceConsumedExportAuthorizationDigest32V1 {
        self.consumed_authorization_digest
    }

    /// Encodes the exact ordered LP32 released receipt body.
    pub fn encode(&self) -> Vec<u8> {
        let mut output = Vec::new();
        push_lp32(&mut output, EXPORT_RELEASED_RECEIPT_ENCODING_DOMAIN_V1);
        push_lp32(&mut output, &[EXPORT_RELEASED_RECEIPT_TAG_V1]);
        push_lp32(&mut output, &[EXPORT_RELEASED_TERMINAL_STATUS_TAG_V1]);
        push_lp32(&mut output, &[CeremonyRequestKindV1::Export.tag()]);
        encode_ceremony_binding(&mut output, &self.context.ceremony);
        push_lp32(&mut output, self.package_set_digest.as_bytes());
        push_lp32(&mut output, self.registered_public_key.as_bytes());
        push_lp32(&mut output, self.output_committed_receipt_digest.as_bytes());
        push_lp32(&mut output, self.client_delivery_evidence_digest.as_bytes());
        push_lp32(&mut output, self.consumed_authorization_digest.as_bytes());
        output
    }

    /// Computes the domain-separated released receipt digest.
    pub fn digest(&self) -> ExportReleasedReceiptDigest32V1 {
        ExportReleasedReceiptDigest32V1(digest_encoding(
            EXPORT_RELEASED_RECEIPT_DIGEST_DOMAIN_V1,
            &self.encode(),
        ))
    }
}

/// Move-owned export artifacts after client release and authorization consumption.
#[derive(Debug, PartialEq, Eq)]
pub struct ReleasedExportArtifactsV1 {
    packages: ExportPackageSetV1,
    output_committed_receipt: ExportOutputCommittedReceiptBodyV1,
    receipt: ExportReleasedReceiptBodyV1,
}

impl ReleasedExportArtifactsV1 {
    /// Returns the exact move-owned package set released to the Client.
    pub const fn packages(&self) -> &ExportPackageSetV1 {
        &self.packages
    }

    /// Returns the preceding output-committed receipt.
    pub const fn output_committed_receipt(&self) -> &ExportOutputCommittedReceiptBodyV1 {
        &self.output_committed_receipt
    }

    /// Returns the terminal released receipt.
    pub const fn receipt(&self) -> &ExportReleasedReceiptBodyV1 {
        &self.receipt
    }
}

fn encode_ceremony_binding(output: &mut Vec<u8>, binding: &SemanticCeremonyBindingV1) {
    push_lp32(output, binding.request_context_digest.as_bytes());
    push_lp32(output, binding.authorization_digest.as_bytes());
    push_lp32(output, binding.transcript_digest.as_bytes());
    push_lp32(output, binding.transport_binding_digest.as_bytes());
    push_lp32(output, binding.artifact_suite_digest.as_bytes());
    push_lp32(output, binding.one_use_execution_id.as_bytes());
    push_lp32(output, binding.input_provenance_digest.as_bytes());
    push_lp32(output, binding.evaluation_evidence_digest.as_bytes());
}

fn encode_package_bindings(
    output: &mut Vec<u8>,
    bindings: &OpaqueHostReferencePackageBindingsCoreV1,
) {
    push_lp32(output, bindings.recipient_protection_digest.as_bytes());
    push_lp32(output, bindings.recipient_ciphertext_digest.as_bytes());
    push_lp32(output, &bindings.ciphertext_length.value().to_be_bytes());
    push_lp32(output, bindings.output_binding_digest.as_bytes());
    push_lp32(output, bindings.package_authentication_digest.as_bytes());
}

fn deriver_a_client_share_bytes(share: &HostOnlyDeriverAClientScalarShareV1) -> [u8; 32] {
    share.expose_fixture_bytes()
}

fn deriver_b_client_share_bytes(share: &HostOnlyDeriverBClientScalarShareV1) -> [u8; 32] {
    share.expose_fixture_bytes()
}

fn deriver_a_signing_worker_share_bytes(
    share: &HostOnlyDeriverASigningWorkerScalarShareV1,
) -> [u8; 32] {
    share.expose_fixture_bytes()
}

fn deriver_b_signing_worker_share_bytes(
    share: &HostOnlyDeriverBSigningWorkerScalarShareV1,
) -> [u8; 32] {
    share.expose_fixture_bytes()
}

fn digest_encoding(domain: &[u8], encoding: &[u8]) -> [u8; 32] {
    let mut input = Vec::new();
    push_lp32(&mut input, domain);
    push_lp32(&mut input, encoding);
    Sha256::digest(input).into()
}

fn push_lp32(output: &mut Vec<u8>, value: &[u8]) {
    let length = u32::try_from(value.len()).expect("fixed semantic artifact value fits LP32");
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_unique_domains(domains: &[&[u8]]) {
        for (index, domain) in domains.iter().enumerate() {
            assert!(!domain.is_empty());
            assert!(domains[index + 1..].iter().all(|other| domain != other));
        }
    }

    #[test]
    fn every_descriptor_set_and_receipt_domain_is_unique() {
        assert_unique_domains(&[
            ACTIVATION_DERIVER_A_CLIENT_DESCRIPTOR_DOMAIN_V1,
            ACTIVATION_DERIVER_B_CLIENT_DESCRIPTOR_DOMAIN_V1,
            ACTIVATION_DERIVER_A_SIGNING_WORKER_DESCRIPTOR_DOMAIN_V1,
            ACTIVATION_DERIVER_B_SIGNING_WORKER_DESCRIPTOR_DOMAIN_V1,
            EXPORT_DERIVER_A_CLIENT_DESCRIPTOR_DOMAIN_V1,
            EXPORT_DERIVER_B_CLIENT_DESCRIPTOR_DOMAIN_V1,
            CLIENT_RECIPIENT_KEY_BINDING_DOMAIN_V1,
            SIGNING_WORKER_RECIPIENT_KEY_BINDING_DOMAIN_V1,
            ACTIVATION_PACKAGE_SET_ENCODING_DOMAIN_V1,
            ACTIVATION_PACKAGE_SET_DIGEST_DOMAIN_V1,
            EXPORT_PACKAGE_SET_ENCODING_DOMAIN_V1,
            EXPORT_PACKAGE_SET_DIGEST_DOMAIN_V1,
            ACTIVATION_OUTPUT_COMMITTED_RECEIPT_ENCODING_DOMAIN_V1,
            ACTIVATION_OUTPUT_COMMITTED_RECEIPT_DIGEST_DOMAIN_V1,
            EXPORT_OUTPUT_COMMITTED_RECEIPT_ENCODING_DOMAIN_V1,
            EXPORT_OUTPUT_COMMITTED_RECEIPT_DIGEST_DOMAIN_V1,
            EXPORT_RELEASED_RECEIPT_ENCODING_DOMAIN_V1,
            EXPORT_RELEASED_RECEIPT_DIGEST_DOMAIN_V1,
        ]);
    }

    #[test]
    fn every_opaque_host_reference_slot_rejects_zero() {
        assert!(matches!(
            OpaqueHostReferenceEvaluationEvidenceDigest32V1::new([0; 32]),
            Err(SemanticArtifactErrorV1::ZeroOpaqueDigest(
                SemanticArtifactOpaqueDigestFieldV1::EvaluationEvidence
            ))
        ));
        assert!(matches!(
            OpaqueHostReferenceRecipientProtectionDigest32V1::new([0; 32]),
            Err(SemanticArtifactErrorV1::ZeroOpaqueDigest(
                SemanticArtifactOpaqueDigestFieldV1::RecipientProtection
            ))
        ));
        assert!(matches!(
            OpaqueHostReferenceOutputBindingDigest32V1::new([0; 32]),
            Err(SemanticArtifactErrorV1::ZeroOpaqueDigest(
                SemanticArtifactOpaqueDigestFieldV1::OutputBinding
            ))
        ));
        assert!(matches!(
            OpaqueHostReferencePackageAuthenticationDigest32V1::new([0; 32]),
            Err(SemanticArtifactErrorV1::ZeroOpaqueDigest(
                SemanticArtifactOpaqueDigestFieldV1::PackageAuthentication
            ))
        ));
        assert!(matches!(
            OpaqueHostReferenceRecipientCiphertextDigest32V1::new([0; 32]),
            Err(SemanticArtifactErrorV1::ZeroOpaqueDigest(
                SemanticArtifactOpaqueDigestFieldV1::RecipientCiphertext
            ))
        ));
        assert!(matches!(
            OpaqueHostReferenceDeriverAReceiptEvidenceDigest32V1::new([0; 32]),
            Err(SemanticArtifactErrorV1::ZeroOpaqueDigest(
                SemanticArtifactOpaqueDigestFieldV1::DeriverAReceiptEvidence
            ))
        ));
        assert!(matches!(
            OpaqueHostReferenceDeriverBReceiptEvidenceDigest32V1::new([0; 32]),
            Err(SemanticArtifactErrorV1::ZeroOpaqueDigest(
                SemanticArtifactOpaqueDigestFieldV1::DeriverBReceiptEvidence
            ))
        ));
        assert!(matches!(
            OpaqueHostReferenceConsumedExportAuthorizationDigest32V1::new([0; 32]),
            Err(SemanticArtifactErrorV1::ZeroOpaqueDigest(
                SemanticArtifactOpaqueDigestFieldV1::ConsumedExportAuthorization
            ))
        ));
        assert!(matches!(
            OpaqueHostReferenceClientDeliveryEvidenceDigest32V1::new([0; 32]),
            Err(SemanticArtifactErrorV1::ZeroOpaqueDigest(
                SemanticArtifactOpaqueDigestFieldV1::ClientDeliveryEvidence
            ))
        ));
        assert!(matches!(
            OpaqueHostReferenceActivationClientDeliveryEvidenceDigest32V1::new([0; 32]),
            Err(SemanticArtifactErrorV1::ZeroOpaqueDigest(
                SemanticArtifactOpaqueDigestFieldV1::ActivationClientDeliveryEvidence
            ))
        ));
        assert!(matches!(
            OpaqueHostReferenceActivationSigningWorkerDeliveryEvidenceDigest32V1::new([0; 32]),
            Err(SemanticArtifactErrorV1::ZeroOpaqueDigest(
                SemanticArtifactOpaqueDigestFieldV1::ActivationSigningWorkerDeliveryEvidence
            ))
        ));
        assert_eq!(
            OneUseExecutionId32V1::new([0; 32]),
            Err(SemanticArtifactErrorV1::ZeroOneUseExecutionId)
        );
        assert_eq!(
            SemanticCiphertextLengthV1::new(0),
            Err(SemanticArtifactErrorV1::ZeroCiphertextLength)
        );
    }

    #[test]
    fn joined_signing_points_and_registration_candidate_must_be_nonidentity() {
        let identity = ED25519_BASEPOINT_POINT * Scalar::ZERO;
        assert_eq!(
            validate_activation_public_output(
                identity,
                ED25519_BASEPOINT_POINT,
                ActivationRegisteredIdentityV1::RegistrationCandidate,
            )
            .map(|_| ()),
            Err(SemanticArtifactErrorV1::JoinedClientPointIdentity)
        );
        assert_eq!(
            validate_activation_public_output(
                ED25519_BASEPOINT_POINT,
                identity,
                ActivationRegisteredIdentityV1::RegistrationCandidate,
            )
            .map(|_| ()),
            Err(SemanticArtifactErrorV1::JoinedSigningWorkerPointIdentity)
        );
        assert_eq!(
            validate_activation_public_output(
                ED25519_BASEPOINT_POINT,
                ED25519_BASEPOINT_POINT + ED25519_BASEPOINT_POINT,
                ActivationRegisteredIdentityV1::RegistrationCandidate,
            )
            .map(|_| ()),
            Err(SemanticArtifactErrorV1::DerivedRegisteredPublicKey(
                RegisteredEd25519PublicKeyErrorV1::Identity
            ))
        );
    }
}
