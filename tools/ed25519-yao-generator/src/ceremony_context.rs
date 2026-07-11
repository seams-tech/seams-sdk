//! Canonical host-only ceremony context and authorization encodings.
//!
//! Every value handled here is public synthetic reference material. The module
//! freezes byte encodings and digest dependencies only. It does not authenticate
//! authorization records, transport bindings, artifact suites, or role inputs.

use core::{fmt, num::NonZeroU64};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{RegisteredEd25519PublicKey32V1, RegisteredEd25519PublicKeyErrorV1};

/// Domain for the canonical public request-context encoding.
pub const PUBLIC_REQUEST_CONTEXT_ENCODING_DOMAIN_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/public-request-context/v1";
/// Domain for registration authorization bytes.
pub const REGISTRATION_AUTHORIZATION_ENCODING_DOMAIN_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/authorization/registration/v1";
/// Domain for activation-control authorization bytes.
pub const ACTIVATION_AUTHORIZATION_ENCODING_DOMAIN_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/authorization/activation/v1";
/// Domain for recovery authorization bytes.
pub const RECOVERY_AUTHORIZATION_ENCODING_DOMAIN_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/authorization/recovery/v1";
/// Domain for refresh authorization bytes.
pub const REFRESH_AUTHORIZATION_ENCODING_DOMAIN_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/authorization/refresh/v1";
/// Domain for export authorization bytes.
pub const EXPORT_AUTHORIZATION_ENCODING_DOMAIN_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/authorization/export/v1";
/// Domain for the canonical ceremony-transcript encoding.
pub const CEREMONY_TRANSCRIPT_ENCODING_DOMAIN_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/ceremony-transcript/v1";

/// Registration request tag.
pub const CEREMONY_REGISTRATION_REQUEST_TAG_V1: u8 = 0x01;
/// Activation-control request tag.
pub const CEREMONY_ACTIVATION_REQUEST_TAG_V1: u8 = 0x02;
/// Recovery request tag.
pub const CEREMONY_RECOVERY_REQUEST_TAG_V1: u8 = 0x03;
/// Refresh request tag.
pub const CEREMONY_REFRESH_REQUEST_TAG_V1: u8 = 0x04;
/// Export request tag.
pub const CEREMONY_EXPORT_REQUEST_TAG_V1: u8 = 0x05;

const PROTOCOL_VERSION_LABEL: &[u8] = b"protocolVersion";
const PROTOCOL_ID_LABEL: &[u8] = b"protocolId";
const REQUEST_KIND_LABEL: &[u8] = b"requestKind";
const CIRCUIT_ID_LABEL: &[u8] = b"circuitId";
const REQUEST_ID_LABEL: &[u8] = b"requestId";
const REPLAY_NONCE_LABEL: &[u8] = b"replayNonce";
const ACCOUNT_ID_LABEL: &[u8] = b"accountId";
const WALLET_ID_LABEL: &[u8] = b"walletId";
const SESSION_ID_LABEL: &[u8] = b"sessionId";
const ORGANIZATION_ID_LABEL: &[u8] = b"organizationId";
const PROJECT_ID_LABEL: &[u8] = b"projectId";
const ENVIRONMENT_ID_LABEL: &[u8] = b"environmentId";
const SIGNING_ROOT_ID_LABEL: &[u8] = b"signingRootId";
const SIGNING_ROOT_VERSION_LABEL: &[u8] = b"signingRootVersion";
const CHAIN_TARGET_LABEL: &[u8] = b"chainTarget";
const ROOT_SHARE_EPOCH_LABEL: &[u8] = b"rootShareEpoch";
const ROUTER_ID_LABEL: &[u8] = b"routerId";
const DERIVER_SET_ID_LABEL: &[u8] = b"deriverSetId";
const DERIVER_A_ID_LABEL: &[u8] = b"deriverAId";
const DERIVER_A_KEY_EPOCH_LABEL: &[u8] = b"deriverAKeyEpoch";
const DERIVER_B_ID_LABEL: &[u8] = b"deriverBId";
const DERIVER_B_KEY_EPOCH_LABEL: &[u8] = b"deriverBKeyEpoch";
const SIGNING_WORKER_ID_LABEL: &[u8] = b"signingWorkerId";
const SIGNING_WORKER_KEY_EPOCH_LABEL: &[u8] = b"signingWorkerKeyEpoch";
const CLIENT_EPHEMERAL_PUBLIC_KEY_LABEL: &[u8] = b"clientEphemeralPublicKey";
const RECIPIENT_PLAN_LABEL: &[u8] = b"recipientPlan";
const OUTPUT_PACKAGE_KIND_LABEL: &[u8] = b"outputPackageKind";
const REQUEST_EXPIRY_LABEL: &[u8] = b"requestExpiry";
const PUBLIC_REQUEST_CONTEXT_DIGEST_LABEL: &[u8] = b"publicRequestContextDigest";
const AUTHORIZATION_RECORD_DIGEST_LABEL: &[u8] = b"authorizationRecordDigest";
const REGISTRATION_INTENT_DIGEST_LABEL: &[u8] = b"registrationIntentDigest";
const ORIGIN_REQUEST_KIND_LABEL: &[u8] = b"originRequestKind";
const ORIGIN_REQUEST_CONTEXT_DIGEST_LABEL: &[u8] = b"originRequestContextDigest";
const ORIGIN_TRANSCRIPT_DIGEST_LABEL: &[u8] = b"originTranscriptDigest";
const PACKAGE_SET_DIGEST_LABEL: &[u8] = b"packageSetDigest";
const ACTIVATION_EPOCH_LABEL: &[u8] = b"activationEpoch";
const REPLACEMENT_CREDENTIAL_BINDING_DIGEST_LABEL: &[u8] = b"replacementCredentialBindingDigest";
const CURRENT_DERIVER_A_INPUT_STATE_EPOCH_LABEL: &[u8] = b"currentDeriverAInputStateEpoch";
const NEXT_DERIVER_A_INPUT_STATE_EPOCH_LABEL: &[u8] = b"nextDeriverAInputStateEpoch";
const CURRENT_DERIVER_B_INPUT_STATE_EPOCH_LABEL: &[u8] = b"currentDeriverBInputStateEpoch";
const NEXT_DERIVER_B_INPUT_STATE_EPOCH_LABEL: &[u8] = b"nextDeriverBInputStateEpoch";
const REGISTERED_ED25519_PUBLIC_KEY_LABEL: &[u8] = b"registeredEd25519PublicKey";
const AUTHORIZATION_DIGEST_LABEL: &[u8] = b"authorizationDigest";
const TRANSCRIPT_NONCE_LABEL: &[u8] = b"transcriptNonce";
const TRANSPORT_BINDING_DIGEST_LABEL: &[u8] = b"transportBindingDigest";
const ARTIFACT_SUITE_DIGEST_LABEL: &[u8] = b"artifactSuiteDigest";

/// Canonical immutable store-identity scope domain.
pub const DURABLE_STORE_IDENTITY_SCOPE_ENCODING_DOMAIN_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/store-identity-scope/v1";

const ACTIVATION_FAMILY_RECIPIENT_PLAN_TAG_V1: u8 = 0x01;
const ACTIVATION_CONTINUATION_RECIPIENT_PLAN_TAG_V1: u8 = 0x02;
const EXPORT_RECIPIENT_PLAN_TAG_V1: u8 = 0x03;
const ACTIVATION_OUTPUT_PACKAGE_KIND_TAG_V1: u8 = 0x01;
const EXPORT_OUTPUT_PACKAGE_KIND_TAG_V1: u8 = 0x02;

/// Textual identifier rejected at the canonical ceremony boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CeremonyIdentifierFieldV1 {
    /// Request identifier.
    RequestId,
    /// Account identifier.
    AccountId,
    /// Wallet identifier.
    WalletId,
    /// Session identifier.
    SessionId,
    /// Organization identifier.
    OrganizationId,
    /// Project identifier.
    ProjectId,
    /// Environment identifier.
    EnvironmentId,
    /// Signing-root identifier.
    SigningRootId,
    /// Chain or network target.
    ChainTarget,
    /// Router identifier.
    RouterId,
    /// Deriver-set identifier.
    DeriverSetId,
    /// Deriver A identifier.
    DeriverAId,
    /// Deriver B identifier.
    DeriverBId,
    /// SigningWorker identifier.
    SigningWorkerId,
}

impl fmt::Display for CeremonyIdentifierFieldV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::RequestId => "requestId",
            Self::AccountId => "accountId",
            Self::WalletId => "walletId",
            Self::SessionId => "sessionId",
            Self::OrganizationId => "organizationId",
            Self::ProjectId => "projectId",
            Self::EnvironmentId => "environmentId",
            Self::SigningRootId => "signingRootId",
            Self::ChainTarget => "chainTarget",
            Self::RouterId => "routerId",
            Self::DeriverSetId => "deriverSetId",
            Self::DeriverAId => "deriverAId",
            Self::DeriverBId => "deriverBId",
            Self::SigningWorkerId => "signingWorkerId",
        })
    }
}

/// Nonzero numeric field rejected at the canonical ceremony boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CeremonyNumericFieldV1 {
    /// Signing-root version.
    SigningRootVersion,
    /// Root-share epoch.
    RootShareEpoch,
    /// Deriver A key epoch.
    DeriverAKeyEpoch,
    /// Deriver B key epoch.
    DeriverBKeyEpoch,
    /// SigningWorker key epoch.
    SigningWorkerKeyEpoch,
    /// Request expiry in Unix milliseconds.
    RequestExpiry,
    /// Activation epoch.
    ActivationEpoch,
    /// Current Deriver A input-state epoch.
    CurrentDeriverAInputStateEpoch,
    /// Next Deriver A input-state epoch.
    NextDeriverAInputStateEpoch,
    /// Current Deriver B input-state epoch.
    CurrentDeriverBInputStateEpoch,
    /// Next Deriver B input-state epoch.
    NextDeriverBInputStateEpoch,
}

/// Opaque digest field rejected at the canonical ceremony boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CeremonyOpaqueDigestFieldV1 {
    /// Authorization record digest.
    AuthorizationRecord,
    /// Registration-intent digest.
    RegistrationIntent,
    /// Activation package-set digest.
    PackageSet,
    /// Replacement-credential binding digest.
    ReplacementCredentialBinding,
    /// Transport-binding digest.
    TransportBinding,
    /// Artifact-suite digest.
    ArtifactSuite,
}

/// Failure while constructing or validating canonical ceremony bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CeremonyContextErrorV1 {
    /// A required textual identifier was empty.
    EmptyIdentifier(CeremonyIdentifierFieldV1),
    /// A textual identifier contained a byte outside visible ASCII.
    InvalidIdentifierGrammar(CeremonyIdentifierFieldV1),
    /// A textual identifier exceeded the LP32 length range.
    IdentifierTooLong(CeremonyIdentifierFieldV1),
    /// A required numeric field was zero.
    ZeroNumeric(CeremonyNumericFieldV1),
    /// A required opaque digest was all zero.
    ZeroOpaqueDigest(CeremonyOpaqueDigestFieldV1),
    /// A refresh input-state epoch did not strictly advance.
    RefreshEpochDidNotStrictlyAdvance(CeremonyNumericFieldV1),
    /// A registered Ed25519 public key failed canonical point validation.
    RegisteredPublicKey(RegisteredEd25519PublicKeyErrorV1),
    /// An activation origin was not an evaluation-producing ceremony.
    InvalidActivationOriginRequestKind,
    /// An activation control request reused its origin request context.
    ActivationOriginContextReused,
    /// Authorization and request-context branches differed.
    AuthorizationRequestKindMismatch,
    /// Authorization was bound to another public request context.
    AuthorizationContextDigestMismatch,
    /// A transcript was bound to another public request context.
    TranscriptContextDigestMismatch,
    /// A transcript was bound to another authorization.
    TranscriptAuthorizationDigestMismatch,
    /// One LP32 value exceeded the version-one U32 range.
    ValueTooLong,
    /// Canonical bytes were malformed, reordered, truncated, or extended.
    MalformedEncoding,
}

impl fmt::Display for CeremonyContextErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyIdentifier(field) => write!(formatter, "{field} must be nonempty"),
            Self::InvalidIdentifierGrammar(field) => write!(
                formatter,
                "{field} must contain only visible ASCII bytes 0x21 through 0x7e"
            ),
            Self::IdentifierTooLong(field) => {
                write!(formatter, "{field} exceeds the LP32 length range")
            }
            Self::ZeroNumeric(field) => write!(formatter, "{field:?} must be nonzero"),
            Self::ZeroOpaqueDigest(field) => {
                write!(formatter, "{field:?} digest must be nonzero")
            }
            Self::RefreshEpochDidNotStrictlyAdvance(field) => {
                write!(formatter, "{field:?} must strictly advance")
            }
            Self::RegisteredPublicKey(error) => error.fmt(formatter),
            Self::InvalidActivationOriginRequestKind => formatter.write_str(
                "activation origin must be a registration, recovery, or refresh ceremony",
            ),
            Self::ActivationOriginContextReused => formatter.write_str(
                "activation control request must be distinct from its origin request context",
            ),
            Self::AuthorizationRequestKindMismatch => {
                formatter.write_str("authorization request kind does not match its context")
            }
            Self::AuthorizationContextDigestMismatch => {
                formatter.write_str("authorization is bound to another request context")
            }
            Self::TranscriptContextDigestMismatch => {
                formatter.write_str("transcript is bound to another request context")
            }
            Self::TranscriptAuthorizationDigestMismatch => {
                formatter.write_str("transcript is bound to another authorization")
            }
            Self::ValueTooLong => formatter.write_str("ceremony LP32 value exceeds U32 length"),
            Self::MalformedEncoding => formatter.write_str("ceremony encoding is noncanonical"),
        }
    }
}

impl std::error::Error for CeremonyContextErrorV1 {}

fn validate_identifier(
    value: &str,
    field: CeremonyIdentifierFieldV1,
) -> Result<(), CeremonyContextErrorV1> {
    if value.is_empty() {
        return Err(CeremonyContextErrorV1::EmptyIdentifier(field));
    }
    if u32::try_from(value.len()).is_err() {
        return Err(CeremonyContextErrorV1::IdentifierTooLong(field));
    }
    if !value.bytes().all(|byte| (0x21..=0x7e).contains(&byte)) {
        return Err(CeremonyContextErrorV1::InvalidIdentifierGrammar(field));
    }
    Ok(())
}

macro_rules! define_identifier {
    ($(#[$meta:meta])* $name:ident, $field:expr) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct $name(String);

        impl $name {
            /// Validates and copies one exact visible-ASCII identifier.
            pub fn parse(value: &str) -> Result<Self, CeremonyContextErrorV1> {
                validate_identifier(value, $field)?;
                Ok(Self(value.to_owned()))
            }

            /// Returns the exact validated identifier.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
    };
}

define_identifier!(/// Public request identifier.
    CeremonyRequestIdV1, CeremonyIdentifierFieldV1::RequestId);
define_identifier!(/// Public account identifier.
    CeremonyAccountIdV1, CeremonyIdentifierFieldV1::AccountId);
define_identifier!(/// Public wallet identifier.
    CeremonyWalletIdV1, CeremonyIdentifierFieldV1::WalletId);
define_identifier!(/// Public session identifier.
    CeremonySessionIdV1, CeremonyIdentifierFieldV1::SessionId);
define_identifier!(/// Public organization identifier.
    CeremonyOrganizationIdV1, CeremonyIdentifierFieldV1::OrganizationId);
define_identifier!(/// Public project identifier.
    CeremonyProjectIdV1, CeremonyIdentifierFieldV1::ProjectId);
define_identifier!(/// Public environment identifier.
    CeremonyEnvironmentIdV1, CeremonyIdentifierFieldV1::EnvironmentId);
define_identifier!(/// Public signing-root identifier.
    CeremonySigningRootIdV1, CeremonyIdentifierFieldV1::SigningRootId);
define_identifier!(/// Public chain or network target.
    CeremonyChainTargetV1, CeremonyIdentifierFieldV1::ChainTarget);
define_identifier!(/// Public Router identifier.
    CeremonyRouterIdV1, CeremonyIdentifierFieldV1::RouterId);
define_identifier!(/// Public Deriver-set identifier.
    CeremonyDeriverSetIdV1, CeremonyIdentifierFieldV1::DeriverSetId);
define_identifier!(/// Public Deriver A identifier.
    CeremonyDeriverAIdV1, CeremonyIdentifierFieldV1::DeriverAId);
define_identifier!(/// Public Deriver B identifier.
    CeremonyDeriverBIdV1, CeremonyIdentifierFieldV1::DeriverBId);
define_identifier!(/// Public SigningWorker identifier.
    CeremonySigningWorkerIdV1, CeremonyIdentifierFieldV1::SigningWorkerId);

macro_rules! define_nonzero_numeric {
    ($(#[$meta:meta])* $name:ident, $field:expr) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
        pub struct $name(NonZeroU64);

        impl $name {
            /// Validates one nonzero version, epoch, or expiry value.
            pub const fn new(value: u64) -> Result<Self, CeremonyContextErrorV1> {
                match NonZeroU64::new(value) {
                    Some(value) => Ok(Self(value)),
                    None => Err(CeremonyContextErrorV1::ZeroNumeric($field)),
                }
            }

            /// Returns the numeric value encoded as BE64.
            pub const fn value(self) -> u64 {
                self.0.get()
            }
        }
    };
}

define_nonzero_numeric!(/// Public signing-root version.
    CeremonySigningRootVersionV1, CeremonyNumericFieldV1::SigningRootVersion);
define_nonzero_numeric!(/// Public root-share epoch.
    CeremonyRootShareEpochV1, CeremonyNumericFieldV1::RootShareEpoch);
define_nonzero_numeric!(/// Public Deriver A key epoch.
    CeremonyDeriverAKeyEpochV1, CeremonyNumericFieldV1::DeriverAKeyEpoch);
define_nonzero_numeric!(/// Public Deriver B key epoch.
    CeremonyDeriverBKeyEpochV1, CeremonyNumericFieldV1::DeriverBKeyEpoch);
define_nonzero_numeric!(/// Public SigningWorker key epoch.
    CeremonySigningWorkerKeyEpochV1, CeremonyNumericFieldV1::SigningWorkerKeyEpoch);
define_nonzero_numeric!(/// Public request expiry in Unix milliseconds.
    CeremonyRequestExpiryV1, CeremonyNumericFieldV1::RequestExpiry);
define_nonzero_numeric!(/// Public activation epoch.
    CeremonyActivationEpochV1, CeremonyNumericFieldV1::ActivationEpoch);
define_nonzero_numeric!(/// Current Deriver A input-state epoch.
    CeremonyCurrentDeriverAInputStateEpochV1,
    CeremonyNumericFieldV1::CurrentDeriverAInputStateEpoch);
define_nonzero_numeric!(/// Next Deriver A input-state epoch.
    CeremonyNextDeriverAInputStateEpochV1,
    CeremonyNumericFieldV1::NextDeriverAInputStateEpoch);
define_nonzero_numeric!(/// Current Deriver B input-state epoch.
    CeremonyCurrentDeriverBInputStateEpochV1,
    CeremonyNumericFieldV1::CurrentDeriverBInputStateEpoch);
define_nonzero_numeric!(/// Next Deriver B input-state epoch.
    CeremonyNextDeriverBInputStateEpochV1,
    CeremonyNumericFieldV1::NextDeriverBInputStateEpoch);

macro_rules! define_fixed_bytes {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name([u8; 32]);

        impl $name {
            /// Constructs an exactly 32-byte public value.
            pub const fn new(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            /// Returns the exact bytes.
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }
    };
}

define_fixed_bytes!(/// Public replay nonce.
    CeremonyReplayNonce32V1);
define_fixed_bytes!(/// Independent public transcript nonce.
    CeremonyTranscriptNonce32V1);
define_fixed_bytes!(/// Client ephemeral public key bytes.
    CeremonyClientEphemeralPublicKey32V1);

fn validate_nonzero_digest(
    bytes: [u8; 32],
    field: CeremonyOpaqueDigestFieldV1,
) -> Result<[u8; 32], CeremonyContextErrorV1> {
    if bytes == [0; 32] {
        return Err(CeremonyContextErrorV1::ZeroOpaqueDigest(field));
    }
    Ok(bytes)
}

macro_rules! define_nonzero_digest {
    ($(#[$meta:meta])* $name:ident, $field:expr) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name([u8; 32]);

        impl $name {
            /// Validates one nonzero public binding digest.
            pub fn new(bytes: [u8; 32]) -> Result<Self, CeremonyContextErrorV1> {
                validate_nonzero_digest(bytes, $field).map(Self)
            }

            /// Returns the exact digest bytes.
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }
    };
}

define_nonzero_digest!(/// Opaque admitted authorization-record digest.
    CeremonyAuthorizationRecordDigest32V1,
    CeremonyOpaqueDigestFieldV1::AuthorizationRecord);
define_nonzero_digest!(/// Opaque registration-intent digest.
    CeremonyRegistrationIntentDigest32V1,
    CeremonyOpaqueDigestFieldV1::RegistrationIntent);
define_nonzero_digest!(/// Opaque committed activation package-set digest.
    CeremonyPackageSetDigest32V1, CeremonyOpaqueDigestFieldV1::PackageSet);
define_nonzero_digest!(/// Opaque replacement-credential binding digest.
    CeremonyReplacementCredentialBindingDigest32V1,
    CeremonyOpaqueDigestFieldV1::ReplacementCredentialBinding);
define_nonzero_digest!(/// Opaque public transport-binding digest.
    CeremonyTransportBindingDigest32V1,
    CeremonyOpaqueDigestFieldV1::TransportBinding);
define_nonzero_digest!(/// Opaque public artifact-suite digest.
    CeremonyArtifactSuiteDigest32V1, CeremonyOpaqueDigestFieldV1::ArtifactSuite);

/// Canonical lifecycle request kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CeremonyRequestKindV1 {
    /// New-key registration preparation.
    Registration,
    /// Internal activation continuation.
    Activation,
    /// Same-root recovery.
    Recovery,
    /// Opposite-delta refresh.
    Refresh,
    /// Explicitly authorized seed export.
    Export,
}

impl CeremonyRequestKindV1 {
    /// Returns the frozen one-byte request tag.
    pub const fn tag(self) -> u8 {
        match self {
            Self::Registration => CEREMONY_REGISTRATION_REQUEST_TAG_V1,
            Self::Activation => CEREMONY_ACTIVATION_REQUEST_TAG_V1,
            Self::Recovery => CEREMONY_RECOVERY_REQUEST_TAG_V1,
            Self::Refresh => CEREMONY_REFRESH_REQUEST_TAG_V1,
            Self::Export => CEREMONY_EXPORT_REQUEST_TAG_V1,
        }
    }

    /// Returns the canonical request-kind name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Registration => "registration",
            Self::Activation => "activation",
            Self::Recovery => "recovery",
            Self::Refresh => "refresh",
            Self::Export => "export",
        }
    }

    /// Returns the fixed circuit identifier derived from this request kind.
    pub const fn circuit_id(self) -> &'static str {
        match self {
            Self::Registration | Self::Activation | Self::Recovery | Self::Refresh => {
                ed25519_yao::ACTIVATION_CIRCUIT_ID_STR
            }
            Self::Export => ed25519_yao::EXPORT_CIRCUIT_ID_STR,
        }
    }

    /// Returns whether this branch performs an evaluation represented in provenance.
    pub const fn has_evaluation_provenance(self) -> bool {
        !matches!(self, Self::Activation)
    }

    const fn recipient_plan_tag(self) -> u8 {
        match self {
            Self::Registration | Self::Recovery | Self::Refresh => {
                ACTIVATION_FAMILY_RECIPIENT_PLAN_TAG_V1
            }
            Self::Activation => ACTIVATION_CONTINUATION_RECIPIENT_PLAN_TAG_V1,
            Self::Export => EXPORT_RECIPIENT_PLAN_TAG_V1,
        }
    }

    const fn output_package_kind_tag(self) -> u8 {
        match self {
            Self::Registration | Self::Activation | Self::Recovery | Self::Refresh => {
                ACTIVATION_OUTPUT_PACKAGE_KIND_TAG_V1
            }
            Self::Export => EXPORT_OUTPUT_PACKAGE_KIND_TAG_V1,
        }
    }

    fn from_tag(tag: u8) -> Result<Self, CeremonyContextErrorV1> {
        match tag {
            CEREMONY_REGISTRATION_REQUEST_TAG_V1 => Ok(Self::Registration),
            CEREMONY_ACTIVATION_REQUEST_TAG_V1 => Ok(Self::Activation),
            CEREMONY_RECOVERY_REQUEST_TAG_V1 => Ok(Self::Recovery),
            CEREMONY_REFRESH_REQUEST_TAG_V1 => Ok(Self::Refresh),
            CEREMONY_EXPORT_REQUEST_TAG_V1 => Ok(Self::Export),
            _ => Err(CeremonyContextErrorV1::MalformedEncoding),
        }
    }
}

/// Public wallet and tenancy identity committed by every request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CeremonyIdentityScopeV1 {
    account_id: CeremonyAccountIdV1,
    wallet_id: CeremonyWalletIdV1,
    session_id: CeremonySessionIdV1,
    organization_id: CeremonyOrganizationIdV1,
    project_id: CeremonyProjectIdV1,
    environment_id: CeremonyEnvironmentIdV1,
    signing_root_id: CeremonySigningRootIdV1,
    signing_root_version: CeremonySigningRootVersionV1,
    chain_target: CeremonyChainTargetV1,
}

impl CeremonyIdentityScopeV1 {
    /// Creates the complete required identity scope.
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        account_id: CeremonyAccountIdV1,
        wallet_id: CeremonyWalletIdV1,
        session_id: CeremonySessionIdV1,
        organization_id: CeremonyOrganizationIdV1,
        project_id: CeremonyProjectIdV1,
        environment_id: CeremonyEnvironmentIdV1,
        signing_root_id: CeremonySigningRootIdV1,
        signing_root_version: CeremonySigningRootVersionV1,
        chain_target: CeremonyChainTargetV1,
    ) -> Self {
        Self {
            account_id,
            wallet_id,
            session_id,
            organization_id,
            project_id,
            environment_id,
            signing_root_id,
            signing_root_version,
            chain_target,
        }
    }

    fn durable_store_identity_scope(&self) -> CeremonyDurableStoreIdentityScopeV1 {
        CeremonyDurableStoreIdentityScopeV1 {
            wallet_id: self.wallet_id.clone(),
            organization_id: self.organization_id.clone(),
            project_id: self.project_id.clone(),
            environment_id: self.environment_id.clone(),
            signing_root_id: self.signing_root_id.clone(),
            chain_target: self.chain_target.clone(),
        }
    }
}

/// Immutable domain identity retained across registered-state ceremonies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CeremonyDurableStoreIdentityScopeV1 {
    wallet_id: CeremonyWalletIdV1,
    organization_id: CeremonyOrganizationIdV1,
    project_id: CeremonyProjectIdV1,
    environment_id: CeremonyEnvironmentIdV1,
    signing_root_id: CeremonySigningRootIdV1,
    chain_target: CeremonyChainTargetV1,
}

impl CeremonyDurableStoreIdentityScopeV1 {
    /// Encodes the exact immutable identity fields in canonical order.
    pub fn encode(&self) -> Result<Vec<u8>, CeremonyContextErrorV1> {
        let mut output = Vec::new();
        push_lp32(&mut output, DURABLE_STORE_IDENTITY_SCOPE_ENCODING_DOMAIN_V1)?;
        push_labeled(
            &mut output,
            WALLET_ID_LABEL,
            self.wallet_id.as_str().as_bytes(),
        )?;
        push_labeled(
            &mut output,
            ORGANIZATION_ID_LABEL,
            self.organization_id.as_str().as_bytes(),
        )?;
        push_labeled(
            &mut output,
            PROJECT_ID_LABEL,
            self.project_id.as_str().as_bytes(),
        )?;
        push_labeled(
            &mut output,
            ENVIRONMENT_ID_LABEL,
            self.environment_id.as_str().as_bytes(),
        )?;
        push_labeled(
            &mut output,
            SIGNING_ROOT_ID_LABEL,
            self.signing_root_id.as_str().as_bytes(),
        )?;
        push_labeled(
            &mut output,
            CHAIN_TARGET_LABEL,
            self.chain_target.as_str().as_bytes(),
        )?;
        Ok(output)
    }
}

/// Public Deriver A identity and key epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CeremonyDeriverABindingV1 {
    id: CeremonyDeriverAIdV1,
    key_epoch: CeremonyDeriverAKeyEpochV1,
}

impl CeremonyDeriverABindingV1 {
    /// Creates a Deriver A binding.
    pub const fn new(id: CeremonyDeriverAIdV1, key_epoch: CeremonyDeriverAKeyEpochV1) -> Self {
        Self { id, key_epoch }
    }

    /// Returns the bound Deriver A identity.
    pub const fn id(&self) -> &CeremonyDeriverAIdV1 {
        &self.id
    }

    /// Returns the bound Deriver A key epoch.
    pub const fn key_epoch(&self) -> CeremonyDeriverAKeyEpochV1 {
        self.key_epoch
    }
}

/// Public Deriver B identity and key epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CeremonyDeriverBBindingV1 {
    id: CeremonyDeriverBIdV1,
    key_epoch: CeremonyDeriverBKeyEpochV1,
}

impl CeremonyDeriverBBindingV1 {
    /// Creates a Deriver B binding.
    pub const fn new(id: CeremonyDeriverBIdV1, key_epoch: CeremonyDeriverBKeyEpochV1) -> Self {
        Self { id, key_epoch }
    }

    /// Returns the bound Deriver B identity.
    pub const fn id(&self) -> &CeremonyDeriverBIdV1 {
        &self.id
    }

    /// Returns the bound Deriver B key epoch.
    pub const fn key_epoch(&self) -> CeremonyDeriverBKeyEpochV1 {
        self.key_epoch
    }
}

/// Public SigningWorker identity and key epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CeremonySigningWorkerBindingV1 {
    id: CeremonySigningWorkerIdV1,
    key_epoch: CeremonySigningWorkerKeyEpochV1,
}

impl CeremonySigningWorkerBindingV1 {
    /// Creates a SigningWorker binding.
    pub const fn new(
        id: CeremonySigningWorkerIdV1,
        key_epoch: CeremonySigningWorkerKeyEpochV1,
    ) -> Self {
        Self { id, key_epoch }
    }

    /// Returns the exact SigningWorker identity.
    pub const fn id(&self) -> &CeremonySigningWorkerIdV1 {
        &self.id
    }

    /// Returns the SigningWorker recipient-key epoch.
    pub const fn key_epoch(&self) -> CeremonySigningWorkerKeyEpochV1 {
        self.key_epoch
    }
}

/// Public Router and role-set infrastructure committed by every request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CeremonyInfrastructureV1 {
    router_id: CeremonyRouterIdV1,
    deriver_set_id: CeremonyDeriverSetIdV1,
    deriver_a: CeremonyDeriverABindingV1,
    deriver_b: CeremonyDeriverBBindingV1,
    signing_worker: CeremonySigningWorkerBindingV1,
}

impl CeremonyInfrastructureV1 {
    /// Creates the complete public infrastructure binding.
    pub const fn new(
        router_id: CeremonyRouterIdV1,
        deriver_set_id: CeremonyDeriverSetIdV1,
        deriver_a: CeremonyDeriverABindingV1,
        deriver_b: CeremonyDeriverBBindingV1,
        signing_worker: CeremonySigningWorkerBindingV1,
    ) -> Self {
        Self {
            router_id,
            deriver_set_id,
            deriver_a,
            deriver_b,
            signing_worker,
        }
    }
}

/// SHA-256 digest of the exact public request-context encoding.
///
/// ```compile_fail
/// use ed25519_yao_generator::ceremony_context::CeremonyPublicRequestContextDigest32V1;
///
/// let _ = CeremonyPublicRequestContextDigest32V1([0_u8; 32]);
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct CeremonyPublicRequestContextDigest32V1([u8; 32]);

impl CeremonyPublicRequestContextDigest32V1 {
    /// Returns the digest bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for CeremonyPublicRequestContextDigest32V1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CeremonyPublicRequestContextDigest32V1([computed SHA-256])")
    }
}

/// Canonical public request context known before authorization and transcript hashing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CeremonyPublicRequestContextV1 {
    request_kind: CeremonyRequestKindV1,
    request_id: CeremonyRequestIdV1,
    replay_nonce: CeremonyReplayNonce32V1,
    identity_scope: CeremonyIdentityScopeV1,
    root_share_epoch: CeremonyRootShareEpochV1,
    infrastructure: CeremonyInfrastructureV1,
    client_ephemeral_public_key: CeremonyClientEphemeralPublicKey32V1,
    request_expiry: CeremonyRequestExpiryV1,
}

impl CeremonyPublicRequestContextV1 {
    /// Creates a complete branch-tagged public request context.
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        request_kind: CeremonyRequestKindV1,
        request_id: CeremonyRequestIdV1,
        replay_nonce: CeremonyReplayNonce32V1,
        identity_scope: CeremonyIdentityScopeV1,
        root_share_epoch: CeremonyRootShareEpochV1,
        infrastructure: CeremonyInfrastructureV1,
        client_ephemeral_public_key: CeremonyClientEphemeralPublicKey32V1,
        request_expiry: CeremonyRequestExpiryV1,
    ) -> Self {
        Self {
            request_kind,
            request_id,
            replay_nonce,
            identity_scope,
            root_share_epoch,
            infrastructure,
            client_ephemeral_public_key,
            request_expiry,
        }
    }

    /// Returns the request kind that derives recipient, output, and circuit metadata.
    pub const fn request_kind(&self) -> CeremonyRequestKindV1 {
        self.request_kind
    }

    /// Returns the validated public request identifier.
    pub const fn request_id(&self) -> &CeremonyRequestIdV1 {
        &self.request_id
    }

    /// Returns the public replay nonce.
    pub const fn replay_nonce(&self) -> CeremonyReplayNonce32V1 {
        self.replay_nonce
    }

    /// Returns the public request expiry in Unix milliseconds.
    pub const fn request_expiry(&self) -> CeremonyRequestExpiryV1 {
        self.request_expiry
    }

    /// Returns the immutable identity subset used by authenticated store state.
    pub fn durable_store_identity_scope(&self) -> CeremonyDurableStoreIdentityScopeV1 {
        self.identity_scope.durable_store_identity_scope()
    }

    /// Returns the SigningWorker recipient identity and key epoch fixed by this request.
    pub const fn signing_worker_binding(&self) -> &CeremonySigningWorkerBindingV1 {
        &self.infrastructure.signing_worker
    }

    /// Returns the Deriver A identity and key epoch committed by this request.
    pub const fn deriver_a_binding(&self) -> &CeremonyDeriverABindingV1 {
        &self.infrastructure.deriver_a
    }

    /// Returns the Deriver B identity and key epoch committed by this request.
    pub const fn deriver_b_binding(&self) -> &CeremonyDeriverBBindingV1 {
        &self.infrastructure.deriver_b
    }

    /// Returns the Client recipient key committed by this request.
    pub const fn client_ephemeral_public_key(&self) -> CeremonyClientEphemeralPublicKey32V1 {
        self.client_ephemeral_public_key
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn derive_activation_control_request_for_attempt(
        &self,
        request_id: CeremonyRequestIdV1,
        replay_nonce: CeremonyReplayNonce32V1,
        request_expiry: CeremonyRequestExpiryV1,
    ) -> Self {
        Self {
            request_kind: CeremonyRequestKindV1::Activation,
            request_id,
            replay_nonce,
            identity_scope: self.identity_scope.clone(),
            root_share_epoch: self.root_share_epoch,
            infrastructure: self.infrastructure.clone(),
            client_ephemeral_public_key: self.client_ephemeral_public_key,
            request_expiry,
        }
    }

    /// Encodes the exact ordered LP32 request context.
    pub fn encode(&self) -> Result<Vec<u8>, CeremonyContextErrorV1> {
        let mut output = Vec::new();
        push_lp32(&mut output, PUBLIC_REQUEST_CONTEXT_ENCODING_DOMAIN_V1)?;
        push_labeled(&mut output, PROTOCOL_VERSION_LABEL, &1_u64.to_be_bytes())?;
        push_labeled(&mut output, REQUEST_KIND_LABEL, &[self.request_kind.tag()])?;
        push_labeled(
            &mut output,
            REQUEST_ID_LABEL,
            self.request_id.as_str().as_bytes(),
        )?;
        push_labeled(
            &mut output,
            REPLAY_NONCE_LABEL,
            self.replay_nonce.as_bytes(),
        )?;
        push_labeled(
            &mut output,
            ACCOUNT_ID_LABEL,
            self.identity_scope.account_id.as_str().as_bytes(),
        )?;
        push_labeled(
            &mut output,
            WALLET_ID_LABEL,
            self.identity_scope.wallet_id.as_str().as_bytes(),
        )?;
        push_labeled(
            &mut output,
            SESSION_ID_LABEL,
            self.identity_scope.session_id.as_str().as_bytes(),
        )?;
        push_labeled(
            &mut output,
            ORGANIZATION_ID_LABEL,
            self.identity_scope.organization_id.as_str().as_bytes(),
        )?;
        push_labeled(
            &mut output,
            PROJECT_ID_LABEL,
            self.identity_scope.project_id.as_str().as_bytes(),
        )?;
        push_labeled(
            &mut output,
            ENVIRONMENT_ID_LABEL,
            self.identity_scope.environment_id.as_str().as_bytes(),
        )?;
        push_labeled(
            &mut output,
            SIGNING_ROOT_ID_LABEL,
            self.identity_scope.signing_root_id.as_str().as_bytes(),
        )?;
        push_labeled(
            &mut output,
            SIGNING_ROOT_VERSION_LABEL,
            &self
                .identity_scope
                .signing_root_version
                .value()
                .to_be_bytes(),
        )?;
        push_labeled(
            &mut output,
            CHAIN_TARGET_LABEL,
            self.identity_scope.chain_target.as_str().as_bytes(),
        )?;
        push_labeled(
            &mut output,
            ROOT_SHARE_EPOCH_LABEL,
            &self.root_share_epoch.value().to_be_bytes(),
        )?;
        push_labeled(
            &mut output,
            ROUTER_ID_LABEL,
            self.infrastructure.router_id.as_str().as_bytes(),
        )?;
        push_labeled(
            &mut output,
            DERIVER_SET_ID_LABEL,
            self.infrastructure.deriver_set_id.as_str().as_bytes(),
        )?;
        push_labeled(
            &mut output,
            DERIVER_A_ID_LABEL,
            self.infrastructure.deriver_a.id.as_str().as_bytes(),
        )?;
        push_labeled(
            &mut output,
            DERIVER_A_KEY_EPOCH_LABEL,
            &self
                .infrastructure
                .deriver_a
                .key_epoch
                .value()
                .to_be_bytes(),
        )?;
        push_labeled(
            &mut output,
            DERIVER_B_ID_LABEL,
            self.infrastructure.deriver_b.id.as_str().as_bytes(),
        )?;
        push_labeled(
            &mut output,
            DERIVER_B_KEY_EPOCH_LABEL,
            &self
                .infrastructure
                .deriver_b
                .key_epoch
                .value()
                .to_be_bytes(),
        )?;
        push_labeled(
            &mut output,
            SIGNING_WORKER_ID_LABEL,
            self.infrastructure.signing_worker.id.as_str().as_bytes(),
        )?;
        push_labeled(
            &mut output,
            SIGNING_WORKER_KEY_EPOCH_LABEL,
            &self
                .infrastructure
                .signing_worker
                .key_epoch
                .value()
                .to_be_bytes(),
        )?;
        push_labeled(
            &mut output,
            CLIENT_EPHEMERAL_PUBLIC_KEY_LABEL,
            self.client_ephemeral_public_key.as_bytes(),
        )?;
        push_labeled(
            &mut output,
            RECIPIENT_PLAN_LABEL,
            &[self.request_kind.recipient_plan_tag()],
        )?;
        push_labeled(
            &mut output,
            OUTPUT_PACKAGE_KIND_LABEL,
            &[self.request_kind.output_package_kind_tag()],
        )?;
        push_labeled(
            &mut output,
            REQUEST_EXPIRY_LABEL,
            &self.request_expiry.value().to_be_bytes(),
        )?;
        Ok(output)
    }

    /// Computes SHA-256 over the exact canonical request-context bytes.
    pub fn digest(&self) -> Result<CeremonyPublicRequestContextDigest32V1, CeremonyContextErrorV1> {
        Ok(CeremonyPublicRequestContextDigest32V1(
            Sha256::digest(self.encode()?).into(),
        ))
    }
}

/// Registration authorization bound to an unregistered public request context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CeremonyRegistrationAuthorizationV1 {
    request_context_digest: CeremonyPublicRequestContextDigest32V1,
    authorization_record_digest: CeremonyAuthorizationRecordDigest32V1,
    registration_intent_digest: CeremonyRegistrationIntentDigest32V1,
}

impl CeremonyRegistrationAuthorizationV1 {
    /// Binds registration admission and intent to one request context.
    pub fn new(
        request: &CeremonyPublicRequestContextV1,
        authorization_record_digest: CeremonyAuthorizationRecordDigest32V1,
        registration_intent_digest: CeremonyRegistrationIntentDigest32V1,
    ) -> Result<Self, CeremonyContextErrorV1> {
        require_request_kind(request, CeremonyRequestKindV1::Registration)?;
        Ok(Self {
            request_context_digest: request.digest()?,
            authorization_record_digest,
            registration_intent_digest,
        })
    }

    /// Returns the opaque authorization record bound to this registration.
    pub const fn authorization_record_digest(&self) -> CeremonyAuthorizationRecordDigest32V1 {
        self.authorization_record_digest
    }

    /// Returns the registration intent fixed by the authorization boundary.
    pub const fn registration_intent_digest(&self) -> CeremonyRegistrationIntentDigest32V1 {
        self.registration_intent_digest
    }
}

/// Coherent request, authorization, and transcript digest witness.
///
/// The private fields can only be derived from a complete matching ceremony DAG.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CeremonyValidatedDagV1 {
    request_kind: CeremonyRequestKindV1,
    request_context_digest: CeremonyPublicRequestContextDigest32V1,
    authorization_digest: CeremonyAuthorizationDigest32V1,
    transcript_digest: CeremonyTranscriptDigest32V1,
}

impl CeremonyValidatedDagV1 {
    /// Validates both digest edges and seals the resulting ceremony witness.
    pub fn from_components(
        request: &CeremonyPublicRequestContextV1,
        authorization: &CeremonyAuthorizationV1,
        transcript: &CeremonyTranscriptV1,
    ) -> Result<Self, CeremonyContextErrorV1> {
        if authorization.request_kind() != request.request_kind()
            || transcript.request_kind() != request.request_kind()
        {
            return Err(CeremonyContextErrorV1::AuthorizationRequestKindMismatch);
        }
        let request_context_digest = request.digest()?;
        if authorization.request_context_digest() != request_context_digest {
            return Err(CeremonyContextErrorV1::AuthorizationContextDigestMismatch);
        }
        if transcript.request_context_digest() != request_context_digest {
            return Err(CeremonyContextErrorV1::TranscriptContextDigestMismatch);
        }
        let authorization_digest = authorization.digest()?;
        if transcript.authorization_digest() != authorization_digest {
            return Err(CeremonyContextErrorV1::TranscriptAuthorizationDigestMismatch);
        }
        Ok(Self {
            request_kind: request.request_kind(),
            request_context_digest,
            authorization_digest,
            transcript_digest: transcript.digest()?,
        })
    }

    /// Returns the lifecycle branch sealed into the DAG.
    pub const fn request_kind(self) -> CeremonyRequestKindV1 {
        self.request_kind
    }

    /// Returns the computed request-context digest.
    pub const fn request_context_digest(self) -> CeremonyPublicRequestContextDigest32V1 {
        self.request_context_digest
    }

    /// Returns the computed authorization digest.
    pub const fn authorization_digest(self) -> CeremonyAuthorizationDigest32V1 {
        self.authorization_digest
    }

    /// Returns the computed transcript digest.
    pub const fn transcript_digest(self) -> CeremonyTranscriptDigest32V1 {
        self.transcript_digest
    }

    /// Narrows an evaluation-producing DAG into an activation origin witness.
    pub fn activation_origin(self) -> Result<CeremonyActivationOriginV1, CeremonyContextErrorV1> {
        match self.request_kind {
            CeremonyRequestKindV1::Registration
            | CeremonyRequestKindV1::Recovery
            | CeremonyRequestKindV1::Refresh => Ok(CeremonyActivationOriginV1 {
                request_kind: self.request_kind,
                request_context_digest: self.request_context_digest,
                transcript_digest: self.transcript_digest,
            }),
            CeremonyRequestKindV1::Activation | CeremonyRequestKindV1::Export => {
                Err(CeremonyContextErrorV1::InvalidActivationOriginRequestKind)
            }
        }
    }
}

/// Registration, recovery, or refresh origin accepted by activation control.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CeremonyActivationOriginV1 {
    request_kind: CeremonyRequestKindV1,
    request_context_digest: CeremonyPublicRequestContextDigest32V1,
    transcript_digest: CeremonyTranscriptDigest32V1,
}

/// Activation-control authorization over one committed origin package set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CeremonyActivationAuthorizationV1 {
    request_context_digest: CeremonyPublicRequestContextDigest32V1,
    authorization_record_digest: CeremonyAuthorizationRecordDigest32V1,
    origin_request_kind: CeremonyRequestKindV1,
    origin_request_context_digest: CeremonyPublicRequestContextDigest32V1,
    origin_transcript_digest: CeremonyTranscriptDigest32V1,
    package_set_digest: CeremonyPackageSetDigest32V1,
    activation_epoch: CeremonyActivationEpochV1,
}

impl CeremonyActivationAuthorizationV1 {
    /// Binds activation control to one origin transcript and package set.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        request: &CeremonyPublicRequestContextV1,
        authorization_record_digest: CeremonyAuthorizationRecordDigest32V1,
        origin: CeremonyActivationOriginV1,
        package_set_digest: CeremonyPackageSetDigest32V1,
        activation_epoch: CeremonyActivationEpochV1,
    ) -> Result<Self, CeremonyContextErrorV1> {
        let authorization = Self::new_for_lifecycle_attempt(
            request,
            authorization_record_digest,
            origin,
            package_set_digest,
            activation_epoch,
        )?;
        if request.digest()? == origin.request_context_digest {
            return Err(CeremonyContextErrorV1::ActivationOriginContextReused);
        }
        Ok(authorization)
    }

    pub(crate) fn new_for_lifecycle_attempt(
        request: &CeremonyPublicRequestContextV1,
        authorization_record_digest: CeremonyAuthorizationRecordDigest32V1,
        origin: CeremonyActivationOriginV1,
        package_set_digest: CeremonyPackageSetDigest32V1,
        activation_epoch: CeremonyActivationEpochV1,
    ) -> Result<Self, CeremonyContextErrorV1> {
        require_request_kind(request, CeremonyRequestKindV1::Activation)?;
        Ok(Self {
            request_context_digest: request.digest()?,
            authorization_record_digest,
            origin_request_kind: origin.request_kind,
            origin_request_context_digest: origin.request_context_digest,
            origin_transcript_digest: origin.transcript_digest,
            package_set_digest,
            activation_epoch,
        })
    }
}

/// Recovery authorization bound to one replacement credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CeremonyRecoveryAuthorizationV1 {
    request_context_digest: CeremonyPublicRequestContextDigest32V1,
    authorization_record_digest: CeremonyAuthorizationRecordDigest32V1,
    replacement_credential_binding_digest: CeremonyReplacementCredentialBindingDigest32V1,
}

impl CeremonyRecoveryAuthorizationV1 {
    /// Binds same-root recovery admission to one replacement credential binding.
    pub fn new(
        request: &CeremonyPublicRequestContextV1,
        authorization_record_digest: CeremonyAuthorizationRecordDigest32V1,
        replacement_credential_binding_digest: CeremonyReplacementCredentialBindingDigest32V1,
    ) -> Result<Self, CeremonyContextErrorV1> {
        require_request_kind(request, CeremonyRequestKindV1::Recovery)?;
        Ok(Self {
            request_context_digest: request.digest()?,
            authorization_record_digest,
            replacement_credential_binding_digest,
        })
    }

    /// Returns the replacement credential binding fixed by recovery admission.
    pub(crate) const fn replacement_credential_binding_digest(
        &self,
    ) -> CeremonyReplacementCredentialBindingDigest32V1 {
        self.replacement_credential_binding_digest
    }
}

/// Refresh authorization with role-specific strictly advancing input-state epochs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CeremonyRefreshAuthorizationV1 {
    request_context_digest: CeremonyPublicRequestContextDigest32V1,
    authorization_record_digest: CeremonyAuthorizationRecordDigest32V1,
    current_deriver_a_input_state_epoch: CeremonyCurrentDeriverAInputStateEpochV1,
    next_deriver_a_input_state_epoch: CeremonyNextDeriverAInputStateEpochV1,
    current_deriver_b_input_state_epoch: CeremonyCurrentDeriverBInputStateEpochV1,
    next_deriver_b_input_state_epoch: CeremonyNextDeriverBInputStateEpochV1,
}

impl CeremonyRefreshAuthorizationV1 {
    /// Validates and binds both strictly advancing role input-state epochs.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        request: &CeremonyPublicRequestContextV1,
        authorization_record_digest: CeremonyAuthorizationRecordDigest32V1,
        current_deriver_a_input_state_epoch: CeremonyCurrentDeriverAInputStateEpochV1,
        next_deriver_a_input_state_epoch: CeremonyNextDeriverAInputStateEpochV1,
        current_deriver_b_input_state_epoch: CeremonyCurrentDeriverBInputStateEpochV1,
        next_deriver_b_input_state_epoch: CeremonyNextDeriverBInputStateEpochV1,
    ) -> Result<Self, CeremonyContextErrorV1> {
        require_request_kind(request, CeremonyRequestKindV1::Refresh)?;
        if next_deriver_a_input_state_epoch.value() <= current_deriver_a_input_state_epoch.value() {
            return Err(CeremonyContextErrorV1::RefreshEpochDidNotStrictlyAdvance(
                CeremonyNumericFieldV1::NextDeriverAInputStateEpoch,
            ));
        }
        if next_deriver_b_input_state_epoch.value() <= current_deriver_b_input_state_epoch.value() {
            return Err(CeremonyContextErrorV1::RefreshEpochDidNotStrictlyAdvance(
                CeremonyNumericFieldV1::NextDeriverBInputStateEpoch,
            ));
        }
        Ok(Self {
            request_context_digest: request.digest()?,
            authorization_record_digest,
            current_deriver_a_input_state_epoch,
            next_deriver_a_input_state_epoch,
            current_deriver_b_input_state_epoch,
            next_deriver_b_input_state_epoch,
        })
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) const fn current_deriver_a_input_state_epoch(
        &self,
    ) -> CeremonyCurrentDeriverAInputStateEpochV1 {
        self.current_deriver_a_input_state_epoch
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) const fn next_deriver_a_input_state_epoch(
        &self,
    ) -> CeremonyNextDeriverAInputStateEpochV1 {
        self.next_deriver_a_input_state_epoch
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) const fn current_deriver_b_input_state_epoch(
        &self,
    ) -> CeremonyCurrentDeriverBInputStateEpochV1 {
        self.current_deriver_b_input_state_epoch
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) const fn next_deriver_b_input_state_epoch(
        &self,
    ) -> CeremonyNextDeriverBInputStateEpochV1 {
        self.next_deriver_b_input_state_epoch
    }
}

/// Export authorization bound to the canonical registered Ed25519 identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CeremonyExportAuthorizationV1 {
    request_context_digest: CeremonyPublicRequestContextDigest32V1,
    authorization_record_digest: CeremonyAuthorizationRecordDigest32V1,
    registered_public_key: RegisteredEd25519PublicKey32V1,
}

impl CeremonyExportAuthorizationV1 {
    /// Binds export admission to the registered public identity.
    pub fn new(
        request: &CeremonyPublicRequestContextV1,
        authorization_record_digest: CeremonyAuthorizationRecordDigest32V1,
        registered_public_key: RegisteredEd25519PublicKey32V1,
    ) -> Result<Self, CeremonyContextErrorV1> {
        require_request_kind(request, CeremonyRequestKindV1::Export)?;
        Ok(Self {
            request_context_digest: request.digest()?,
            authorization_record_digest,
            registered_public_key,
        })
    }

    /// Returns the canonical registered identity bound by this authorization.
    pub const fn registered_public_key(&self) -> RegisteredEd25519PublicKey32V1 {
        self.registered_public_key
    }
}

/// Branch-specific authorization. Invalid field combinations are unrepresentable.
///
/// ```compile_fail
/// use ed25519_yao_generator::ceremony_context::{
///     CeremonyExportAuthorizationV1, CeremonyRegistrationAuthorizationV1,
/// };
///
/// fn accepts_export(_authorization: CeremonyExportAuthorizationV1) {}
/// fn reject_cross_branch(authorization: CeremonyRegistrationAuthorizationV1) {
///     accepts_export(authorization);
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CeremonyAuthorizationV1 {
    /// Registration admission and intent.
    Registration(CeremonyRegistrationAuthorizationV1),
    /// Internal activation-control authorization.
    Activation(CeremonyActivationAuthorizationV1),
    /// Same-root recovery authorization.
    Recovery(CeremonyRecoveryAuthorizationV1),
    /// Role-epoch refresh authorization.
    Refresh(CeremonyRefreshAuthorizationV1),
    /// Explicit seed-export authorization.
    Export(CeremonyExportAuthorizationV1),
}

impl CeremonyAuthorizationV1 {
    /// Returns the branch derived from the authorization type.
    pub const fn request_kind(&self) -> CeremonyRequestKindV1 {
        match self {
            Self::Registration(_) => CeremonyRequestKindV1::Registration,
            Self::Activation(_) => CeremonyRequestKindV1::Activation,
            Self::Recovery(_) => CeremonyRequestKindV1::Recovery,
            Self::Refresh(_) => CeremonyRequestKindV1::Refresh,
            Self::Export(_) => CeremonyRequestKindV1::Export,
        }
    }

    /// Returns the request-context digest embedded by the branch constructor.
    pub const fn request_context_digest(&self) -> CeremonyPublicRequestContextDigest32V1 {
        match self {
            Self::Registration(value) => value.request_context_digest,
            Self::Activation(value) => value.request_context_digest,
            Self::Recovery(value) => value.request_context_digest,
            Self::Refresh(value) => value.request_context_digest,
            Self::Export(value) => value.request_context_digest,
        }
    }

    /// Encodes the exact branch-specific authorization preimage.
    pub fn encode(&self) -> Result<Vec<u8>, CeremonyContextErrorV1> {
        let mut output = Vec::new();
        push_lp32(&mut output, authorization_domain(self.request_kind()))?;
        push_labeled(
            &mut output,
            REQUEST_KIND_LABEL,
            &[self.request_kind().tag()],
        )?;
        push_labeled(
            &mut output,
            PUBLIC_REQUEST_CONTEXT_DIGEST_LABEL,
            self.request_context_digest().as_bytes(),
        )?;
        match self {
            Self::Registration(value) => encode_registration_authorization(&mut output, value)?,
            Self::Activation(value) => encode_activation_authorization(&mut output, value)?,
            Self::Recovery(value) => encode_recovery_authorization(&mut output, value)?,
            Self::Refresh(value) => encode_refresh_authorization(&mut output, value)?,
            Self::Export(value) => encode_export_authorization(&mut output, value)?,
        }
        Ok(output)
    }

    /// Computes SHA-256 over the exact authorization bytes.
    pub fn digest(&self) -> Result<CeremonyAuthorizationDigest32V1, CeremonyContextErrorV1> {
        Ok(CeremonyAuthorizationDigest32V1(
            Sha256::digest(self.encode()?).into(),
        ))
    }
}

impl From<CeremonyRegistrationAuthorizationV1> for CeremonyAuthorizationV1 {
    fn from(value: CeremonyRegistrationAuthorizationV1) -> Self {
        Self::Registration(value)
    }
}

impl From<CeremonyActivationAuthorizationV1> for CeremonyAuthorizationV1 {
    fn from(value: CeremonyActivationAuthorizationV1) -> Self {
        Self::Activation(value)
    }
}

impl From<CeremonyRecoveryAuthorizationV1> for CeremonyAuthorizationV1 {
    fn from(value: CeremonyRecoveryAuthorizationV1) -> Self {
        Self::Recovery(value)
    }
}

impl From<CeremonyRefreshAuthorizationV1> for CeremonyAuthorizationV1 {
    fn from(value: CeremonyRefreshAuthorizationV1) -> Self {
        Self::Refresh(value)
    }
}

impl From<CeremonyExportAuthorizationV1> for CeremonyAuthorizationV1 {
    fn from(value: CeremonyExportAuthorizationV1) -> Self {
        Self::Export(value)
    }
}

/// SHA-256 digest of one branch-specific authorization preimage.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct CeremonyAuthorizationDigest32V1([u8; 32]);

impl CeremonyAuthorizationDigest32V1 {
    /// Returns the exact digest bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for CeremonyAuthorizationDigest32V1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CeremonyAuthorizationDigest32V1([computed SHA-256])")
    }
}

/// SHA-256 digest of the exact ceremony transcript preimage.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct CeremonyTranscriptDigest32V1([u8; 32]);

impl CeremonyTranscriptDigest32V1 {
    /// Returns the exact digest bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for CeremonyTranscriptDigest32V1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CeremonyTranscriptDigest32V1([computed SHA-256])")
    }
}

/// Canonical transcript binding over request, authorization, and public suite slots.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CeremonyTranscriptV1 {
    request_kind: CeremonyRequestKindV1,
    request_context_digest: CeremonyPublicRequestContextDigest32V1,
    authorization_digest: CeremonyAuthorizationDigest32V1,
    transcript_nonce: CeremonyTranscriptNonce32V1,
    transport_binding_digest: CeremonyTransportBindingDigest32V1,
    artifact_suite_digest: CeremonyArtifactSuiteDigest32V1,
}

impl CeremonyTranscriptV1 {
    /// Constructs the final transcript layer and validates both prior DAG edges.
    pub fn new(
        request: &CeremonyPublicRequestContextV1,
        authorization: &CeremonyAuthorizationV1,
        transcript_nonce: CeremonyTranscriptNonce32V1,
        transport_binding_digest: CeremonyTransportBindingDigest32V1,
        artifact_suite_digest: CeremonyArtifactSuiteDigest32V1,
    ) -> Result<Self, CeremonyContextErrorV1> {
        if authorization.request_kind() != request.request_kind() {
            return Err(CeremonyContextErrorV1::AuthorizationRequestKindMismatch);
        }
        let request_context_digest = request.digest()?;
        if authorization.request_context_digest() != request_context_digest {
            return Err(CeremonyContextErrorV1::AuthorizationContextDigestMismatch);
        }
        Ok(Self {
            request_kind: request.request_kind(),
            request_context_digest,
            authorization_digest: authorization.digest()?,
            transcript_nonce,
            transport_binding_digest,
            artifact_suite_digest,
        })
    }

    /// Returns the fixed request kind.
    pub const fn request_kind(&self) -> CeremonyRequestKindV1 {
        self.request_kind
    }

    /// Returns the bound request-context digest.
    pub const fn request_context_digest(&self) -> CeremonyPublicRequestContextDigest32V1 {
        self.request_context_digest
    }

    /// Returns the bound authorization digest.
    pub const fn authorization_digest(&self) -> CeremonyAuthorizationDigest32V1 {
        self.authorization_digest
    }

    /// Returns the independent public transcript nonce.
    pub const fn transcript_nonce(&self) -> CeremonyTranscriptNonce32V1 {
        self.transcript_nonce
    }

    /// Returns the public artifact-suite digest bound by this transcript.
    pub const fn artifact_suite_digest(&self) -> CeremonyArtifactSuiteDigest32V1 {
        self.artifact_suite_digest
    }

    /// Returns the public transport-binding digest bound by this transcript.
    pub const fn transport_binding_digest(&self) -> CeremonyTransportBindingDigest32V1 {
        self.transport_binding_digest
    }

    /// Encodes the final transcript without any ciphertext or self-dependent digest.
    pub fn encode(&self) -> Result<Vec<u8>, CeremonyContextErrorV1> {
        let mut output = Vec::new();
        push_lp32(&mut output, CEREMONY_TRANSCRIPT_ENCODING_DOMAIN_V1)?;
        push_labeled(&mut output, PROTOCOL_VERSION_LABEL, &1_u64.to_be_bytes())?;
        push_labeled(
            &mut output,
            PROTOCOL_ID_LABEL,
            ed25519_yao::PROTOCOL_ID_STR.as_bytes(),
        )?;
        push_labeled(&mut output, REQUEST_KIND_LABEL, &[self.request_kind.tag()])?;
        push_labeled(
            &mut output,
            CIRCUIT_ID_LABEL,
            self.request_kind.circuit_id().as_bytes(),
        )?;
        push_labeled(
            &mut output,
            PUBLIC_REQUEST_CONTEXT_DIGEST_LABEL,
            self.request_context_digest.as_bytes(),
        )?;
        push_labeled(
            &mut output,
            AUTHORIZATION_DIGEST_LABEL,
            self.authorization_digest.as_bytes(),
        )?;
        push_labeled(
            &mut output,
            TRANSCRIPT_NONCE_LABEL,
            self.transcript_nonce.as_bytes(),
        )?;
        push_labeled(
            &mut output,
            TRANSPORT_BINDING_DIGEST_LABEL,
            self.transport_binding_digest.as_bytes(),
        )?;
        push_labeled(
            &mut output,
            ARTIFACT_SUITE_DIGEST_LABEL,
            self.artifact_suite_digest.as_bytes(),
        )?;
        Ok(output)
    }

    /// Computes SHA-256 over the exact transcript bytes.
    pub fn digest(&self) -> Result<CeremonyTranscriptDigest32V1, CeremonyContextErrorV1> {
        Ok(CeremonyTranscriptDigest32V1(
            Sha256::digest(self.encode()?).into(),
        ))
    }
}

/// Validates one canonical request-context encoding.
pub fn validate_canonical_public_request_context_encoding_v1(
    encoding: &[u8],
) -> Result<(), CeremonyContextErrorV1> {
    decode_public_request_context(encoding).map(|_| ())
}

/// Validates one canonical branch-specific authorization encoding.
pub fn validate_canonical_authorization_encoding_v1(
    encoding: &[u8],
) -> Result<(), CeremonyContextErrorV1> {
    decode_authorization(encoding).map(|_| ())
}

/// Validates one canonical ceremony-transcript encoding.
pub fn validate_canonical_transcript_encoding_v1(
    encoding: &[u8],
) -> Result<(), CeremonyContextErrorV1> {
    decode_transcript(encoding).map(|_| ())
}

/// Validates exact encodings and the two digest edges in the three-layer DAG.
pub fn validate_canonical_ceremony_bundle_v1(
    request_context_encoding: &[u8],
    authorization_encoding: &[u8],
    transcript_encoding: &[u8],
) -> Result<(), CeremonyContextErrorV1> {
    let request = decode_public_request_context(request_context_encoding)?;
    let authorization = decode_authorization(authorization_encoding)?;
    let transcript = decode_transcript(transcript_encoding)?;
    if request.request_kind != authorization.request_kind
        || request.request_kind != transcript.request_kind
    {
        return Err(CeremonyContextErrorV1::AuthorizationRequestKindMismatch);
    }
    let request_digest = Sha256::digest(request_context_encoding);
    if authorization.request_context_digest != request_digest.as_slice() {
        return Err(CeremonyContextErrorV1::AuthorizationContextDigestMismatch);
    }
    if transcript.request_context_digest != request_digest.as_slice() {
        return Err(CeremonyContextErrorV1::TranscriptContextDigestMismatch);
    }
    let authorization_digest = Sha256::digest(authorization_encoding);
    if transcript.authorization_digest != authorization_digest.as_slice() {
        return Err(CeremonyContextErrorV1::TranscriptAuthorizationDigestMismatch);
    }
    Ok(())
}

fn require_request_kind(
    request: &CeremonyPublicRequestContextV1,
    expected: CeremonyRequestKindV1,
) -> Result<(), CeremonyContextErrorV1> {
    if request.request_kind() != expected {
        return Err(CeremonyContextErrorV1::AuthorizationRequestKindMismatch);
    }
    Ok(())
}

fn authorization_domain(kind: CeremonyRequestKindV1) -> &'static [u8] {
    match kind {
        CeremonyRequestKindV1::Registration => REGISTRATION_AUTHORIZATION_ENCODING_DOMAIN_V1,
        CeremonyRequestKindV1::Activation => ACTIVATION_AUTHORIZATION_ENCODING_DOMAIN_V1,
        CeremonyRequestKindV1::Recovery => RECOVERY_AUTHORIZATION_ENCODING_DOMAIN_V1,
        CeremonyRequestKindV1::Refresh => REFRESH_AUTHORIZATION_ENCODING_DOMAIN_V1,
        CeremonyRequestKindV1::Export => EXPORT_AUTHORIZATION_ENCODING_DOMAIN_V1,
    }
}

fn encode_registration_authorization(
    output: &mut Vec<u8>,
    value: &CeremonyRegistrationAuthorizationV1,
) -> Result<(), CeremonyContextErrorV1> {
    push_labeled(
        output,
        AUTHORIZATION_RECORD_DIGEST_LABEL,
        value.authorization_record_digest.as_bytes(),
    )?;
    push_labeled(
        output,
        REGISTRATION_INTENT_DIGEST_LABEL,
        value.registration_intent_digest.as_bytes(),
    )
}

fn encode_activation_authorization(
    output: &mut Vec<u8>,
    value: &CeremonyActivationAuthorizationV1,
) -> Result<(), CeremonyContextErrorV1> {
    push_labeled(
        output,
        AUTHORIZATION_RECORD_DIGEST_LABEL,
        value.authorization_record_digest.as_bytes(),
    )?;
    push_labeled(
        output,
        ORIGIN_REQUEST_KIND_LABEL,
        &[value.origin_request_kind.tag()],
    )?;
    push_labeled(
        output,
        ORIGIN_REQUEST_CONTEXT_DIGEST_LABEL,
        value.origin_request_context_digest.as_bytes(),
    )?;
    push_labeled(
        output,
        ORIGIN_TRANSCRIPT_DIGEST_LABEL,
        value.origin_transcript_digest.as_bytes(),
    )?;
    push_labeled(
        output,
        PACKAGE_SET_DIGEST_LABEL,
        value.package_set_digest.as_bytes(),
    )?;
    push_labeled(
        output,
        ACTIVATION_EPOCH_LABEL,
        &value.activation_epoch.value().to_be_bytes(),
    )
}

fn encode_recovery_authorization(
    output: &mut Vec<u8>,
    value: &CeremonyRecoveryAuthorizationV1,
) -> Result<(), CeremonyContextErrorV1> {
    push_labeled(
        output,
        AUTHORIZATION_RECORD_DIGEST_LABEL,
        value.authorization_record_digest.as_bytes(),
    )?;
    push_labeled(
        output,
        REPLACEMENT_CREDENTIAL_BINDING_DIGEST_LABEL,
        value.replacement_credential_binding_digest.as_bytes(),
    )
}

fn encode_refresh_authorization(
    output: &mut Vec<u8>,
    value: &CeremonyRefreshAuthorizationV1,
) -> Result<(), CeremonyContextErrorV1> {
    push_labeled(
        output,
        AUTHORIZATION_RECORD_DIGEST_LABEL,
        value.authorization_record_digest.as_bytes(),
    )?;
    push_labeled(
        output,
        CURRENT_DERIVER_A_INPUT_STATE_EPOCH_LABEL,
        &value
            .current_deriver_a_input_state_epoch
            .value()
            .to_be_bytes(),
    )?;
    push_labeled(
        output,
        NEXT_DERIVER_A_INPUT_STATE_EPOCH_LABEL,
        &value.next_deriver_a_input_state_epoch.value().to_be_bytes(),
    )?;
    push_labeled(
        output,
        CURRENT_DERIVER_B_INPUT_STATE_EPOCH_LABEL,
        &value
            .current_deriver_b_input_state_epoch
            .value()
            .to_be_bytes(),
    )?;
    push_labeled(
        output,
        NEXT_DERIVER_B_INPUT_STATE_EPOCH_LABEL,
        &value.next_deriver_b_input_state_epoch.value().to_be_bytes(),
    )
}

fn encode_export_authorization(
    output: &mut Vec<u8>,
    value: &CeremonyExportAuthorizationV1,
) -> Result<(), CeremonyContextErrorV1> {
    push_labeled(
        output,
        AUTHORIZATION_RECORD_DIGEST_LABEL,
        value.authorization_record_digest.as_bytes(),
    )?;
    push_labeled(
        output,
        REGISTERED_ED25519_PUBLIC_KEY_LABEL,
        value.registered_public_key.as_bytes(),
    )
}

fn push_labeled(
    output: &mut Vec<u8>,
    label: &[u8],
    value: &[u8],
) -> Result<(), CeremonyContextErrorV1> {
    push_lp32(output, label)?;
    push_lp32(output, value)
}

fn push_lp32(output: &mut Vec<u8>, value: &[u8]) -> Result<(), CeremonyContextErrorV1> {
    let length = u32::try_from(value.len()).map_err(|_| CeremonyContextErrorV1::ValueTooLong)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

struct Lp32Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Lp32Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn read(&mut self) -> Result<&'a [u8], CeremonyContextErrorV1> {
        let length_end = self
            .offset
            .checked_add(4)
            .ok_or(CeremonyContextErrorV1::MalformedEncoding)?;
        let length_bytes: [u8; 4] = self
            .bytes
            .get(self.offset..length_end)
            .ok_or(CeremonyContextErrorV1::MalformedEncoding)?
            .try_into()
            .map_err(|_| CeremonyContextErrorV1::MalformedEncoding)?;
        let length = u32::from_be_bytes(length_bytes) as usize;
        let value_end = length_end
            .checked_add(length)
            .ok_or(CeremonyContextErrorV1::MalformedEncoding)?;
        let value = self
            .bytes
            .get(length_end..value_end)
            .ok_or(CeremonyContextErrorV1::MalformedEncoding)?;
        self.offset = value_end;
        Ok(value)
    }

    fn read_labeled(&mut self, expected_label: &[u8]) -> Result<&'a [u8], CeremonyContextErrorV1> {
        if self.read()? != expected_label {
            return Err(CeremonyContextErrorV1::MalformedEncoding);
        }
        self.read()
    }

    fn finish(self) -> Result<(), CeremonyContextErrorV1> {
        if self.offset != self.bytes.len() {
            return Err(CeremonyContextErrorV1::MalformedEncoding);
        }
        Ok(())
    }
}

struct DecodedRequestContextV1 {
    request_kind: CeremonyRequestKindV1,
}

struct DecodedAuthorizationV1 {
    request_kind: CeremonyRequestKindV1,
    request_context_digest: [u8; 32],
}

struct DecodedTranscriptV1 {
    request_kind: CeremonyRequestKindV1,
    request_context_digest: [u8; 32],
    authorization_digest: [u8; 32],
}

fn decode_public_request_context(
    encoding: &[u8],
) -> Result<DecodedRequestContextV1, CeremonyContextErrorV1> {
    let mut cursor = Lp32Cursor::new(encoding);
    require_exact(cursor.read()?, PUBLIC_REQUEST_CONTEXT_ENCODING_DOMAIN_V1)?;
    require_exact(
        cursor.read_labeled(PROTOCOL_VERSION_LABEL)?,
        &1_u64.to_be_bytes(),
    )?;
    let request_kind = decode_request_kind(cursor.read_labeled(REQUEST_KIND_LABEL)?)?;
    require_visible_ascii(cursor.read_labeled(REQUEST_ID_LABEL)?)?;
    require_fixed::<32>(cursor.read_labeled(REPLAY_NONCE_LABEL)?)?;
    require_visible_ascii(cursor.read_labeled(ACCOUNT_ID_LABEL)?)?;
    require_visible_ascii(cursor.read_labeled(WALLET_ID_LABEL)?)?;
    require_visible_ascii(cursor.read_labeled(SESSION_ID_LABEL)?)?;
    require_visible_ascii(cursor.read_labeled(ORGANIZATION_ID_LABEL)?)?;
    require_visible_ascii(cursor.read_labeled(PROJECT_ID_LABEL)?)?;
    require_visible_ascii(cursor.read_labeled(ENVIRONMENT_ID_LABEL)?)?;
    require_visible_ascii(cursor.read_labeled(SIGNING_ROOT_ID_LABEL)?)?;
    require_nonzero_be64(cursor.read_labeled(SIGNING_ROOT_VERSION_LABEL)?)?;
    require_visible_ascii(cursor.read_labeled(CHAIN_TARGET_LABEL)?)?;
    require_nonzero_be64(cursor.read_labeled(ROOT_SHARE_EPOCH_LABEL)?)?;
    require_visible_ascii(cursor.read_labeled(ROUTER_ID_LABEL)?)?;
    require_visible_ascii(cursor.read_labeled(DERIVER_SET_ID_LABEL)?)?;
    require_visible_ascii(cursor.read_labeled(DERIVER_A_ID_LABEL)?)?;
    require_nonzero_be64(cursor.read_labeled(DERIVER_A_KEY_EPOCH_LABEL)?)?;
    require_visible_ascii(cursor.read_labeled(DERIVER_B_ID_LABEL)?)?;
    require_nonzero_be64(cursor.read_labeled(DERIVER_B_KEY_EPOCH_LABEL)?)?;
    require_visible_ascii(cursor.read_labeled(SIGNING_WORKER_ID_LABEL)?)?;
    require_nonzero_be64(cursor.read_labeled(SIGNING_WORKER_KEY_EPOCH_LABEL)?)?;
    require_fixed::<32>(cursor.read_labeled(CLIENT_EPHEMERAL_PUBLIC_KEY_LABEL)?)?;
    require_exact(
        cursor.read_labeled(RECIPIENT_PLAN_LABEL)?,
        &[request_kind.recipient_plan_tag()],
    )?;
    require_exact(
        cursor.read_labeled(OUTPUT_PACKAGE_KIND_LABEL)?,
        &[request_kind.output_package_kind_tag()],
    )?;
    require_nonzero_be64(cursor.read_labeled(REQUEST_EXPIRY_LABEL)?)?;
    cursor.finish()?;
    Ok(DecodedRequestContextV1 { request_kind })
}

fn decode_authorization(encoding: &[u8]) -> Result<DecodedAuthorizationV1, CeremonyContextErrorV1> {
    let mut cursor = Lp32Cursor::new(encoding);
    let domain = cursor.read()?;
    let request_kind = decode_request_kind(cursor.read_labeled(REQUEST_KIND_LABEL)?)?;
    require_exact(domain, authorization_domain(request_kind))?;
    let request_context_digest =
        require_fixed::<32>(cursor.read_labeled(PUBLIC_REQUEST_CONTEXT_DIGEST_LABEL)?)?;
    require_nonzero_digest_bytes(cursor.read_labeled(AUTHORIZATION_RECORD_DIGEST_LABEL)?)?;
    match request_kind {
        CeremonyRequestKindV1::Registration => {
            require_nonzero_digest_bytes(cursor.read_labeled(REGISTRATION_INTENT_DIGEST_LABEL)?)?;
        }
        CeremonyRequestKindV1::Activation => {
            let origin_request_kind =
                decode_request_kind(cursor.read_labeled(ORIGIN_REQUEST_KIND_LABEL)?)?;
            if !matches!(
                origin_request_kind,
                CeremonyRequestKindV1::Registration
                    | CeremonyRequestKindV1::Recovery
                    | CeremonyRequestKindV1::Refresh
            ) {
                return Err(CeremonyContextErrorV1::InvalidActivationOriginRequestKind);
            }
            let origin_request_context_digest =
                require_fixed::<32>(cursor.read_labeled(ORIGIN_REQUEST_CONTEXT_DIGEST_LABEL)?)?;
            if origin_request_context_digest == request_context_digest {
                return Err(CeremonyContextErrorV1::ActivationOriginContextReused);
            }
            require_fixed::<32>(cursor.read_labeled(ORIGIN_TRANSCRIPT_DIGEST_LABEL)?)?;
            require_nonzero_digest_bytes(cursor.read_labeled(PACKAGE_SET_DIGEST_LABEL)?)?;
            require_nonzero_be64(cursor.read_labeled(ACTIVATION_EPOCH_LABEL)?)?;
        }
        CeremonyRequestKindV1::Recovery => {
            require_nonzero_digest_bytes(
                cursor.read_labeled(REPLACEMENT_CREDENTIAL_BINDING_DIGEST_LABEL)?,
            )?;
        }
        CeremonyRequestKindV1::Refresh => decode_refresh_epochs(&mut cursor)?,
        CeremonyRequestKindV1::Export => {
            let public_key =
                require_fixed::<32>(cursor.read_labeled(REGISTERED_ED25519_PUBLIC_KEY_LABEL)?)?;
            RegisteredEd25519PublicKey32V1::parse(public_key)
                .map_err(CeremonyContextErrorV1::RegisteredPublicKey)?;
        }
    }
    cursor.finish()?;
    Ok(DecodedAuthorizationV1 {
        request_kind,
        request_context_digest,
    })
}

fn decode_refresh_epochs(cursor: &mut Lp32Cursor<'_>) -> Result<(), CeremonyContextErrorV1> {
    let current_a =
        require_nonzero_be64(cursor.read_labeled(CURRENT_DERIVER_A_INPUT_STATE_EPOCH_LABEL)?)?;
    let next_a =
        require_nonzero_be64(cursor.read_labeled(NEXT_DERIVER_A_INPUT_STATE_EPOCH_LABEL)?)?;
    let current_b =
        require_nonzero_be64(cursor.read_labeled(CURRENT_DERIVER_B_INPUT_STATE_EPOCH_LABEL)?)?;
    let next_b =
        require_nonzero_be64(cursor.read_labeled(NEXT_DERIVER_B_INPUT_STATE_EPOCH_LABEL)?)?;
    if next_a <= current_a || next_b <= current_b {
        return Err(CeremonyContextErrorV1::MalformedEncoding);
    }
    Ok(())
}

fn decode_transcript(encoding: &[u8]) -> Result<DecodedTranscriptV1, CeremonyContextErrorV1> {
    let mut cursor = Lp32Cursor::new(encoding);
    require_exact(cursor.read()?, CEREMONY_TRANSCRIPT_ENCODING_DOMAIN_V1)?;
    require_exact(
        cursor.read_labeled(PROTOCOL_VERSION_LABEL)?,
        &1_u64.to_be_bytes(),
    )?;
    require_exact(
        cursor.read_labeled(PROTOCOL_ID_LABEL)?,
        ed25519_yao::PROTOCOL_ID_STR.as_bytes(),
    )?;
    let request_kind = decode_request_kind(cursor.read_labeled(REQUEST_KIND_LABEL)?)?;
    require_exact(
        cursor.read_labeled(CIRCUIT_ID_LABEL)?,
        request_kind.circuit_id().as_bytes(),
    )?;
    let request_context_digest =
        require_fixed::<32>(cursor.read_labeled(PUBLIC_REQUEST_CONTEXT_DIGEST_LABEL)?)?;
    let authorization_digest =
        require_fixed::<32>(cursor.read_labeled(AUTHORIZATION_DIGEST_LABEL)?)?;
    require_fixed::<32>(cursor.read_labeled(TRANSCRIPT_NONCE_LABEL)?)?;
    require_nonzero_digest_bytes(cursor.read_labeled(TRANSPORT_BINDING_DIGEST_LABEL)?)?;
    require_nonzero_digest_bytes(cursor.read_labeled(ARTIFACT_SUITE_DIGEST_LABEL)?)?;
    cursor.finish()?;
    Ok(DecodedTranscriptV1 {
        request_kind,
        request_context_digest,
        authorization_digest,
    })
}

fn decode_request_kind(bytes: &[u8]) -> Result<CeremonyRequestKindV1, CeremonyContextErrorV1> {
    let [tag] = bytes else {
        return Err(CeremonyContextErrorV1::MalformedEncoding);
    };
    CeremonyRequestKindV1::from_tag(*tag)
}

fn require_exact(actual: &[u8], expected: &[u8]) -> Result<(), CeremonyContextErrorV1> {
    if actual != expected {
        return Err(CeremonyContextErrorV1::MalformedEncoding);
    }
    Ok(())
}

fn require_visible_ascii(bytes: &[u8]) -> Result<(), CeremonyContextErrorV1> {
    if bytes.is_empty() || !bytes.iter().all(|byte| (0x21..=0x7e).contains(byte)) {
        return Err(CeremonyContextErrorV1::MalformedEncoding);
    }
    Ok(())
}

fn require_fixed<const N: usize>(bytes: &[u8]) -> Result<[u8; N], CeremonyContextErrorV1> {
    bytes
        .try_into()
        .map_err(|_| CeremonyContextErrorV1::MalformedEncoding)
}

fn require_nonzero_be64(bytes: &[u8]) -> Result<u64, CeremonyContextErrorV1> {
    let value = u64::from_be_bytes(require_fixed::<8>(bytes)?);
    if value == 0 {
        return Err(CeremonyContextErrorV1::MalformedEncoding);
    }
    Ok(value)
}

fn require_nonzero_digest_bytes(bytes: &[u8]) -> Result<[u8; 32], CeremonyContextErrorV1> {
    let digest = require_fixed::<32>(bytes)?;
    if digest == [0; 32] {
        return Err(CeremonyContextErrorV1::MalformedEncoding);
    }
    Ok(digest)
}
