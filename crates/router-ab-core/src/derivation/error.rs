use core::fmt;

use serde::{Deserialize, Serialize};

use crate::derivation::context::{CandidateId, CorrectnessLevel, RequestKind};
use crate::derivation::material::{PublicDigest32, Role};

/// Stable error codes for split-derivation failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouterAbDerivationErrorCode {
    /// A required field was empty.
    EmptyField,
    /// A vector or transcript field is malformed.
    MalformedInput,
    /// A protocol or evidence version is unsupported.
    UnsupportedVersion,
    /// A fixture or vector has an unsupported version.
    UnsupportedVectorVersion,
    /// A candidate identifier is unsupported at this boundary.
    UnsupportedCandidate,
    /// A candidate path is intentionally present before its algorithm lands.
    NotImplemented,
    /// Correctness level did not match the verifier expectation.
    CorrectnessLevelMismatch,
    /// Signer A and Signer B used the same identity.
    DuplicateSignerIdentity,
    /// A signer identity did not match the transcript.
    SignerIdentityMismatch,
    /// A signer receipt did not bind the expected transcript.
    SignerReceiptMismatch,
    /// A root-share epoch did not match the transcript.
    RootEpochMismatch,
    /// A transcript digest did not match the expected value.
    TranscriptMismatch,
    /// A recipient role or identity did not match the expected value.
    RecipientMismatch,
    /// A replay key was reused with a different transcript value.
    ReplayMismatch,
    /// A signer-originated envelope lacked required authentication.
    UnauthenticatedEnvelope,
    /// A package commitment did not match the expected value.
    PackageCommitmentMismatch,
    /// Candidate or address verification failed.
    OutputVerificationFailed,
    /// Activation was attempted before address verification.
    AddressVerificationRequired,
    /// Ceremony state transition is invalid.
    InvalidStateTransition,
    /// A code path attempted to expose secret material.
    SecretMaterialExposure,
}

/// Redacted diagnostic metadata safe for logs after adapter policy checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedactedDiagnostic {
    /// Stable error code.
    pub code: RouterAbDerivationErrorCode,
    /// Role associated with the diagnostic, when known.
    pub role: Option<Role>,
    /// Candidate associated with the diagnostic, when known.
    pub candidate_id: Option<CandidateId>,
    /// Request kind associated with the diagnostic, when known.
    pub request_kind: Option<RequestKind>,
    /// Correctness level associated with the diagnostic, when known.
    pub correctness_level: Option<CorrectnessLevel>,
    /// Router-assigned ceremony id.
    pub ceremony_id: Option<String>,
    /// Public root-share epoch label.
    pub root_share_epoch: Option<String>,
    /// Public transcript digest.
    pub transcript_digest: Option<PublicDigest32>,
    /// Public package commitment digest.
    pub package_commitment: Option<PublicDigest32>,
}

impl RedactedDiagnostic {
    /// Creates a diagnostic with only a stable error code.
    pub fn new(code: RouterAbDerivationErrorCode) -> Self {
        Self {
            code,
            role: None,
            candidate_id: None,
            request_kind: None,
            correctness_level: None,
            ceremony_id: None,
            root_share_epoch: None,
            transcript_digest: None,
            package_commitment: None,
        }
    }
}

/// Error type used by this crate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouterAbDerivationError {
    code: RouterAbDerivationErrorCode,
    message: String,
    diagnostic: Option<RedactedDiagnostic>,
}

impl RouterAbDerivationError {
    /// Creates a new structured error.
    pub fn new(code: RouterAbDerivationErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            diagnostic: None,
        }
    }

    /// Creates a new structured error with redacted diagnostic metadata.
    pub fn with_diagnostic(
        code: RouterAbDerivationErrorCode,
        message: impl Into<String>,
        diagnostic: RedactedDiagnostic,
    ) -> Self {
        Self {
            code,
            message: message.into(),
            diagnostic: Some(diagnostic),
        }
    }

    /// Returns the stable error code.
    pub fn code(&self) -> RouterAbDerivationErrorCode {
        self.code
    }

    /// Returns a human-readable diagnostic message.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Returns optional redacted diagnostic metadata.
    pub fn diagnostic(&self) -> Option<&RedactedDiagnostic> {
        self.diagnostic.as_ref()
    }
}

impl fmt::Display for RouterAbDerivationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.code, self.message)
    }
}

impl std::error::Error for RouterAbDerivationError {}

/// Result alias used by this crate.
pub type RouterAbDerivationResult<T> = Result<T, RouterAbDerivationError>;
