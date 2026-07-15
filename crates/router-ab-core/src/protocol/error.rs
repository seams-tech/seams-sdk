use core::fmt;

use serde::{Deserialize, Serialize};

/// Stable service-protocol error codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouterAbProtocolErrorCode {
    /// A required field was empty.
    EmptyField,
    /// A timestamp range was invalid.
    InvalidTimeRange,
    /// A gate decision contained invalid branch data.
    InvalidGateDecision,
    /// A registration prepare handle contained invalid scope data.
    InvalidPrepareHandle,
    /// A role was invalid at this service boundary.
    InvalidRole,
    /// Signer identity or signer-set metadata was invalid.
    InvalidSignerIdentity,
    /// A lifecycle scope or transition was invalid.
    InvalidLifecycleState,
    /// A required local-service binding was missing.
    MissingLocalBinding,
    /// A local-service binding would violate role separation.
    ForbiddenLocalBinding,
    /// A local service startup config was invalid.
    InvalidLocalServiceConfig,
    /// A local HTTP request was invalid.
    InvalidLocalHttpRequest,
    /// A local request expired before handling.
    ExpiredLocalRequest,
    /// A local request nonce was replayed.
    ReplayedLocalRequest,
    /// A local transport route did not match its wire message.
    InvalidLocalRoute,
    /// A wire payload was malformed.
    MalformedWirePayload,
    /// A vector fixture version was unsupported.
    UnsupportedVectorVersion,
}

/// Error type used by the service protocol crate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouterAbProtocolError {
    code: RouterAbProtocolErrorCode,
    message: String,
}

impl RouterAbProtocolError {
    /// Creates a structured protocol error.
    pub fn new(code: RouterAbProtocolErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// Returns the stable error code.
    pub fn code(&self) -> RouterAbProtocolErrorCode {
        self.code
    }

    /// Returns a human-readable diagnostic message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for RouterAbProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.code, self.message)
    }
}

impl std::error::Error for RouterAbProtocolError {}

/// Result alias used by this crate.
pub type RouterAbProtocolResult<T> = Result<T, RouterAbProtocolError>;
