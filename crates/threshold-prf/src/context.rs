use crate::suite::SuiteId;

/// Domain-separated purpose for a threshold PRF output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrfPurpose {
    /// Server input for `ecdsa-hss`.
    EcdsaHssYServer,
    /// Server root input for `ed25519-hss`.
    Ed25519HssYServer,
    /// Server rerandomization input for `ed25519-hss`.
    Ed25519HssTauServer,
    /// Router/A/B client-base output.
    RouterAbXClientBaseV1,
    /// Router/A/B server-base output.
    RouterAbXServerBaseV1,
}

/// Purpose-specific threshold PRF output encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrfOutputEncoding {
    /// Return the first 32 output-hash bytes directly.
    Raw32,
    /// Reduce the first 32 output-hash bytes to canonical Ed25519 scalar bytes.
    CanonicalEd25519Scalar32,
}

impl PrfPurpose {
    /// Returns the canonical purpose bytes.
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::EcdsaHssYServer => b"ecdsa-hss/y_server",
            Self::Ed25519HssYServer => b"ed25519-hss/y_server",
            Self::Ed25519HssTauServer => b"ed25519-hss/tau_server",
            Self::RouterAbXClientBaseV1 => b"router-ab/x_client_base/v1",
            Self::RouterAbXServerBaseV1 => b"router-ab/x_server_base/v1",
        }
    }

    /// Returns the output encoding for this purpose.
    pub fn output_encoding(&self) -> PrfOutputEncoding {
        match self {
            Self::EcdsaHssYServer | Self::Ed25519HssYServer => PrfOutputEncoding::Raw32,
            Self::Ed25519HssTauServer
            | Self::RouterAbXClientBaseV1
            | Self::RouterAbXServerBaseV1 => PrfOutputEncoding::CanonicalEd25519Scalar32,
        }
    }
}

/// Canonical threshold PRF context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrfContext {
    /// PRF suite identifier.
    pub suite_id: SuiteId,
    /// Domain-separated output purpose.
    pub purpose: PrfPurpose,
    /// Canonically encoded wallet/project context bytes.
    pub context_bytes: Vec<u8>,
}

impl PrfContext {
    /// Creates a new PRF context.
    pub fn new(suite_id: SuiteId, purpose: PrfPurpose, context_bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            suite_id,
            purpose,
            context_bytes: context_bytes.into(),
        }
    }
}
