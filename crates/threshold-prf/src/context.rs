use crate::suite::SuiteId;

/// Domain-separated purpose for a threshold PRF output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrfPurpose {
    /// Server input for `ecdsa-hss`.
    EcdsaHssYRelayer,
    /// Server root input for `ed25519-hss`.
    Ed25519HssYRelayer,
    /// Server rerandomization input for `ed25519-hss`.
    Ed25519HssTauRelayer,
}

impl PrfPurpose {
    /// Returns the canonical purpose bytes.
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::EcdsaHssYRelayer => b"ecdsa-hss/y_relayer",
            Self::Ed25519HssYRelayer => b"ed25519-hss/y_relayer",
            Self::Ed25519HssTauRelayer => b"ed25519-hss/tau_relayer",
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
