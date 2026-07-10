use core::fmt;

use sha2::{Digest, Sha256};

/// Domain separating the Yao-era stable key context from every prior scheme.
pub const STABLE_KEY_DERIVATION_CONTEXT_DOMAIN_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/stable-key-context/v1";

/// Domain separating the stable context binding digest from its encoding.
pub const STABLE_KEY_DERIVATION_CONTEXT_BINDING_DOMAIN_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/stable-key-context-binding/v1";

/// Exact byte length of the version-one stable context encoding.
pub const STABLE_KEY_DERIVATION_CONTEXT_ENCODED_LEN: usize =
    STABLE_KEY_DERIVATION_CONTEXT_DOMAIN_V1.len() + 32 + 2 + 2;

/// Position of an invalid participant identifier at the raw boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParticipantPosition {
    /// First raw participant identifier.
    First,
    /// Second raw participant identifier.
    Second,
}

/// Validation failures for stable key derivation context construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StableKeyDerivationContextError {
    /// Participant identifiers must be non-zero.
    ZeroParticipantId {
        /// Position of the zero identifier.
        position: ParticipantPosition,
    },
    /// The two participants must have distinct identifiers.
    DuplicateParticipantIds,
}

impl fmt::Display for StableKeyDerivationContextError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroParticipantId { position } => {
                write!(
                    formatter,
                    "{position:?} participant identifier must be non-zero"
                )
            }
            Self::DuplicateParticipantIds => {
                formatter.write_str("participant identifiers must be distinct")
            }
        }
    }
}

impl std::error::Error for StableKeyDerivationContextError {}

/// Immutable SDK-owned application binding digest.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ApplicationBindingDigest([u8; 32]);

impl ApplicationBindingDigest {
    /// Constructs a digest already validated as exactly 32 bytes by its type.
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the immutable digest bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Exactly two distinct, non-zero participant identifiers in ascending order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NormalizedParticipantIds([u16; 2]);

impl NormalizedParticipantIds {
    /// Validates two raw identifiers and canonicalizes their order.
    pub fn new(first: u16, second: u16) -> Result<Self, StableKeyDerivationContextError> {
        if first == 0 {
            return Err(StableKeyDerivationContextError::ZeroParticipantId {
                position: ParticipantPosition::First,
            });
        }
        if second == 0 {
            return Err(StableKeyDerivationContextError::ZeroParticipantId {
                position: ParticipantPosition::Second,
            });
        }
        if first == second {
            return Err(StableKeyDerivationContextError::DuplicateParticipantIds);
        }

        let normalized = if first < second {
            [first, second]
        } else {
            [second, first]
        };
        Ok(Self(normalized))
    }

    /// Returns the canonical ascending pair.
    pub const fn as_array(&self) -> [u16; 2] {
        self.0
    }
}

/// Immutable, key-affecting context for the Yao-era Ed25519 derivation.
pub struct StableKeyDerivationContext {
    application_binding_digest: ApplicationBindingDigest,
    participant_ids: NormalizedParticipantIds,
}

impl StableKeyDerivationContext {
    /// Validates and constructs the only supported version-one context shape.
    pub fn new(
        application_binding_digest: [u8; 32],
        first_participant_id: u16,
        second_participant_id: u16,
    ) -> Result<Self, StableKeyDerivationContextError> {
        Ok(Self {
            application_binding_digest: ApplicationBindingDigest::new(application_binding_digest),
            participant_ids: NormalizedParticipantIds::new(
                first_participant_id,
                second_participant_id,
            )?,
        })
    }

    /// Returns the immutable application binding digest.
    pub const fn application_binding_digest(&self) -> &ApplicationBindingDigest {
        &self.application_binding_digest
    }

    /// Returns exactly two normalized participant identifiers.
    pub const fn participant_ids(&self) -> NormalizedParticipantIds {
        self.participant_ids
    }

    /// Encodes the frozen version-one context bytes.
    pub fn encode(&self) -> StableKeyDerivationContextBytes {
        let mut bytes = [0u8; STABLE_KEY_DERIVATION_CONTEXT_ENCODED_LEN];
        let domain_end = STABLE_KEY_DERIVATION_CONTEXT_DOMAIN_V1.len();
        bytes[..domain_end].copy_from_slice(STABLE_KEY_DERIVATION_CONTEXT_DOMAIN_V1);

        let digest_end = domain_end + 32;
        bytes[domain_end..digest_end].copy_from_slice(self.application_binding_digest.as_bytes());

        let participant_ids = self.participant_ids.as_array();
        bytes[digest_end..digest_end + 2].copy_from_slice(&participant_ids[0].to_be_bytes());
        bytes[digest_end + 2..].copy_from_slice(&participant_ids[1].to_be_bytes());

        StableKeyDerivationContextBytes(bytes)
    }

    /// Computes the frozen SHA-256 binding for the encoded context.
    pub fn binding_digest(&self) -> StableKeyDerivationContextBindingDigest {
        let encoded = self.encode();
        let mut hasher = Sha256::new();
        hasher.update(STABLE_KEY_DERIVATION_CONTEXT_BINDING_DOMAIN_V1);
        hasher.update(encoded.as_bytes());
        StableKeyDerivationContextBindingDigest(hasher.finalize().into())
    }
}

/// Frozen version-one stable context encoding.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct StableKeyDerivationContextBytes([u8; STABLE_KEY_DERIVATION_CONTEXT_ENCODED_LEN]);

impl StableKeyDerivationContextBytes {
    /// Returns the exact encoded bytes.
    pub const fn as_bytes(&self) -> &[u8; STABLE_KEY_DERIVATION_CONTEXT_ENCODED_LEN] {
        &self.0
    }
}

/// SHA-256 binding of the domain-separated stable context encoding.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct StableKeyDerivationContextBindingDigest([u8; 32]);

impl StableKeyDerivationContextBindingDigest {
    /// Returns the binding digest bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}
