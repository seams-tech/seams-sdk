use serde::{Deserialize, Serialize};

/// Wire-format version for split-derivation vectors and envelopes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WireVersion {
    /// Initial Router/A/B split-derivation wire format.
    V1,
}

/// Canonical encoding family for committed vectors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CanonicalEncoding {
    /// Length-prefixed Rust reference encoding used during scaffolding.
    LengthPrefixedReference,
    /// Future Borsh encoding gate if adopted by the broader protocol.
    Borsh,
}
