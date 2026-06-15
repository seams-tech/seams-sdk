use core::fmt;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Runtime role in the Router/A/B architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// Gateway role that handles auth, rate limits, and routing.
    Router,
    /// First split signer role.
    SignerA,
    /// Second split signer role.
    SignerB,
    /// Server role that receives server-output material.
    Server,
    /// Client role that receives client-output material.
    Client,
}

impl Role {
    /// Returns the canonical role label.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Router => "router",
            Self::SignerA => "signer_a",
            Self::SignerB => "signer_b",
            Self::Server => "server",
            Self::Client => "client",
        }
    }
}

/// Kind of opened share material allowed by the target invariant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpenedShareKind {
    /// Client-side base output opened to the client.
    XClientBase,
    /// Server-side base output opened to the designated server.
    XServerBase,
}

impl OpenedShareKind {
    /// Returns the canonical opened-share label.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::XClientBase => "x_client_base",
            Self::XServerBase => "x_server_base",
        }
    }
}

/// Secret 32-byte material that zeroizes on drop.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct SecretMaterial32 {
    bytes: [u8; 32],
}

impl SecretMaterial32 {
    /// Creates a secret material wrapper.
    pub fn new(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    /// Returns secret bytes for recipient-local cryptographic use.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

impl fmt::Debug for SecretMaterial32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretMaterial32")
            .field("bytes", &"[redacted]")
            .finish()
    }
}

/// Public 32-byte material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicMaterial32 {
    /// Public bytes.
    pub bytes: [u8; 32],
}

impl PublicMaterial32 {
    /// Creates public material.
    pub fn new(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }
}

/// Public 32-byte digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicDigest32 {
    /// Digest bytes.
    pub bytes: [u8; 32],
}

impl PublicDigest32 {
    /// Creates a public digest wrapper.
    pub fn new(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    /// Returns digest bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}
