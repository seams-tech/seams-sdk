/// Supported threshold PRF suite identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuiteId {
    /// Ristretto255 with SHA-512 for the generic canonical t-of-N protocol.
    Ristretto255Sha512,
}

impl SuiteId {
    /// Returns the canonical suite identifier bytes.
    pub fn as_bytes(self) -> &'static [u8] {
        match self {
            Self::Ristretto255Sha512 => b"threshold-prf/ristretto255-sha512",
        }
    }
}
