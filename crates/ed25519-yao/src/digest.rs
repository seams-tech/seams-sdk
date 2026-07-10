use core::fmt;

use crate::{ValidationError, ValidationResult};

/// Required byte length for every manifest digest.
pub const DIGEST32_LENGTH: usize = 32;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct NonZeroDigest32([u8; DIGEST32_LENGTH]);

impl NonZeroDigest32 {
    fn new(bytes: [u8; DIGEST32_LENGTH]) -> ValidationResult<Self> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(ValidationError::ZeroDigest);
        }
        Ok(Self(bytes))
    }

    fn try_from_slice(bytes: &[u8]) -> ValidationResult<Self> {
        if bytes.len() != DIGEST32_LENGTH {
            return Err(ValidationError::DigestLength {
                actual: bytes.len(),
            });
        }
        let mut digest = [0_u8; DIGEST32_LENGTH];
        digest.copy_from_slice(bytes);
        Self::new(digest)
    }

    const fn as_bytes(&self) -> &[u8; DIGEST32_LENGTH] {
        &self.0
    }

    const fn into_bytes(self) -> [u8; DIGEST32_LENGTH] {
        self.0
    }
}

macro_rules! define_digest_type {
    ($(#[$metadata:meta])* $name:ident) => {
        $(#[$metadata])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name(NonZeroDigest32);

        impl $name {
            /// Validates an exact-width, nonzero digest for this artifact role.
            pub fn new(bytes: [u8; DIGEST32_LENGTH]) -> ValidationResult<Self> {
                NonZeroDigest32::new(bytes).map(Self)
            }

            /// Validates a raw digest slice once at a request or persistence boundary.
            pub fn try_from_slice(bytes: &[u8]) -> ValidationResult<Self> {
                NonZeroDigest32::try_from_slice(bytes).map(Self)
            }

            /// Returns the validated digest bytes.
            pub const fn as_bytes(&self) -> &[u8; DIGEST32_LENGTH] {
                self.0.as_bytes()
            }

            /// Consumes the value and returns the validated digest bytes.
            pub const fn into_bytes(self) -> [u8; DIGEST32_LENGTH] {
                self.0.into_bytes()
            }
        }

        impl TryFrom<[u8; DIGEST32_LENGTH]> for $name {
            type Error = ValidationError;

            fn try_from(bytes: [u8; DIGEST32_LENGTH]) -> Result<Self, Self::Error> {
                Self::new(bytes)
            }
        }

        impl TryFrom<&[u8]> for $name {
            type Error = ValidationError;

            fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
                Self::try_from_slice(bytes)
            }
        }

        impl AsRef<[u8; DIGEST32_LENGTH]> for $name {
            fn as_ref(&self) -> &[u8; DIGEST32_LENGTH] {
                self.as_bytes()
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(
                    stringify!($name),
                    "([validated public digest])"
                ))
            }
        }
    };
}

define_digest_type!(
    /// Digest of one complete canonical circuit artifact.
    ///
    /// The private field prevents raw construction, while the distinct type
    /// prevents this digest from being supplied for another artifact role.
    ///
    /// ```compile_fail
    /// use ed25519_yao::CircuitDigest32;
    ///
    /// let _digest = CircuitDigest32([1_u8; 32]);
    /// ```
    CircuitDigest32
);

define_digest_type!(
    /// Digest of the compiler version and parameters used for an artifact.
    CompilerDigest32
);

define_digest_type!(
    /// Digest of the canonical source intermediate representation.
    SourceIrDigest32
);

define_digest_type!(
    /// Digest of the compact gate schedule.
    ScheduleDigest32
);

define_digest_type!(
    /// Digest of the constants embedded in a circuit artifact.
    ConstantsDigest32
);

define_digest_type!(
    /// Digest of the circuit's fixed input schema.
    InputSchemaDigest32
);

define_digest_type!(
    /// Digest of the activation circuit's fixed output schema.
    ActivationOutputSchemaDigest32
);

define_digest_type!(
    /// Digest of the export circuit's fixed output schema.
    ExportOutputSchemaDigest32
);

macro_rules! define_computed_manifest_digest_type {
    ($(#[$metadata:meta])* $name:ident) => {
        $(#[$metadata])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name([u8; DIGEST32_LENGTH]);

        impl $name {
            pub(crate) const fn from_computed_bytes(bytes: [u8; DIGEST32_LENGTH]) -> Self {
                Self(bytes)
            }

            /// Returns the internally computed SHA-256 digest bytes.
            pub const fn as_bytes(&self) -> &[u8; DIGEST32_LENGTH] {
                &self.0
            }

            /// Consumes the value and returns the internally computed digest bytes.
            pub const fn into_bytes(self) -> [u8; DIGEST32_LENGTH] {
                self.0
            }
        }

        impl AsRef<[u8; DIGEST32_LENGTH]> for $name {
            fn as_ref(&self) -> &[u8; DIGEST32_LENGTH] {
                self.as_bytes()
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(
                    stringify!($name),
                    "([internally computed SHA-256 digest])"
                ))
            }
        }
    };
}

define_computed_manifest_digest_type!(
    /// Canonical SHA-256 identity of a draft activation manifest.
    ///
    /// Only `DraftActivationCircuitManifest` can construct this value.
    ///
    /// ```compile_fail
    /// use ed25519_yao::DraftActivationManifestDigest32;
    ///
    /// let _caller_supplied = DraftActivationManifestDigest32([1_u8; 32]);
    /// ```
    DraftActivationManifestDigest32
);

define_computed_manifest_digest_type!(
    /// Canonical SHA-256 identity of a draft export manifest.
    ///
    /// Only `DraftExportCircuitManifest` can construct this value.
    DraftExportManifestDigest32
);
