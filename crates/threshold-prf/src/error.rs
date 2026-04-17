use core::fmt;

/// Result type used by the threshold PRF crate.
pub type ThresholdPrfResult<T> = Result<T, ThresholdPrfError>;

/// Errors returned by threshold PRF operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ThresholdPrfError {
    /// A scalar encoding was not canonical for the suite field.
    InvalidScalarEncoding,
    /// A compressed group element did not decode to a valid suite point.
    InvalidPointEncoding,
    /// A serialized PRF partial did not match the fixed wire format.
    InvalidPartialEncoding,
    /// A serialized signing-root share did not match the fixed wire format.
    InvalidShareEncoding,
    /// A secret scalar was zero where the protocol requires non-zero material.
    ZeroScalar,
    /// The share id is outside the supported 2-of-3 signing-root range.
    InvalidShareId,
    /// The operation received the wrong number of shares or partials.
    InvalidThresholdSubset,
    /// The operation received the same share id more than once.
    DuplicateShareId,
    /// A partial was produced for a different PRF context.
    ContextMismatch,
    /// A transcript field exceeded its fixed length-prefix capacity.
    TranscriptLengthOverflow,
    /// A root-share commitment did not match its fixed wire format.
    InvalidCommitmentEncoding,
    /// A DLEQ proof did not match its fixed wire format.
    InvalidDleqProofEncoding,
    /// A DLEQ proof failed verification.
    InvalidDleqProof,
}

impl fmt::Display for ThresholdPrfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidScalarEncoding => f.write_str("invalid scalar encoding"),
            Self::InvalidPointEncoding => f.write_str("invalid point encoding"),
            Self::InvalidPartialEncoding => f.write_str("invalid threshold PRF partial encoding"),
            Self::InvalidShareEncoding => {
                f.write_str("invalid threshold PRF signing-root share encoding")
            }
            Self::ZeroScalar => f.write_str("zero scalar is not valid threshold PRF material"),
            Self::InvalidShareId => f.write_str("share id must be one of 1, 2, or 3"),
            Self::InvalidThresholdSubset => {
                f.write_str("threshold operation requires exactly two shares")
            }
            Self::DuplicateShareId => {
                f.write_str("threshold operation received duplicate share ids")
            }
            Self::ContextMismatch => {
                f.write_str("threshold PRF partial context does not match combine context")
            }
            Self::TranscriptLengthOverflow => {
                f.write_str("threshold PRF transcript field length overflow")
            }
            Self::InvalidCommitmentEncoding => {
                f.write_str("invalid threshold PRF share commitment encoding")
            }
            Self::InvalidDleqProofEncoding => {
                f.write_str("invalid threshold PRF DLEQ proof encoding")
            }
            Self::InvalidDleqProof => f.write_str("invalid threshold PRF DLEQ proof"),
        }
    }
}

impl std::error::Error for ThresholdPrfError {}
