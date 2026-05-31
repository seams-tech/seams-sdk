use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcdsaHssErrorCode {
    InvalidInput,
    InvalidLength,
    DecodeError,
    CryptoError,
    Utf8Error,
    Internal,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcdsaHssError {
    pub code: EcdsaHssErrorCode,
    pub message: String,
}

impl EcdsaHssError {
    pub fn new(code: EcdsaHssErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn invalid_input(message: impl Into<String>) -> Self {
        Self::new(EcdsaHssErrorCode::InvalidInput, message)
    }

    pub fn invalid_length(message: impl Into<String>) -> Self {
        Self::new(EcdsaHssErrorCode::InvalidLength, message)
    }

    pub fn decode_error(message: impl Into<String>) -> Self {
        Self::new(EcdsaHssErrorCode::DecodeError, message)
    }

    pub fn crypto_error(message: impl Into<String>) -> Self {
        Self::new(EcdsaHssErrorCode::CryptoError, message)
    }

    pub fn utf8_error(message: impl Into<String>) -> Self {
        Self::new(EcdsaHssErrorCode::Utf8Error, message)
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(EcdsaHssErrorCode::Internal, message)
    }
}

impl fmt::Display for EcdsaHssError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for EcdsaHssError {}

pub type EcdsaHssResult<T> = Result<T, EcdsaHssError>;
