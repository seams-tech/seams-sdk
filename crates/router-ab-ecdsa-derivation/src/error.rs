use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouterAbEcdsaDerivationErrorCode {
    InvalidInput,
    InvalidLength,
    DecodeError,
    CryptoError,
    Utf8Error,
    Internal,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouterAbEcdsaDerivationError {
    pub code: RouterAbEcdsaDerivationErrorCode,
    pub message: String,
}

impl RouterAbEcdsaDerivationError {
    pub fn new(code: RouterAbEcdsaDerivationErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn invalid_input(message: impl Into<String>) -> Self {
        Self::new(RouterAbEcdsaDerivationErrorCode::InvalidInput, message)
    }

    pub fn invalid_length(message: impl Into<String>) -> Self {
        Self::new(RouterAbEcdsaDerivationErrorCode::InvalidLength, message)
    }

    pub fn decode_error(message: impl Into<String>) -> Self {
        Self::new(RouterAbEcdsaDerivationErrorCode::DecodeError, message)
    }

    pub fn crypto_error(message: impl Into<String>) -> Self {
        Self::new(RouterAbEcdsaDerivationErrorCode::CryptoError, message)
    }

    pub fn utf8_error(message: impl Into<String>) -> Self {
        Self::new(RouterAbEcdsaDerivationErrorCode::Utf8Error, message)
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(RouterAbEcdsaDerivationErrorCode::Internal, message)
    }
}

impl fmt::Display for RouterAbEcdsaDerivationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for RouterAbEcdsaDerivationError {}

pub type RouterAbEcdsaDerivationResult<T> = Result<T, RouterAbEcdsaDerivationError>;
