use std::fmt::{Display, Formatter};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtoError {
    Decode(String),
    InvalidInput(String),
}

impl Display for ProtoError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Decode(message) => write!(f, "decode error: {message}"),
            Self::InvalidInput(message) => write!(f, "invalid input: {message}"),
        }
    }
}

impl std::error::Error for ProtoError {}

pub type ProtoResult<T> = Result<T, ProtoError>;
