use router_ab_core::{RouterAbProtocolError, RouterAbProtocolErrorCode, RouterAbProtocolResult};

pub(crate) fn require_non_empty(field: &str, value: &str) -> RouterAbProtocolResult<()> {
    if value.is_empty() {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::EmptyField,
            format!("{field} must not be empty"),
        ));
    }
    Ok(())
}

pub(crate) fn require_non_empty_vec<T>(field: &str, value: &[T]) -> RouterAbProtocolResult<()> {
    if value.is_empty() {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::EmptyField,
            format!("{field} must not be empty"),
        ));
    }
    Ok(())
}

pub(crate) fn require_no_ascii_whitespace(field: &str, value: &str) -> RouterAbProtocolResult<()> {
    if value.bytes().any(|byte| byte.is_ascii_whitespace()) {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("{field} must not contain ASCII whitespace"),
        ));
    }
    Ok(())
}

pub(crate) fn require_positive_ms(field: &str, value: u64) -> RouterAbProtocolResult<()> {
    if value == 0 {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidTimeRange,
            format!("{field} must be greater than zero"),
        ));
    }
    Ok(())
}
