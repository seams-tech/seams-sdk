use router_ab_core::{
    redacted_diagnostic, RedactedDiagnostic, RouterAbDerivationError, RouterAbDerivationErrorCode,
};

#[test]
fn redacted_diagnostic_defaults_to_error_code() {
    let err = RouterAbDerivationError::new(
        RouterAbDerivationErrorCode::TranscriptMismatch,
        "transcript mismatch",
    );

    let diagnostic = redacted_diagnostic(&err);

    assert_eq!(
        diagnostic.code,
        RouterAbDerivationErrorCode::TranscriptMismatch
    );
    assert!(diagnostic.ceremony_id.is_none());
    assert!(diagnostic.transcript_digest.is_none());
}

#[test]
fn redacted_diagnostic_preserves_public_metadata() {
    let mut diagnostic = RedactedDiagnostic::new(RouterAbDerivationErrorCode::ReplayMismatch);
    diagnostic.ceremony_id = Some("ceremony-1".to_owned());

    let err = RouterAbDerivationError::with_diagnostic(
        RouterAbDerivationErrorCode::ReplayMismatch,
        "replay mismatch",
        diagnostic,
    );

    let diagnostic = redacted_diagnostic(&err);

    assert_eq!(diagnostic.code, RouterAbDerivationErrorCode::ReplayMismatch);
    assert_eq!(diagnostic.ceremony_id.as_deref(), Some("ceremony-1"));
}
