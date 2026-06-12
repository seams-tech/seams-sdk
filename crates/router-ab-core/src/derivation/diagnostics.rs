use crate::derivation::error::{RedactedDiagnostic, RouterAbDerivationError};

/// Returns redacted diagnostic metadata for an error.
pub fn redacted_diagnostic(error: &RouterAbDerivationError) -> RedactedDiagnostic {
    error
        .diagnostic()
        .cloned()
        .unwrap_or_else(|| RedactedDiagnostic::new(error.code()))
}
