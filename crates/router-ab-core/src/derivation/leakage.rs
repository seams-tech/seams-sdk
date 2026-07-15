/// Stable identifier for a leakage-analysis question.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeakageQuestionId {
    /// Can one server role reconstruct joined `d`?
    JoinedDServerSide,
    /// Can one server role reconstruct joined `a`?
    JoinedAServerSide,
    /// Can one server role reconstruct joined `x_client_base`?
    JoinedXClientBaseServerSide,
    /// Can the client reconstruct joined server material?
    JoinedServerMaterialClientSide,
    /// Are opened values role-scoped and transcript-bound?
    OpenedValueScope,
}

/// Leakage-analysis question for the fixed ECDSA threshold-PRF construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeakageQuestion {
    /// Stable question identifier.
    pub id: LeakageQuestionId,
    /// Human-readable question text.
    pub question: &'static str,
    /// Release-gate requirement.
    pub release_gate: &'static str,
}

/// Returns the initial leakage-analysis checklist.
pub fn default_leakage_questions() -> Vec<LeakageQuestion> {
    vec![
        LeakageQuestion {
            id: LeakageQuestionId::JoinedDServerSide,
            question: "Does any single server-side role hold enough state to reconstruct joined d?",
            release_gate: "answer must be no for the fixed construction",
        },
        LeakageQuestion {
            id: LeakageQuestionId::JoinedAServerSide,
            question: "Does any single server-side role hold enough state to reconstruct joined a?",
            release_gate: "answer must be no for the fixed construction",
        },
        LeakageQuestion {
            id: LeakageQuestionId::JoinedXClientBaseServerSide,
            question: "Does any single server-side role hold enough state to reconstruct joined x_client_base?",
            release_gate: "answer must be no for the fixed construction",
        },
        LeakageQuestion {
            id: LeakageQuestionId::JoinedServerMaterialClientSide,
            question: "Does the client hold enough state to reconstruct joined y_server or tau_server?",
            release_gate: "answer must be no for the fixed construction",
        },
        LeakageQuestion {
            id: LeakageQuestionId::OpenedValueScope,
            question: "Are opened values limited to x_client_base for the client and x_server_base for the server?",
            release_gate: "answer must be yes for the fixed construction",
        },
    ]
}
