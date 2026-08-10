//! Feature-independent wire types shared by the Cloudflare and native local adapters.

use router_ab_core::{
    Ed25519YaoEncryptedInputV1, Ed25519YaoExecutionIdV1, Ed25519YaoInputPairBindingV1,
    Ed25519YaoLaneJobV1, Ed25519YaoRoleReadinessReceiptV1, Ed25519YaoRoleStartAcceptanceV1,
    RouterAbProtocolError, RouterAbProtocolErrorCode, RouterEd25519YaoBurnReasonV1,
    RouterEd25519YaoExecuteFailureCodeV1,
};
use router_ab_ed25519_yao::Ed25519YaoRoleExecutionV1;
use serde::{Deserialize, Serialize};

/// Family-specific public context retained by each role for exact input opening.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "family", rename_all = "snake_case", deny_unknown_fields)]
pub enum CloudflareEd25519YaoPairWorkV1 {
    /// Registration, recovery, or export uses the ceremony binding directly.
    Ceremony,
    /// Lane inputs additionally authenticate the complete admitted job in HPKE AAD.
    Lane { job: Ed25519YaoLaneJobV1 },
}

/// Exact pair and role envelope sent to one private prepare-pair route.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareEd25519YaoPairPrepareRequestV1 {
    pub pair_binding: Ed25519YaoInputPairBindingV1,
    pub work: CloudflareEd25519YaoPairWorkV1,
    pub input: Ed25519YaoEncryptedInputV1,
}

/// Exact pair, encrypted A input, and both readiness receipts sent to the A
/// execute-pair route.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareEd25519YaoPairExecuteRequestV1 {
    pub pair_binding: Ed25519YaoInputPairBindingV1,
    pub work: CloudflareEd25519YaoPairWorkV1,
    pub input: Ed25519YaoEncryptedInputV1,
    pub local_receipt: Ed25519YaoRoleReadinessReceiptV1,
    pub peer_receipt: Ed25519YaoRoleReadinessReceiptV1,
}

/// A's sealed execution plus B's opaque, already-persisted sealed execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareEd25519YaoPairExecuteResponseV1 {
    pub deriver_a_execution: Ed25519YaoRoleExecutionV1,
    pub deriver_b_sealed_execution_json: String,
}

/// Pair start confirmation sent after Deriver B accepted the exact execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareEd25519YaoPairStartRequestV1 {
    pub pair_binding: Ed25519YaoInputPairBindingV1,
    pub execution_id: Ed25519YaoExecutionIdV1,
    pub acceptance: Ed25519YaoRoleStartAcceptanceV1,
}

/// Exact pair lookup sent to a role status or burn route.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareEd25519YaoPairLookupRequestV1 {
    pub session: [u8; 32],
    pub pair_digest: [u8; 32],
}

/// Sanitized role-local state returned only to the MPC Router for exact replay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum CloudflareEd25519YaoPairStatusResponseV1 {
    Missing {
        session: [u8; 32],
        pair_digest: [u8; 32],
    },
    Prepared {
        session: [u8; 32],
        pair_digest: [u8; 32],
    },
    Running {
        session: [u8; 32],
        pair_digest: [u8; 32],
    },
    Completed {
        execution: Box<Ed25519YaoRoleExecutionV1>,
    },
    Burned {
        session: [u8; 32],
        pair_digest: [u8; 32],
    },
    Expired {
        session: [u8; 32],
        pair_digest: [u8; 32],
    },
}

/// Sanitized role failure returned by a private pair route.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum CloudflareEd25519YaoRoleFailureResponseV1 {
    RecoverableFailure {
        code: RouterEd25519YaoExecuteFailureCodeV1,
        retry_after_ms: u64,
    },
    Rejected {
        code: RouterEd25519YaoExecuteFailureCodeV1,
    },
    Burned {
        reason: RouterEd25519YaoBurnReasonV1,
    },
}

impl CloudflareEd25519YaoRoleFailureResponseV1 {
    /// Converts a role-local protocol error into a sanitized result class.
    pub fn from_protocol_error(
        error: &RouterAbProtocolError,
    ) -> CloudflareEd25519YaoRoleFailureResponseV1 {
        if matches!(
            error.code(),
            RouterAbProtocolErrorCode::ExpiredLocalRequest
                | RouterAbProtocolErrorCode::PairPreparationExpired
        ) {
            return Self::RecoverableFailure {
                code: RouterEd25519YaoExecuteFailureCodeV1::CeremonyExpired,
                retry_after_ms: 1_000,
            };
        }
        if error.code() == RouterAbProtocolErrorCode::ConflictingPair {
            return Self::Rejected {
                code: RouterEd25519YaoExecuteFailureCodeV1::ConflictingPair,
            };
        }
        if error.code() == RouterAbProtocolErrorCode::MissingPairPreparation {
            return Self::Rejected {
                code: RouterEd25519YaoExecuteFailureCodeV1::MissingPreparation,
            };
        }
        if matches!(
            error.code(),
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig
                | RouterAbProtocolErrorCode::MissingLocalBinding
                | RouterAbProtocolErrorCode::ForbiddenLocalBinding
        ) {
            return Self::RecoverableFailure {
                code: RouterEd25519YaoExecuteFailureCodeV1::ServiceUnavailable,
                retry_after_ms: 1_000,
            };
        }
        Self::Rejected {
            code: RouterEd25519YaoExecuteFailureCodeV1::TerminalRoleFailure,
        }
    }
}
