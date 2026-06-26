use crate::derivation::{Role, RootShareEpoch};
use serde::{Deserialize, Serialize};

use crate::protocol::error::RouterAbProtocolResult;
use crate::protocol::gate::{ExpensiveWorkGateDecisionV1, ExpensiveWorkKindV1};
use crate::protocol::identity::SignerIdentityV1;
use crate::protocol::payload::AbPeerMessageVerifyingKeyV1;
use crate::protocol::wire::WireMessageV1;

/// Audit event emitted by platform-agnostic engines.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AuditEventV1 {
    /// Router expensive-work gate decision.
    GateDecision {
        /// Lifecycle id.
        lifecycle_id: String,
        /// Protected work class.
        work_kind: ExpensiveWorkKindV1,
        /// Gate decision.
        decision: ExpensiveWorkGateDecisionV1,
    },
    /// Router ECDSA-HSS explicit export decision.
    EcdsaHssExplicitExportDecision {
        /// Router A/B operation kind.
        operation: String,
        /// Stable export request id.
        request_id: String,
        /// Export request digest encoded as unpadded base64url.
        request_digest_b64u: String,
        /// Wallet id that owns the exported key.
        wallet_id: String,
        /// Account id authorized by the Router lifecycle scope.
        account_id: String,
        /// Session id authorized by the Router lifecycle scope.
        session_id: String,
        /// Selected SigningWorker/server id.
        selected_server_id: String,
        /// SDK-owned application binding digest encoded as unpadded base64url.
        application_binding_digest_b64u: String,
        /// Export authorization digest encoded as unpadded base64url.
        export_authorization_digest_b64u: String,
        /// Router decision.
        decision: EcdsaHssExplicitExportAuditDecisionV1,
        /// Stable reason code for the decision.
        reason_code: String,
    },
}

/// Sanitized ECDSA-HSS explicit export audit decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EcdsaHssExplicitExportAuditDecisionV1 {
    /// Export material was forwarded to the authorized client recipient.
    Forwarded,
    /// Router admission stopped the export before Deriver dispatch.
    Stopped,
    /// Router rejected the export before completion.
    Rejected,
}

/// Host-provided clock.
pub trait Clock {
    /// Returns Unix time in milliseconds.
    fn now_unix_ms(&self) -> u64;
}

/// Host-provided CSPRNG.
pub trait Csprng {
    /// Fills the output buffer with cryptographic randomness.
    fn fill_random(&mut self, out: &mut [u8]) -> RouterAbProtocolResult<()>;
}

/// Host-provided signer identity and key access.
pub trait SignerKeyStore {
    /// Returns the canonical signer identity for a role.
    fn signer_identity(&self, role: Role) -> RouterAbProtocolResult<String>;

    /// Returns the Ed25519 verifying key for an authenticated A/B peer signer.
    fn signer_verifying_key(
        &self,
        signer: &SignerIdentityV1,
    ) -> RouterAbProtocolResult<AbPeerMessageVerifyingKeyV1>;
}

/// Host-provided signing-root share storage access.
pub trait SigningRootShareStore {
    /// Returns whether the host has local root-share material for role/epoch.
    fn has_root_share(&self, role: Role, epoch: &RootShareEpoch) -> RouterAbProtocolResult<bool>;
}

/// Host-provided peer transport.
pub trait PeerTransport {
    /// Sends a canonical wire message and returns the peer response.
    fn send_peer_message(&self, message: WireMessageV1) -> RouterAbProtocolResult<WireMessageV1>;
}

/// Host-provided audit sink.
pub trait AuditSink {
    /// Records an audit event.
    fn record_audit_event(&self, event: AuditEventV1) -> RouterAbProtocolResult<()>;
}
