//! Verus mirror for the true-blind role-local boundary contract.
//!
//! This module tracks the settled Lean boundary shape in Rust-shaped terms before
//! the production Rust rewrite lands.

use vstd::prelude::*;

use crate::shared::derivation::Bytes32;

verus! {

pub type Bytes20 = [u8; 20];
pub type Bytes33 = [u8; 33];

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum TrueBlindOperationKind {
    NonExport,
    ExplicitExport,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct TrueBlindPublicIdentity {
    pub context_binding32: Bytes32,
    pub derivation_client_share_public_key33: Bytes33,
    pub relayer_public_key33: Bytes33,
    pub threshold_public_key33: Bytes33,
    pub threshold_ethereum_address20: Bytes20,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct TrueBlindPublicTranscript {
    pub context_binding32: Bytes32,
    pub derivation_client_share_public_key33: Bytes33,
    pub relayer_public_key33: Bytes33,
    pub threshold_public_key33: Bytes33,
    pub threshold_ethereum_address20: Bytes20,
    pub operation: TrueBlindOperationKind,
    pub transcript_digest32: Bytes32,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct TrueBlindClientBootstrapWire {
    pub context_binding32: Bytes32,
    pub derivation_client_share_public_key33: Bytes33,
    pub transcript_digest32: Bytes32,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct TrueBlindServerBootstrapWire {
    pub public_transcript: TrueBlindPublicTranscript,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct TrueBlindClientRetainedState {
    pub client_share32: Bytes32,
    pub public_identity: TrueBlindPublicIdentity,
    pub accepted_transcript: TrueBlindPublicTranscript,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct TrueBlindServerRetainedState {
    pub relayer_share32: Bytes32,
    pub public_identity: TrueBlindPublicIdentity,
    pub accepted_transcript: TrueBlindPublicTranscript,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct TrueBlindExplicitExportWire {
    pub export_relayer_share32: Bytes32,
    pub public_transcript: TrueBlindPublicTranscript,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct TrueBlindExplicitExportAuthorization {
    pub public_identity: TrueBlindPublicIdentity,
    pub export_transcript: TrueBlindPublicTranscript,
    pub authorization_digest32: Bytes32,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct TrueBlindAuthorizedExplicitExportWire {
    pub authorization: TrueBlindExplicitExportAuthorization,
    pub wire: TrueBlindExplicitExportWire,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum TrueBlindWireEnvelope {
    ClientBootstrap(TrueBlindClientBootstrapWire),
    ServerBootstrap(TrueBlindServerBootstrapWire),
    ExplicitExport(TrueBlindAuthorizedExplicitExportWire),
}

pub open spec fn public_identity_matches_transcript_spec(
    public_identity: TrueBlindPublicIdentity,
    transcript: TrueBlindPublicTranscript,
) -> bool {
    &&& transcript.context_binding32 == public_identity.context_binding32
    &&& transcript.derivation_client_share_public_key33 == public_identity.derivation_client_share_public_key33
    &&& transcript.relayer_public_key33 == public_identity.relayer_public_key33
    &&& transcript.threshold_public_key33 == public_identity.threshold_public_key33
    &&& transcript.threshold_ethereum_address20
        == public_identity.threshold_ethereum_address20
}

pub open spec fn export_authorization_binds_public_identity_spec(
    authorization: TrueBlindExplicitExportAuthorization,
) -> bool {
    &&& public_identity_matches_transcript_spec(
        authorization.public_identity,
        authorization.export_transcript,
    )
    &&& authorization.export_transcript.operation == TrueBlindOperationKind::ExplicitExport
}

pub open spec fn export_authorization_matches_wire_spec(
    authorization: TrueBlindExplicitExportAuthorization,
    wire: TrueBlindExplicitExportWire,
) -> bool {
    &&& authorization.export_transcript == wire.public_transcript
    &&& export_authorization_binds_public_identity_spec(authorization)
}

pub open spec fn authorized_export_wire_is_valid_spec(
    wire: TrueBlindAuthorizedExplicitExportWire,
) -> bool {
    export_authorization_matches_wire_spec(wire.authorization, wire.wire)
}

pub open spec fn client_state_matches_server_state_spec(
    client_state: TrueBlindClientRetainedState,
    server_state: TrueBlindServerRetainedState,
) -> bool {
    &&& client_state.public_identity == server_state.public_identity
    &&& client_state.accepted_transcript.context_binding32
        == server_state.accepted_transcript.context_binding32
}

pub open spec fn client_state_matches_export_authorization_spec(
    client_state: TrueBlindClientRetainedState,
    authorization: TrueBlindExplicitExportAuthorization,
) -> bool {
    &&& client_state.public_identity == authorization.public_identity
    &&& client_state.accepted_transcript.context_binding32
        == authorization.export_transcript.context_binding32
}

pub open spec fn wire_envelope_operation_spec(
    wire: TrueBlindWireEnvelope,
) -> TrueBlindOperationKind {
    match wire {
        TrueBlindWireEnvelope::ClientBootstrap(_) => TrueBlindOperationKind::NonExport,
        TrueBlindWireEnvelope::ServerBootstrap(_) => TrueBlindOperationKind::NonExport,
        TrueBlindWireEnvelope::ExplicitExport(_) => TrueBlindOperationKind::ExplicitExport,
    }
}

pub open spec fn wire_envelope_carries_client_root_spec(
    _wire: TrueBlindWireEnvelope,
) -> bool {
    false
}

pub open spec fn wire_envelope_carries_client_share_spec(
    _wire: TrueBlindWireEnvelope,
) -> bool {
    false
}

pub open spec fn wire_envelope_carries_canonical_scalar_spec(
    _wire: TrueBlindWireEnvelope,
) -> bool {
    false
}

pub open spec fn wire_envelope_carries_relayer_export_share_spec(
    wire: TrueBlindWireEnvelope,
) -> bool {
    match wire {
        TrueBlindWireEnvelope::ClientBootstrap(_) => false,
        TrueBlindWireEnvelope::ServerBootstrap(_) => false,
        TrueBlindWireEnvelope::ExplicitExport(_) => true,
    }
}

pub uninterp spec fn scalar_add_mod_order_spec(left: Bytes32, right: Bytes32) -> Bytes32;

pub open spec fn bound_signing_session_canonical_scalar_spec(
    client_state: TrueBlindClientRetainedState,
    server_state: TrueBlindServerRetainedState,
) -> Bytes32 {
    scalar_add_mod_order_spec(client_state.client_share32, server_state.relayer_share32)
}

pub proof fn public_identity_matches_transcript_implies_context_binding(
    public_identity: TrueBlindPublicIdentity,
    transcript: TrueBlindPublicTranscript,
)
    requires
        public_identity_matches_transcript_spec(public_identity, transcript),
    ensures
        transcript.context_binding32 == public_identity.context_binding32,
{
}

pub proof fn export_authorization_requires_explicit_export_operation(
    authorization: TrueBlindExplicitExportAuthorization,
)
    requires
        export_authorization_binds_public_identity_spec(authorization),
    ensures
        authorization.export_transcript.operation == TrueBlindOperationKind::ExplicitExport,
{
}

pub proof fn valid_authorized_export_wire_binds_transcript_to_authorization(
    wire: TrueBlindAuthorizedExplicitExportWire,
)
    requires
        authorized_export_wire_is_valid_spec(wire),
    ensures
        wire.authorization.export_transcript == wire.wire.public_transcript,
        export_authorization_binds_public_identity_spec(wire.authorization),
{
}

pub proof fn wire_envelope_excludes_client_root(
    wire: TrueBlindWireEnvelope,
)
    ensures
        !wire_envelope_carries_client_root_spec(wire),
{
}

pub proof fn wire_envelope_excludes_client_share(
    wire: TrueBlindWireEnvelope,
)
    ensures
        !wire_envelope_carries_client_share_spec(wire),
{
}

pub proof fn wire_envelope_excludes_canonical_scalar(
    wire: TrueBlindWireEnvelope,
)
    ensures
        !wire_envelope_carries_canonical_scalar_spec(wire),
{
}

pub proof fn non_export_wire_cannot_carry_relayer_export_share(
    wire: TrueBlindWireEnvelope,
)
    requires
        wire_envelope_operation_spec(wire) == TrueBlindOperationKind::NonExport,
    ensures
        !wire_envelope_carries_relayer_export_share_spec(wire),
{
}

pub proof fn relayer_export_share_requires_explicit_export_wire(
    wire: TrueBlindWireEnvelope,
)
    requires
        wire_envelope_carries_relayer_export_share_spec(wire),
    ensures
        wire_envelope_operation_spec(wire) == TrueBlindOperationKind::ExplicitExport,
{
}

pub proof fn client_server_state_match_implies_same_public_identity(
    client_state: TrueBlindClientRetainedState,
    server_state: TrueBlindServerRetainedState,
)
    requires
        client_state_matches_server_state_spec(client_state, server_state),
    ensures
        client_state.public_identity == server_state.public_identity,
{
}

pub proof fn client_server_state_match_implies_same_context_binding(
    client_state: TrueBlindClientRetainedState,
    server_state: TrueBlindServerRetainedState,
)
    requires
        client_state_matches_server_state_spec(client_state, server_state),
    ensures
        client_state.accepted_transcript.context_binding32
            == server_state.accepted_transcript.context_binding32,
{
}

pub proof fn different_public_identity_prevents_bound_signing_session(
    client_state: TrueBlindClientRetainedState,
    server_state: TrueBlindServerRetainedState,
)
    requires
        client_state.public_identity != server_state.public_identity,
    ensures
        !client_state_matches_server_state_spec(client_state, server_state),
{
}

pub proof fn different_context_prevents_bound_signing_session(
    client_state: TrueBlindClientRetainedState,
    server_state: TrueBlindServerRetainedState,
)
    requires
        client_state.accepted_transcript.context_binding32
            != server_state.accepted_transcript.context_binding32,
    ensures
        !client_state_matches_server_state_spec(client_state, server_state),
{
}

pub proof fn client_export_authorization_match_implies_same_public_identity(
    client_state: TrueBlindClientRetainedState,
    authorization: TrueBlindExplicitExportAuthorization,
)
    requires
        client_state_matches_export_authorization_spec(client_state, authorization),
    ensures
        client_state.public_identity == authorization.public_identity,
{
}

pub proof fn client_export_authorization_match_implies_same_context_binding(
    client_state: TrueBlindClientRetainedState,
    authorization: TrueBlindExplicitExportAuthorization,
)
    requires
        client_state_matches_export_authorization_spec(client_state, authorization),
    ensures
        client_state.accepted_transcript.context_binding32
            == authorization.export_transcript.context_binding32,
{
}

}
