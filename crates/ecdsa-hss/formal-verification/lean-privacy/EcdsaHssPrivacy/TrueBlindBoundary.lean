import EcdsaHssPrivacy.TrueBlind

namespace EcdsaHssPrivacy.TrueBlind

noncomputable section

structure ClientBootstrapWire where
  contextBinding32 : Bytes32
  clientPublicKey33 : Bytes33
  transcriptDigest32 : Bytes32
  deriving DecidableEq, Repr

structure ServerBootstrapWire where
  publicTranscript : PublicTranscript
  deriving DecidableEq, Repr

structure RoleLocalClientRetainedState where
  clientShare : ClientDerivedShare
  publicIdentity : PublicIdentity
  acceptedTranscript : PublicTranscript
  deriving DecidableEq, Repr

structure RoleLocalServerRetainedState where
  serverShare : ServerDerivedShare
  publicIdentity : PublicIdentity
  acceptedTranscript : PublicTranscript
  deriving DecidableEq, Repr

structure ExplicitExportWire where
  exportRelayerShare : Scalar
  exportRelayerShare32 : Bytes32
  publicTranscript : PublicTranscript
  deriving DecidableEq, Repr

structure ExplicitExportAuthorization where
  publicIdentity : PublicIdentity
  exportTranscript : PublicTranscript
  authorizationDigest32 : Bytes32
  deriving DecidableEq, Repr

structure AuthorizedExplicitExportWire where
  authorization : ExplicitExportAuthorization
  wire : ExplicitExportWire
  deriving DecidableEq, Repr

structure ClientExportReconstruction where
  clientShare : ClientDerivedShare
  exportRelayerShare32 : Bytes32
  reconstructedCanonicalX : Scalar
  reconstructedCanonicalX32 : Bytes32
  publicIdentity : PublicIdentity
  deriving DecidableEq, Repr

inductive RoleLocalWireEnvelope where
  | clientBootstrap : ClientBootstrapWire → RoleLocalWireEnvelope
  | serverBootstrap : ServerBootstrapWire → RoleLocalWireEnvelope
  | explicitExport : AuthorizedExplicitExportWire → RoleLocalWireEnvelope
  deriving DecidableEq, Repr

axiom exportAuthorizationDigest : PublicIdentity → PublicTranscript → Bytes32

def publicIdentityMatchesTranscript
    (publicIdentity : PublicIdentity)
    (transcript : PublicTranscript) : Prop :=
  transcript.contextBinding32 = publicIdentity.contextBinding32 ∧
  transcript.clientPublicKey33 = publicIdentity.clientPublicKey33 ∧
  transcript.relayerPublicKey33 = publicIdentity.relayerPublicKey33 ∧
  transcript.thresholdPublicKey33 = publicIdentity.thresholdPublicKey33 ∧
  transcript.thresholdEthereumAddress20 =
    publicIdentity.thresholdEthereumAddress20

def clientBootstrapWireOfState (state : ExecutionState) : ClientBootstrapWire :=
  {
    contextBinding32 := state.publicIdentity.contextBinding32
    clientPublicKey33 := state.clientShare.clientPublicKey33
    transcriptDigest32 :=
      publicTranscriptDigest state.publicIdentity OperationKind.nonExport
  }

def serverBootstrapWireOfState (state : ExecutionState) : ServerBootstrapWire :=
  {
    publicTranscript :=
      publicTranscriptOfIdentity state.publicIdentity OperationKind.nonExport
  }

def roleLocalClientRetainedStateOfState
    (state : ExecutionState) : RoleLocalClientRetainedState :=
  {
    clientShare := state.clientShare
    publicIdentity := state.publicIdentity
    acceptedTranscript :=
      publicTranscriptOfIdentity state.publicIdentity OperationKind.nonExport
  }

def roleLocalServerRetainedStateOfState
    (state : ExecutionState) : RoleLocalServerRetainedState :=
  {
    serverShare := state.serverShare
    publicIdentity := state.publicIdentity
    acceptedTranscript :=
      publicTranscriptOfIdentity state.publicIdentity OperationKind.nonExport
  }

def explicitExportWireOfState (state : ExecutionState) : ExplicitExportWire :=
  {
    exportRelayerShare := state.serverShare.xRelayer
    exportRelayerShare32 := state.serverShare.xRelayer32
    publicTranscript :=
      publicTranscriptOfIdentity state.publicIdentity OperationKind.explicitExport
  }

def explicitExportAuthorizationOfState
    (state : ExecutionState) : ExplicitExportAuthorization :=
  let exportTranscript :=
    publicTranscriptOfIdentity state.publicIdentity OperationKind.explicitExport
  {
    publicIdentity := state.publicIdentity
    exportTranscript := exportTranscript
    authorizationDigest32 :=
      exportAuthorizationDigest state.publicIdentity exportTranscript
  }

def authorizedExplicitExportWireOfState
    (state : ExecutionState) : AuthorizedExplicitExportWire :=
  {
    authorization := explicitExportAuthorizationOfState state
    wire := explicitExportWireOfState state
  }

def roleLocalWireEnvelopeOfClientBootstrap
    (state : ExecutionState) : RoleLocalWireEnvelope :=
  .clientBootstrap (clientBootstrapWireOfState state)

def roleLocalWireEnvelopeOfServerBootstrap
    (state : ExecutionState) : RoleLocalWireEnvelope :=
  .serverBootstrap (serverBootstrapWireOfState state)

def roleLocalWireEnvelopeOfExplicitExport
    (state : ExecutionState) : RoleLocalWireEnvelope :=
  .explicitExport (authorizedExplicitExportWireOfState state)

def clientExportReconstructionFromWire
    (clientState : RoleLocalClientRetainedState)
    (wire : ExplicitExportWire) : ClientExportReconstruction :=
  let reconstructedCanonicalX :=
    scalarAdd clientState.clientShare.xClient wire.exportRelayerShare
  {
    clientShare := clientState.clientShare
    exportRelayerShare32 := wire.exportRelayerShare32
    reconstructedCanonicalX := reconstructedCanonicalX
    reconstructedCanonicalX32 := scalarToBytes32 reconstructedCanonicalX
    publicIdentity := clientState.publicIdentity
  }

def clientExportReconstructionToView
    (reconstruction : ClientExportReconstruction) : ExplicitExportClientView :=
  {
    clientShare := reconstruction.clientShare
    exportRelayerShare32 := reconstruction.exportRelayerShare32
    reconstructedCanonicalX := reconstruction.reconstructedCanonicalX
    reconstructedCanonicalX32 := reconstruction.reconstructedCanonicalX32
    publicIdentity := reconstruction.publicIdentity
  }

def clientBootstrapWireClientRoot? (_wire : ClientBootstrapWire) : Option Bytes32 :=
  none

def clientBootstrapWireClientShare? (_wire : ClientBootstrapWire) : Option Bytes32 :=
  none

def clientBootstrapWireRelayerRoot? (_wire : ClientBootstrapWire) : Option Bytes32 :=
  none

def clientBootstrapWireRelayerShare? (_wire : ClientBootstrapWire) : Option Bytes32 :=
  none

def clientBootstrapWireCanonicalX? (_wire : ClientBootstrapWire) : Option Bytes32 :=
  none

def serverBootstrapWireClientRoot? (_wire : ServerBootstrapWire) : Option Bytes32 :=
  none

def serverBootstrapWireClientShare? (_wire : ServerBootstrapWire) : Option Bytes32 :=
  none

def serverBootstrapWireRelayerRoot? (_wire : ServerBootstrapWire) : Option Bytes32 :=
  none

def serverBootstrapWireRelayerShare? (_wire : ServerBootstrapWire) : Option Bytes32 :=
  none

def serverBootstrapWireCanonicalX? (_wire : ServerBootstrapWire) : Option Bytes32 :=
  none

def clientRetainedStateRelayerRoot?
    (_state : RoleLocalClientRetainedState) : Option Bytes32 :=
  none

def clientRetainedStateRelayerShare?
    (_state : RoleLocalClientRetainedState) : Option Bytes32 :=
  none

def clientRetainedStateCanonicalX?
    (_state : RoleLocalClientRetainedState) : Option Bytes32 :=
  none

def serverRetainedStateClientRoot?
    (_state : RoleLocalServerRetainedState) : Option Bytes32 :=
  none

def serverRetainedStateClientShare?
    (_state : RoleLocalServerRetainedState) : Option Bytes32 :=
  none

def serverRetainedStateCanonicalX?
    (_state : RoleLocalServerRetainedState) : Option Bytes32 :=
  none

def serverRetainedStateRelayerShare?
    (state : RoleLocalServerRetainedState) : Option Bytes32 :=
  some state.serverShare.xRelayer32

def explicitExportWireClientRoot? (_wire : ExplicitExportWire) : Option Bytes32 :=
  none

def explicitExportWireClientShare? (_wire : ExplicitExportWire) : Option Bytes32 :=
  none

def explicitExportWireRelayerRoot? (_wire : ExplicitExportWire) : Option Bytes32 :=
  none

def explicitExportWireRelayerShare? (wire : ExplicitExportWire) : Option Bytes32 :=
  some wire.exportRelayerShare32

def explicitExportWireCanonicalX? (_wire : ExplicitExportWire) : Option Bytes32 :=
  none

def exportAuthorizationBindsPublicIdentity
    (authorization : ExplicitExportAuthorization) : Prop :=
  publicIdentityMatchesTranscript
      authorization.publicIdentity
      authorization.exportTranscript ∧
  authorization.exportTranscript.operation = OperationKind.explicitExport

def exportAuthorizationDigestMatches
    (authorization : ExplicitExportAuthorization) : Prop :=
  authorization.authorizationDigest32 =
    exportAuthorizationDigest
      authorization.publicIdentity
      authorization.exportTranscript

def validExportAuthorization
    (authorization : ExplicitExportAuthorization) : Prop :=
  exportAuthorizationBindsPublicIdentity authorization ∧
  exportAuthorizationDigestMatches authorization

def exportAuthorizationMatchesWire
    (authorization : ExplicitExportAuthorization)
    (wire : ExplicitExportWire) : Prop :=
  authorization.exportTranscript = wire.publicTranscript ∧
  exportAuthorizationBindsPublicIdentity authorization

def authorizedExplicitExportWireIsValid
    (authorizedWire : AuthorizedExplicitExportWire) : Prop :=
  exportAuthorizationMatchesWire authorizedWire.authorization authorizedWire.wire

def authorizedExplicitExportWireHasValidAuthorization
    (authorizedWire : AuthorizedExplicitExportWire) : Prop :=
  exportAuthorizationMatchesWire authorizedWire.authorization authorizedWire.wire ∧
  exportAuthorizationDigestMatches authorizedWire.authorization

def roleLocalWireEnvelopeHasValidAuthorization : RoleLocalWireEnvelope → Prop
  | .clientBootstrap _wire => True
  | .serverBootstrap _wire => True
  | .explicitExport wire =>
      authorizedExplicitExportWireHasValidAuthorization wire

def clientStateMatchesExportAuthorization
    (clientState : RoleLocalClientRetainedState)
    (authorization : ExplicitExportAuthorization) : Prop :=
  clientState.publicIdentity = authorization.publicIdentity ∧
  clientState.acceptedTranscript.contextBinding32 =
    authorization.exportTranscript.contextBinding32

def clientStateMatchesServerState
    (clientState : RoleLocalClientRetainedState)
    (serverState : RoleLocalServerRetainedState) : Prop :=
  clientState.publicIdentity = serverState.publicIdentity ∧
  clientState.acceptedTranscript.contextBinding32 =
    serverState.acceptedTranscript.contextBinding32

structure BoundRoleLocalSigningSession where
  clientState : RoleLocalClientRetainedState
  serverState : RoleLocalServerRetainedState
  clientMatchesServer :
    clientStateMatchesServerState clientState serverState

structure BoundExplicitExportSession where
  clientState : RoleLocalClientRetainedState
  exportWire : AuthorizedExplicitExportWire
  validExportWire : authorizedExplicitExportWireIsValid exportWire
  clientMatchesAuthorization :
    clientStateMatchesExportAuthorization clientState exportWire.authorization

def boundExplicitExportSessionOfState
    (state : ExecutionState) : BoundExplicitExportSession :=
  {
    clientState := roleLocalClientRetainedStateOfState state
    exportWire := authorizedExplicitExportWireOfState state
    validExportWire := by
      constructor
      · rfl
      · constructor
        · constructor
          · rfl
          constructor
          · rfl
          constructor
          · rfl
          constructor
          · rfl
          · rfl
        · rfl
    clientMatchesAuthorization := by
      constructor
      · rfl
      · rfl
  }

def boundRoleLocalSigningSessionOfState
    (state : ExecutionState) : BoundRoleLocalSigningSession :=
  {
    clientState := roleLocalClientRetainedStateOfState state
    serverState := roleLocalServerRetainedStateOfState state
    clientMatchesServer := by
      constructor
      · rfl
      · rfl
  }

def boundRoleLocalSigningSessionCanonicalScalar
    (session : BoundRoleLocalSigningSession) : Scalar :=
  scalarAdd session.clientState.clientShare.xClient
    session.serverState.serverShare.xRelayer

def clientExportReconstructionFromBoundSession
    (session : BoundExplicitExportSession) : ClientExportReconstruction :=
  clientExportReconstructionFromWire session.clientState session.exportWire.wire

def roleLocalWireOperation : RoleLocalWireEnvelope → OperationKind
  | .clientBootstrap _wire => .nonExport
  | .serverBootstrap _wire => .nonExport
  | .explicitExport _wire => .explicitExport

def roleLocalWireRelayerShare? : RoleLocalWireEnvelope → Option Bytes32
  | .clientBootstrap _wire => none
  | .serverBootstrap _wire => none
  | .explicitExport wire => explicitExportWireRelayerShare? wire.wire

def roleLocalWireCanonicalX? : RoleLocalWireEnvelope → Option Bytes32
  | .clientBootstrap wire => clientBootstrapWireCanonicalX? wire
  | .serverBootstrap wire => serverBootstrapWireCanonicalX? wire
  | .explicitExport wire => explicitExportWireCanonicalX? wire.wire

def roleLocalWireClientRoot? : RoleLocalWireEnvelope → Option Bytes32
  | .clientBootstrap wire => clientBootstrapWireClientRoot? wire
  | .serverBootstrap wire => serverBootstrapWireClientRoot? wire
  | .explicitExport wire => explicitExportWireClientRoot? wire.wire

def roleLocalWireClientShare? : RoleLocalWireEnvelope → Option Bytes32
  | .clientBootstrap wire => clientBootstrapWireClientShare? wire
  | .serverBootstrap wire => serverBootstrapWireClientShare? wire
  | .explicitExport wire => explicitExportWireClientShare? wire.wire

theorem clientBootstrapWire_excludes_client_root
    (wire : ClientBootstrapWire) :
    clientBootstrapWireClientRoot? wire = none := by
  rfl

theorem clientBootstrapWire_excludes_client_share
    (wire : ClientBootstrapWire) :
    clientBootstrapWireClientShare? wire = none := by
  rfl

theorem clientBootstrapWire_excludes_relayer_root
    (wire : ClientBootstrapWire) :
    clientBootstrapWireRelayerRoot? wire = none := by
  rfl

theorem clientBootstrapWire_excludes_relayer_share
    (wire : ClientBootstrapWire) :
    clientBootstrapWireRelayerShare? wire = none := by
  rfl

theorem clientBootstrapWire_excludes_canonical_x
    (wire : ClientBootstrapWire) :
    clientBootstrapWireCanonicalX? wire = none := by
  rfl

theorem clientBootstrapWireOfState_preserves_public_client_key
    (state : ExecutionState) :
    (clientBootstrapWireOfState state).clientPublicKey33 =
      state.clientShare.clientPublicKey33 := by
  rfl

theorem serverBootstrapWire_excludes_client_root
    (wire : ServerBootstrapWire) :
    serverBootstrapWireClientRoot? wire = none := by
  rfl

theorem serverBootstrapWire_excludes_client_share
    (wire : ServerBootstrapWire) :
    serverBootstrapWireClientShare? wire = none := by
  rfl

theorem serverBootstrapWire_excludes_relayer_root
    (wire : ServerBootstrapWire) :
    serverBootstrapWireRelayerRoot? wire = none := by
  rfl

theorem serverBootstrapWire_excludes_relayer_share
    (wire : ServerBootstrapWire) :
    serverBootstrapWireRelayerShare? wire = none := by
  rfl

theorem serverBootstrapWire_excludes_canonical_x
    (wire : ServerBootstrapWire) :
    serverBootstrapWireCanonicalX? wire = none := by
  rfl

theorem serverBootstrapWireOfState_preserves_public_transcript
    (state : ExecutionState) :
    (serverBootstrapWireOfState state).publicTranscript =
      publicTranscriptOfIdentity state.publicIdentity OperationKind.nonExport := by
  rfl

theorem clientRetainedState_excludes_relayer_root
    (state : RoleLocalClientRetainedState) :
    clientRetainedStateRelayerRoot? state = none := by
  rfl

theorem clientRetainedState_excludes_relayer_share
    (state : RoleLocalClientRetainedState) :
    clientRetainedStateRelayerShare? state = none := by
  rfl

theorem clientRetainedState_excludes_canonical_x
    (state : RoleLocalClientRetainedState) :
    clientRetainedStateCanonicalX? state = none := by
  rfl

theorem roleLocalClientRetainedStateOfState_preserves_client_share
    (state : ExecutionState) :
    (roleLocalClientRetainedStateOfState state).clientShare =
      state.clientShare := by
  rfl

theorem serverRetainedState_excludes_client_root
    (state : RoleLocalServerRetainedState) :
    serverRetainedStateClientRoot? state = none := by
  rfl

theorem serverRetainedState_excludes_client_share
    (state : RoleLocalServerRetainedState) :
    serverRetainedStateClientShare? state = none := by
  rfl

theorem serverRetainedState_excludes_canonical_x
    (state : RoleLocalServerRetainedState) :
    serverRetainedStateCanonicalX? state = none := by
  rfl

theorem serverRetainedState_reveals_own_relayer_share
    (state : RoleLocalServerRetainedState) :
    serverRetainedStateRelayerShare? state =
      some state.serverShare.xRelayer32 := by
  rfl

theorem roleLocalServerRetainedStateOfState_preserves_server_share
    (state : ExecutionState) :
    (roleLocalServerRetainedStateOfState state).serverShare =
      state.serverShare := by
  rfl

theorem explicitExportWire_excludes_client_root
    (wire : ExplicitExportWire) :
    explicitExportWireClientRoot? wire = none := by
  rfl

theorem explicitExportWire_excludes_client_share
    (wire : ExplicitExportWire) :
    explicitExportWireClientShare? wire = none := by
  rfl

theorem explicitExportWire_excludes_relayer_root
    (wire : ExplicitExportWire) :
    explicitExportWireRelayerRoot? wire = none := by
  rfl

theorem explicitExportWire_releases_relayer_share
    (wire : ExplicitExportWire) :
    explicitExportWireRelayerShare? wire =
      some wire.exportRelayerShare32 := by
  rfl

theorem explicitExportWire_excludes_canonical_x
    (wire : ExplicitExportWire) :
    explicitExportWireCanonicalX? wire = none := by
  rfl

theorem explicitExportWireOfState_releases_server_share
    (state : ExecutionState) :
    (explicitExportWireOfState state).exportRelayerShare32 =
      state.serverShare.xRelayer32 := by
  rfl

theorem publicTranscriptOfIdentity_matches_public_identity
    (publicIdentity : PublicIdentity)
    (operation : OperationKind) :
    publicIdentityMatchesTranscript
      publicIdentity
      (publicTranscriptOfIdentity publicIdentity operation) := by
  constructor
  · rfl
  constructor
  · rfl
  constructor
  · rfl
  constructor
  · rfl
  · rfl

theorem explicitExportAuthorizationOfState_binds_public_identity
    (state : ExecutionState) :
    exportAuthorizationBindsPublicIdentity
      (explicitExportAuthorizationOfState state) := by
  constructor
  · exact publicTranscriptOfIdentity_matches_public_identity
      state.publicIdentity OperationKind.explicitExport
  · rfl

theorem explicitExportAuthorizationOfState_digest_matches
    (state : ExecutionState) :
    exportAuthorizationDigestMatches
      (explicitExportAuthorizationOfState state) := by
  rfl

theorem explicitExportAuthorizationOfState_is_valid
    (state : ExecutionState) :
    validExportAuthorization
      (explicitExportAuthorizationOfState state) := by
  constructor
  · exact explicitExportAuthorizationOfState_binds_public_identity state
  · exact explicitExportAuthorizationOfState_digest_matches state

theorem exportAuthorizationBindsPublicIdentity_operation
    (authorization : ExplicitExportAuthorization)
    (hBinds : exportAuthorizationBindsPublicIdentity authorization) :
    authorization.exportTranscript.operation = OperationKind.explicitExport := by
  exact hBinds.right

theorem validExportAuthorization_operation
    (authorization : ExplicitExportAuthorization)
    (hValid : validExportAuthorization authorization) :
    authorization.exportTranscript.operation = OperationKind.explicitExport := by
  exact exportAuthorizationBindsPublicIdentity_operation authorization hValid.left

theorem explicitExportAuthorizationOfState_matches_wire
    (state : ExecutionState) :
    exportAuthorizationMatchesWire
      (explicitExportAuthorizationOfState state)
      (explicitExportWireOfState state) := by
  constructor
  · rfl
  · exact explicitExportAuthorizationOfState_binds_public_identity state

theorem authorizedExplicitExportWireOfState_is_valid
    (state : ExecutionState) :
    authorizedExplicitExportWireIsValid
      (authorizedExplicitExportWireOfState state) := by
  exact explicitExportAuthorizationOfState_matches_wire state

theorem authorizedExplicitExportWireOfState_has_valid_authorization
    (state : ExecutionState) :
    authorizedExplicitExportWireHasValidAuthorization
      (authorizedExplicitExportWireOfState state) := by
  constructor
  · exact explicitExportAuthorizationOfState_matches_wire state
  · exact explicitExportAuthorizationOfState_digest_matches state

theorem authorizedExplicitExportWireHasValidAuthorization_is_valid
    (wire : AuthorizedExplicitExportWire)
    (hValid : authorizedExplicitExportWireHasValidAuthorization wire) :
    authorizedExplicitExportWireIsValid wire := by
  exact hValid.left

theorem authorizedExplicitExportWireHasValidAuthorization_digest_matches
    (wire : AuthorizedExplicitExportWire)
    (hValid : authorizedExplicitExportWireHasValidAuthorization wire) :
    exportAuthorizationDigestMatches wire.authorization := by
  exact hValid.right

theorem authorizedExplicitExportWireHasValidAuthorization_operation
    (wire : AuthorizedExplicitExportWire)
    (hValid : authorizedExplicitExportWireHasValidAuthorization wire) :
    wire.authorization.exportTranscript.operation =
      OperationKind.explicitExport := by
  exact exportAuthorizationBindsPublicIdentity_operation
    wire.authorization hValid.left.right

theorem authorizedExplicitExportWireHasValidAuthorization_wire_operation
    (wire : AuthorizedExplicitExportWire)
    (hValid : authorizedExplicitExportWireHasValidAuthorization wire) :
    wire.wire.publicTranscript.operation =
      OperationKind.explicitExport := by
  have hTranscript : wire.authorization.exportTranscript =
      wire.wire.publicTranscript := hValid.left.left
  have hOperation :=
    authorizedExplicitExportWireHasValidAuthorization_operation wire hValid
  simpa [hTranscript] using hOperation

theorem authorizedExplicitExportWireHasValidAuthorization_matches_wire_identity
    (wire : AuthorizedExplicitExportWire)
    (hValid : authorizedExplicitExportWireHasValidAuthorization wire) :
    publicIdentityMatchesTranscript
      wire.authorization.publicIdentity
      wire.wire.publicTranscript := by
  have hTranscript : wire.authorization.exportTranscript =
      wire.wire.publicTranscript := hValid.left.left
  have hPublic : publicIdentityMatchesTranscript
      wire.authorization.publicIdentity
      wire.authorization.exportTranscript := hValid.left.right.left
  simpa [hTranscript] using hPublic

theorem invalid_authorization_digest_prevents_valid_export_wire
    (wire : AuthorizedExplicitExportWire)
    (hDigest :
      wire.authorization.authorizationDigest32 ≠
        exportAuthorizationDigest
          wire.authorization.publicIdentity
          wire.authorization.exportTranscript) :
    ¬ authorizedExplicitExportWireHasValidAuthorization wire := by
  intro hValid
  exact hDigest hValid.right

theorem roleLocalWireEnvelope_client_bootstrap_operation
    (wire : ClientBootstrapWire) :
    roleLocalWireOperation (.clientBootstrap wire) = OperationKind.nonExport := by
  rfl

theorem roleLocalWireEnvelope_server_bootstrap_operation
    (wire : ServerBootstrapWire) :
    roleLocalWireOperation (.serverBootstrap wire) = OperationKind.nonExport := by
  rfl

theorem roleLocalWireEnvelope_explicit_export_operation
    (wire : AuthorizedExplicitExportWire) :
    roleLocalWireOperation (.explicitExport wire) = OperationKind.explicitExport := by
  rfl

theorem roleLocalWireEnvelope_excludes_client_root
    (wire : RoleLocalWireEnvelope) :
    roleLocalWireClientRoot? wire = none := by
  cases wire <;> rfl

theorem roleLocalWireEnvelope_excludes_client_share
    (wire : RoleLocalWireEnvelope) :
    roleLocalWireClientShare? wire = none := by
  cases wire <;> rfl

theorem roleLocalWireEnvelope_excludes_canonical_x
    (wire : RoleLocalWireEnvelope) :
    roleLocalWireCanonicalX? wire = none := by
  cases wire <;> rfl

theorem roleLocalWireEnvelope_non_export_excludes_relayer_share
    (wire : RoleLocalWireEnvelope)
    (hOperation : roleLocalWireOperation wire = OperationKind.nonExport) :
    roleLocalWireRelayerShare? wire = none := by
  cases wire <;> simp [roleLocalWireOperation, roleLocalWireRelayerShare?] at hOperation ⊢

theorem roleLocalWireEnvelope_explicit_export_releases_relayer_share
    (wire : AuthorizedExplicitExportWire) :
    roleLocalWireRelayerShare? (.explicitExport wire) =
      some wire.wire.exportRelayerShare32 := by
  rfl

theorem roleLocalWireEnvelope_relayer_share_requires_explicit_export
    (wire : RoleLocalWireEnvelope)
    (hShare : (roleLocalWireRelayerShare? wire).isSome) :
    roleLocalWireOperation wire = OperationKind.explicitExport := by
  cases wire <;> simp [roleLocalWireOperation, roleLocalWireRelayerShare?] at hShare ⊢

theorem roleLocalWireEnvelope_explicit_export_of_state_is_valid
    (state : ExecutionState) :
    authorizedExplicitExportWireIsValid
      (authorizedExplicitExportWireOfState state) := by
  exact authorizedExplicitExportWireOfState_is_valid state

theorem roleLocalWireEnvelopeOfExplicitExport_state_has_valid_authorization
    (state : ExecutionState) :
    roleLocalWireEnvelopeHasValidAuthorization
      (roleLocalWireEnvelopeOfExplicitExport state) := by
  exact authorizedExplicitExportWireOfState_has_valid_authorization state

theorem roleLocalWireEnvelope_valid_export_relayer_share_requires_authorized_wire
    (wire : RoleLocalWireEnvelope)
    (hValid : roleLocalWireEnvelopeHasValidAuthorization wire)
    (hShare : (roleLocalWireRelayerShare? wire).isSome) :
    ∃ exportWire : AuthorizedExplicitExportWire,
      wire = .explicitExport exportWire ∧
      authorizedExplicitExportWireHasValidAuthorization exportWire := by
  cases wire with
  | clientBootstrap wire =>
      simp [roleLocalWireRelayerShare?] at hShare
  | serverBootstrap wire =>
      simp [roleLocalWireRelayerShare?] at hShare
  | explicitExport wire =>
      exact ⟨wire, rfl, hValid⟩

theorem invalid_authorization_digest_prevents_valid_role_local_export_wire
    (wire : AuthorizedExplicitExportWire)
    (hDigest :
      wire.authorization.authorizationDigest32 ≠
        exportAuthorizationDigest
          wire.authorization.publicIdentity
          wire.authorization.exportTranscript) :
    ¬ roleLocalWireEnvelopeHasValidAuthorization (.explicitExport wire) := by
  exact invalid_authorization_digest_prevents_valid_export_wire wire hDigest

theorem clientStateMatchesExportAuthorization_public_identity
    (clientState : RoleLocalClientRetainedState)
    (authorization : ExplicitExportAuthorization)
    (hMatches :
      clientStateMatchesExportAuthorization clientState authorization) :
    clientState.publicIdentity = authorization.publicIdentity := by
  exact hMatches.left

theorem clientStateMatchesExportAuthorization_context_binding
    (clientState : RoleLocalClientRetainedState)
    (authorization : ExplicitExportAuthorization)
    (hMatches :
      clientStateMatchesExportAuthorization clientState authorization) :
    clientState.acceptedTranscript.contextBinding32 =
      authorization.exportTranscript.contextBinding32 := by
  exact hMatches.right

theorem clientStateMatchesServerState_public_identity
    (clientState : RoleLocalClientRetainedState)
    (serverState : RoleLocalServerRetainedState)
    (hMatches :
      clientStateMatchesServerState clientState serverState) :
    clientState.publicIdentity = serverState.publicIdentity := by
  exact hMatches.left

theorem clientStateMatchesServerState_context_binding
    (clientState : RoleLocalClientRetainedState)
    (serverState : RoleLocalServerRetainedState)
    (hMatches :
      clientStateMatchesServerState clientState serverState) :
    clientState.acceptedTranscript.contextBinding32 =
      serverState.acceptedTranscript.contextBinding32 := by
  exact hMatches.right

theorem boundRoleLocalSigningSession_client_public_identity_matches_server
    (session : BoundRoleLocalSigningSession) :
    session.clientState.publicIdentity =
      session.serverState.publicIdentity := by
  exact session.clientMatchesServer.left

theorem boundRoleLocalSigningSession_context_binding_matches_server
    (session : BoundRoleLocalSigningSession) :
    session.clientState.acceptedTranscript.contextBinding32 =
      session.serverState.acceptedTranscript.contextBinding32 := by
  exact session.clientMatchesServer.right

theorem boundRoleLocalSigningSessionOfState_client_public_identity_matches
    (state : ExecutionState) :
    (boundRoleLocalSigningSessionOfState state).clientState.publicIdentity =
      (boundRoleLocalSigningSessionOfState state).serverState.publicIdentity := by
  rfl

theorem boundRoleLocalSigningSessionOfState_context_binding_matches
    (state : ExecutionState) :
    (boundRoleLocalSigningSessionOfState state).clientState.acceptedTranscript.contextBinding32 =
      (boundRoleLocalSigningSessionOfState state).serverState.acceptedTranscript.contextBinding32 := by
  rfl

theorem different_public_identity_prevents_bound_role_local_signing_session
    (clientState : RoleLocalClientRetainedState)
    (serverState : RoleLocalServerRetainedState)
    (hDifferent :
      clientState.publicIdentity ≠ serverState.publicIdentity) :
    ¬ ∃ session : BoundRoleLocalSigningSession,
      session.clientState = clientState ∧
      session.serverState = serverState := by
  intro hExists
  rcases hExists with ⟨session, hClient, hServer⟩
  exact hDifferent (by
    simpa [hClient, hServer] using session.clientMatchesServer.left)

theorem different_context_prevents_bound_role_local_signing_session
    (clientState : RoleLocalClientRetainedState)
    (serverState : RoleLocalServerRetainedState)
    (hDifferent :
      clientState.acceptedTranscript.contextBinding32 ≠
        serverState.acceptedTranscript.contextBinding32) :
    ¬ ∃ session : BoundRoleLocalSigningSession,
      session.clientState = clientState ∧
      session.serverState = serverState := by
  intro hExists
  rcases hExists with ⟨session, hClient, hServer⟩
  exact hDifferent (by
    simpa [hClient, hServer] using session.clientMatchesServer.right)

theorem boundRoleLocalSigningSessionOfState_canonical_scalar_matches_state
    (state : ExecutionState) :
    boundRoleLocalSigningSessionCanonicalScalar
        (boundRoleLocalSigningSessionOfState state) =
      reconstructedCanonicalScalar state := by
  rfl

theorem boundRoleLocalSigningSessionOfState_verifies_public_key
    (state : ExecutionState)
    (hExport : exportPublicKeyVerification state) :
    scalarBaseMul
        (boundRoleLocalSigningSessionCanonicalScalar
          (boundRoleLocalSigningSessionOfState state)) =
      (boundRoleLocalSigningSessionOfState state).clientState.publicIdentity.thresholdPublicPoint := by
  rcases hExport with ⟨hPoint, _hCompressed⟩
  simpa [
    boundRoleLocalSigningSessionCanonicalScalar,
    boundRoleLocalSigningSessionOfState,
    reconstructedCanonicalScalar,
  ] using hPoint.symm

theorem boundExplicitExportSession_export_wire_is_valid
    (session : BoundExplicitExportSession) :
    authorizedExplicitExportWireIsValid session.exportWire := by
  exact session.validExportWire

theorem boundExplicitExportSession_client_public_identity_matches_authorization
    (session : BoundExplicitExportSession) :
    session.clientState.publicIdentity =
      session.exportWire.authorization.publicIdentity := by
  exact session.clientMatchesAuthorization.left

theorem boundExplicitExportSession_client_context_matches_export_context
    (session : BoundExplicitExportSession) :
    session.clientState.acceptedTranscript.contextBinding32 =
      session.exportWire.authorization.exportTranscript.contextBinding32 := by
  exact session.clientMatchesAuthorization.right

theorem boundExplicitExportSession_wire_operation_explicit_export
    (session : BoundExplicitExportSession) :
    session.exportWire.authorization.exportTranscript.operation =
      OperationKind.explicitExport := by
  exact session.validExportWire.right.right

theorem boundExplicitExportSession_wire_transcript_matches_authorized_identity
    (session : BoundExplicitExportSession) :
    publicIdentityMatchesTranscript
      session.exportWire.authorization.publicIdentity
      session.exportWire.wire.publicTranscript := by
  have hTranscript := session.validExportWire.left
  have hPublic := session.validExportWire.right.left
  simpa [hTranscript] using hPublic

theorem boundExplicitExportSession_reconstruction_public_identity_matches_authorization
    (session : BoundExplicitExportSession) :
    (clientExportReconstructionFromBoundSession session).publicIdentity =
      session.exportWire.authorization.publicIdentity := by
  simpa [
    clientExportReconstructionFromBoundSession,
    clientExportReconstructionFromWire,
  ] using session.clientMatchesAuthorization.left

theorem boundExplicitExportSessionOfState_client_public_identity_matches
    (state : ExecutionState) :
    (boundExplicitExportSessionOfState state).clientState.publicIdentity =
      (boundExplicitExportSessionOfState state).exportWire.authorization.publicIdentity := by
  rfl

theorem clientExportReconstructionFromWire_matches_explicit_export_view
    (state : ExecutionState) :
    clientExportReconstructionToView
        (clientExportReconstructionFromWire
          (roleLocalClientRetainedStateOfState state)
          (explicitExportWireOfState state)) =
      explicitExportClientView state := by
  rfl

theorem clientExportReconstructionFromWire_verifies_public_key
    (state : ExecutionState)
    (hExport : exportPublicKeyVerification state) :
    scalarBaseMul
        (clientExportReconstructionFromWire
          (roleLocalClientRetainedStateOfState state)
          (explicitExportWireOfState state)).reconstructedCanonicalX =
      (clientExportReconstructionFromWire
          (roleLocalClientRetainedStateOfState state)
          (explicitExportWireOfState state)).publicIdentity.thresholdPublicPoint := by
  rcases hExport with ⟨hPoint, _hCompressed⟩
  simpa [
    clientExportReconstructionFromWire,
    roleLocalClientRetainedStateOfState,
    explicitExportWireOfState,
    reconstructedCanonicalScalar,
  ] using hPoint.symm

theorem boundExplicitExportSessionOfState_reconstruction_matches_explicit_export_view
    (state : ExecutionState) :
    clientExportReconstructionToView
        (clientExportReconstructionFromBoundSession
          (boundExplicitExportSessionOfState state)) =
      explicitExportClientView state := by
  rfl

theorem boundExplicitExportSessionOfState_reconstruction_verifies_public_key
    (state : ExecutionState)
    (hExport : exportPublicKeyVerification state) :
    scalarBaseMul
        (clientExportReconstructionFromBoundSession
          (boundExplicitExportSessionOfState state)).reconstructedCanonicalX =
      (clientExportReconstructionFromBoundSession
          (boundExplicitExportSessionOfState state)).publicIdentity.thresholdPublicPoint := by
  exact clientExportReconstructionFromWire_verifies_public_key state hExport

theorem idealClientExportReconstructionFromWire_verifies_public_key
    (assumptions : DerivationAssumptions)
    (context : PublicContext)
    (clientInput : ClientPrivateInput)
    (serverInput : ServerPrivateInput) :
    scalarBaseMul
        (clientExportReconstructionFromWire
          (roleLocalClientRetainedStateOfState
            (F_ecdsa_hss_true_blind context clientInput serverInput).state)
          (explicitExportWireOfState
            (F_ecdsa_hss_true_blind context clientInput serverInput).state)).reconstructedCanonicalX =
      (clientExportReconstructionFromWire
          (roleLocalClientRetainedStateOfState
            (F_ecdsa_hss_true_blind context clientInput serverInput).state)
          (explicitExportWireOfState
            (F_ecdsa_hss_true_blind context clientInput serverInput).state)).publicIdentity.thresholdPublicPoint := by
  exact clientExportReconstructionFromWire_verifies_public_key
    (F_ecdsa_hss_true_blind context clientInput serverInput).state
    (idealFunctionality_export_public_key_verification
      assumptions context clientInput serverInput)

end

end EcdsaHssPrivacy.TrueBlind
