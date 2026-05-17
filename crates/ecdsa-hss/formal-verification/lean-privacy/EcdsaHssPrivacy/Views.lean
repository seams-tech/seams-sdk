import EcdsaHssPrivacy.Model

namespace EcdsaHssPrivacy

open EcdsaHssBoundary

structure ClientVisibleBoundary where
  operation : ecdsa_hss.wire.ServerEvalOperationV1
  allowedOutputKind : ecdsa_hss.wire.AllowedOutputKindV1
  clientOutput : ClientBoundaryModel
  deriving DecidableEq, Repr

structure ClientObservableProfile where
  boundary : ClientVisibleBoundary
  deriving DecidableEq, Repr

def clientVisibleBoundaryOfRespondBoundary
    (boundary : RespondBoundaryModel) : ClientVisibleBoundary :=
  {
    operation := boundary.operation.operation
    allowedOutputKind := boundary.operation.allowedOutputKind
    clientOutput := boundary.clientOutput
  }

def serverVisibleBoundaryOfRespondBoundary
    (boundary : RespondBoundaryModel) : ServerVisibleBoundary :=
  {
    operation := boundary.operation.operation
    allowedOutputKind := boundary.operation.allowedOutputKind
    finalizeOperation := boundary.finalize.operation
    rawRootMaterialDropped := boundary.finalize.rawRootMaterialDropped
    thresholdPublicKey33 := boundary.finalize.thresholdPublicKey33
    thresholdEthereumAddress20 := boundary.finalize.thresholdEthereumAddress20
    retryCounter := boundary.finalize.retryCounter
    relayerThresholdShare32 := boundary.retained.relayerThresholdShare32
    relayerPublicKey33 := boundary.retained.relayerPublicKey33
    retainedThresholdPublicKey33 := boundary.retained.thresholdPublicKey33
    retainedThresholdEthereumAddress20 := boundary.retained.thresholdEthereumAddress20
    retainedRetryCounter := boundary.retained.retryCounter
  }

def respondBoundaryOfHiddenEvalBoundary
    (boundary : HiddenEvalBoundaryModel) : RespondBoundaryModel :=
  {
    operation := boundary.transport.operation
    clientOutput := boundary.transport.clientOutput
    finalize := boundary.transport.finalize
    retained := {
      rawRootMaterialDropped := boundary.persisted.rawRootMaterialDropped
      relayerThresholdShare32 := boundary.persisted.relayerThresholdShare32
      relayerPublicKey33 := boundary.persisted.relayerPublicKey33
      thresholdPublicKey33 := boundary.persisted.thresholdPublicKey33
      thresholdEthereumAddress20 := boundary.persisted.thresholdEthereumAddress20
      retryCounter := boundary.persisted.retryCounter
    }
  }

def hiddenEvalTransportBoundaryOfState
    (state : HiddenEvalExecutionState) : HiddenEvalTransportBoundaryModel :=
  state.hiddenEvalBoundary.transport

def hiddenEvalPersistedStateBoundaryOfState
    (state : HiddenEvalExecutionState) : HiddenEvalPersistedStateBoundaryModel :=
  state.hiddenEvalBoundary.persisted

def hiddenEvalBoundaryOfState
    (state : HiddenEvalExecutionState) : HiddenEvalBoundaryModel :=
  state.hiddenEvalBoundary

def clientVisibleBoundaryOfHiddenEvalState
    (state : HiddenEvalExecutionState) : ClientVisibleBoundary :=
  clientVisibleBoundaryOfRespondBoundary
    (respondBoundaryOfHiddenEvalBoundary state.hiddenEvalBoundary)

def serverVisibleBoundaryOfHiddenEvalState
    (state : HiddenEvalExecutionState) : ServerVisibleBoundary :=
  serverVisibleBoundaryOfRespondBoundary
    (respondBoundaryOfHiddenEvalBoundary state.hiddenEvalBoundary)

def clientVisibleBoundaryOfState
    (state : ProtocolExecutionState) : ClientVisibleBoundary :=
  clientVisibleBoundaryOfRespondBoundary state.boundary

def serverVisibleBoundaryOfState
    (state : ProtocolExecutionState) : ServerVisibleBoundary :=
  serverVisibleBoundaryOfRespondBoundary state.boundary

def clientObservableProfile
    (state : ProtocolExecutionState) : ClientObservableProfile :=
  {
    boundary := clientVisibleBoundaryOfState state
  }

def serverObservableProfile
    (state : ProtocolExecutionState) : ServerObservableProfile :=
  {
    boundary := serverVisibleBoundaryOfState state
  }

def nonExportClientView?
    (state : ProtocolExecutionState) : Option ClientObservableProfile :=
  match state.boundary.clientOutput with
  | ClientBoundaryModel.nonExport _ => some (clientObservableProfile state)
  | ClientBoundaryModel.explicitExport _ => none

def explicitExportClientView?
    (state : ProtocolExecutionState) : Option ClientObservableProfile :=
  match state.boundary.clientOutput with
  | ClientBoundaryModel.nonExport _ => none
  | ClientBoundaryModel.explicitExport _ => some (clientObservableProfile state)

def nonExportServerView?
    (state : ProtocolExecutionState) : Option ServerObservableProfile :=
  match state.boundary.operation.allowedOutputKind with
  | ecdsa_hss.wire.AllowedOutputKindV1.ThresholdMaterialOnly =>
    some (serverObservableProfile state)
  | ecdsa_hss.wire.AllowedOutputKindV1.ThresholdMaterialAndCanonicalSecret =>
    none

def explicitExportServerView?
    (state : ProtocolExecutionState) : Option ServerObservableProfile :=
  match state.boundary.operation.allowedOutputKind with
  | ecdsa_hss.wire.AllowedOutputKindV1.ThresholdMaterialOnly =>
    none
  | ecdsa_hss.wire.AllowedOutputKindV1.ThresholdMaterialAndCanonicalSecret =>
    some (serverObservableProfile state)

def statesShareClientVisibleBoundary
    (left right : ProtocolExecutionState) : Prop :=
  clientVisibleBoundaryOfState left = clientVisibleBoundaryOfState right

def statesShareServerVisibleBoundary
    (left right : ProtocolExecutionState) : Prop :=
  serverVisibleBoundaryOfState left = serverVisibleBoundaryOfState right

def statesVaryOnlyInClientSecrets
    (left right : ProtocolExecutionState) : Prop :=
  statesShareServerVisibleBoundary left right

def statesVaryOnlyInServerSecrets
    (left right : ProtocolExecutionState) : Prop :=
  statesShareClientVisibleBoundary left right

theorem clientObservableProfile_eq_of_shared_client_boundary
    (left right : ProtocolExecutionState)
    (hBoundary : statesShareClientVisibleBoundary left right) :
    clientObservableProfile left = clientObservableProfile right := by
  simpa [clientObservableProfile, statesShareClientVisibleBoundary]
    using hBoundary

theorem serverObservableProfile_eq_of_shared_server_boundary
    (left right : ProtocolExecutionState)
    (hBoundary : statesShareServerVisibleBoundary left right) :
    serverObservableProfile left = serverObservableProfile right := by
  simpa [serverObservableProfile, statesShareServerVisibleBoundary]
    using hBoundary

theorem nonExportClientView_exists_exactly_for_non_export
    (state : ProtocolExecutionState) :
    (nonExportClientView? state).isSome =
      match state.boundary.clientOutput with
      | ClientBoundaryModel.nonExport _ => true
      | ClientBoundaryModel.explicitExport _ => false := by
  cases state with
  | mk boundary canonicalX32 clientSecrets serverSecrets =>
    cases boundary with
    | mk operation clientOutput finalize retained =>
      cases clientOutput <;> rfl

theorem explicitExportClientView_exists_exactly_for_explicit_export
    (state : ProtocolExecutionState) :
    (explicitExportClientView? state).isSome =
      match state.boundary.clientOutput with
      | ClientBoundaryModel.nonExport _ => false
      | ClientBoundaryModel.explicitExport _ => true := by
  cases state with
  | mk boundary canonicalX32 clientSecrets serverSecrets =>
    cases boundary with
    | mk operation clientOutput finalize retained =>
      cases clientOutput <;> rfl

theorem nonExportServerView_exists_exactly_for_threshold_only_output
    (state : ProtocolExecutionState) :
    (nonExportServerView? state).isSome =
      match state.boundary.operation.allowedOutputKind with
      | ecdsa_hss.wire.AllowedOutputKindV1.ThresholdMaterialOnly => true
      | ecdsa_hss.wire.AllowedOutputKindV1.ThresholdMaterialAndCanonicalSecret => false := by
  cases state with
  | mk boundary canonicalX32 clientSecrets serverSecrets =>
    cases boundary with
    | mk operation clientOutput finalize retained =>
      cases operation with
      | mk operation allowedOutputKind =>
        cases allowedOutputKind <;> rfl

theorem explicitExportServerView_exists_exactly_for_export_output
    (state : ProtocolExecutionState) :
    (explicitExportServerView? state).isSome =
      match state.boundary.operation.allowedOutputKind with
      | ecdsa_hss.wire.AllowedOutputKindV1.ThresholdMaterialOnly => false
      | ecdsa_hss.wire.AllowedOutputKindV1.ThresholdMaterialAndCanonicalSecret => true := by
  cases state with
  | mk boundary canonicalX32 clientSecrets serverSecrets =>
    cases boundary with
    | mk operation clientOutput finalize retained =>
      cases operation with
      | mk operation allowedOutputKind =>
        cases allowedOutputKind <;> rfl

def statesShareHiddenEvalBoundary
    (left right : HiddenEvalExecutionState) : Prop :=
  hiddenEvalBoundaryOfState left = hiddenEvalBoundaryOfState right

def statesShareHiddenEvalTransportBoundary
    (left right : HiddenEvalExecutionState) : Prop :=
  hiddenEvalTransportBoundaryOfState left = hiddenEvalTransportBoundaryOfState right

def statesShareHiddenEvalPersistedStateBoundary
    (left right : HiddenEvalExecutionState) : Prop :=
  hiddenEvalPersistedStateBoundaryOfState left =
    hiddenEvalPersistedStateBoundaryOfState right

theorem clientVisibleBoundaryOfHiddenEvalState_depends_only_on_hidden_eval_boundary
    (left right : HiddenEvalExecutionState)
    (hBoundary : statesShareHiddenEvalBoundary left right) :
    clientVisibleBoundaryOfHiddenEvalState left =
      clientVisibleBoundaryOfHiddenEvalState right := by
  cases left
  cases right
  cases hBoundary
  rfl

theorem serverVisibleBoundaryOfHiddenEvalState_depends_only_on_hidden_eval_boundary
    (left right : HiddenEvalExecutionState)
    (hBoundary : statesShareHiddenEvalBoundary left right) :
    serverVisibleBoundaryOfHiddenEvalState left =
      serverVisibleBoundaryOfHiddenEvalState right := by
  cases left
  cases right
  cases hBoundary
  rfl

theorem hiddenEvalTransportBoundaryOfState_depends_only_on_hidden_eval_boundary
    (left right : HiddenEvalExecutionState)
    (hBoundary : statesShareHiddenEvalBoundary left right) :
    hiddenEvalTransportBoundaryOfState left =
      hiddenEvalTransportBoundaryOfState right := by
  exact congrArg HiddenEvalBoundaryModel.transport hBoundary

theorem hiddenEvalPersistedStateBoundaryOfState_depends_only_on_hidden_eval_boundary
    (left right : HiddenEvalExecutionState)
    (hBoundary : statesShareHiddenEvalBoundary left right) :
    hiddenEvalPersistedStateBoundaryOfState left =
      hiddenEvalPersistedStateBoundaryOfState right := by
  exact congrArg HiddenEvalBoundaryModel.persisted hBoundary

end EcdsaHssPrivacy
