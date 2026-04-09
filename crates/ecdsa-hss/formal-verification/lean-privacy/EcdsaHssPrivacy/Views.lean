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
  cases left
  cases right
  cases hBoundary
  rfl

theorem serverObservableProfile_eq_of_shared_server_boundary
    (left right : ProtocolExecutionState)
    (hBoundary : statesShareServerVisibleBoundary left right) :
    serverObservableProfile left = serverObservableProfile right := by
  cases left
  cases right
  cases hBoundary
  rfl

theorem nonExportClientView_exists_exactly_for_non_export
    (state : ProtocolExecutionState) :
    (nonExportClientView? state).isSome =
      match state.boundary.clientOutput with
      | ClientBoundaryModel.nonExport _ => true
      | ClientBoundaryModel.explicitExport _ => false := by
  cases state.boundary.clientOutput <;> rfl

theorem explicitExportClientView_exists_exactly_for_explicit_export
    (state : ProtocolExecutionState) :
    (explicitExportClientView? state).isSome =
      match state.boundary.clientOutput with
      | ClientBoundaryModel.nonExport _ => false
      | ClientBoundaryModel.explicitExport _ => true := by
  cases state.boundary.clientOutput <;> rfl

theorem nonExportServerView_exists_exactly_for_threshold_only_output
    (state : ProtocolExecutionState) :
    (nonExportServerView? state).isSome =
      match state.boundary.operation.allowedOutputKind with
      | ecdsa_hss.wire.AllowedOutputKindV1.ThresholdMaterialOnly => true
      | ecdsa_hss.wire.AllowedOutputKindV1.ThresholdMaterialAndCanonicalSecret => false := by
  cases state.boundary.operation.allowedOutputKind <;> rfl

theorem explicitExportServerView_exists_exactly_for_export_output
    (state : ProtocolExecutionState) :
    (explicitExportServerView? state).isSome =
      match state.boundary.operation.allowedOutputKind with
      | ecdsa_hss.wire.AllowedOutputKindV1.ThresholdMaterialOnly => false
      | ecdsa_hss.wire.AllowedOutputKindV1.ThresholdMaterialAndCanonicalSecret => true := by
  cases state.boundary.operation.allowedOutputKind <;> rfl

end EcdsaHssPrivacy
