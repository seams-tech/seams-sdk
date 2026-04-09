import EcdsaHssPrivacy.Views

namespace EcdsaHssPrivacy

structure NonExportClientSimulatorInput where
  visibleBoundary : ClientVisibleBoundary
  deriving DecidableEq, Repr

structure ExplicitExportClientSimulatorInput where
  visibleBoundary : ClientVisibleBoundary
  deriving DecidableEq, Repr

structure NonExportServerSimulatorInput where
  visibleBoundary : ServerVisibleBoundary
  deriving DecidableEq, Repr

structure ExplicitExportServerSimulatorInput where
  visibleBoundary : ServerVisibleBoundary
  deriving DecidableEq, Repr

def simulateNonExportClientView
    (input : NonExportClientSimulatorInput) : Option ClientObservableProfile :=
  match input.visibleBoundary.clientOutput with
  | EcdsaHssBoundary.ClientBoundaryModel.nonExport _ =>
    some { boundary := input.visibleBoundary }
  | EcdsaHssBoundary.ClientBoundaryModel.explicitExport _ => none

def simulateExplicitExportClientView
    (input : ExplicitExportClientSimulatorInput) : Option ClientObservableProfile :=
  match input.visibleBoundary.clientOutput with
  | EcdsaHssBoundary.ClientBoundaryModel.nonExport _ => none
  | EcdsaHssBoundary.ClientBoundaryModel.explicitExport _ =>
    some { boundary := input.visibleBoundary }

def simulateNonExportServerView
    (input : NonExportServerSimulatorInput) : Option ServerObservableProfile :=
  match input.visibleBoundary.allowedOutputKind with
  | ecdsa_hss.wire.AllowedOutputKindV1.ThresholdMaterialOnly =>
    some { boundary := input.visibleBoundary }
  | ecdsa_hss.wire.AllowedOutputKindV1.ThresholdMaterialAndCanonicalSecret => none

def simulateExplicitExportServerView
    (input : ExplicitExportServerSimulatorInput) : Option ServerObservableProfile :=
  match input.visibleBoundary.allowedOutputKind with
  | ecdsa_hss.wire.AllowedOutputKindV1.ThresholdMaterialOnly => none
  | ecdsa_hss.wire.AllowedOutputKindV1.ThresholdMaterialAndCanonicalSecret =>
    some { boundary := input.visibleBoundary }

theorem simulateNonExportClientView_matches_state_projection
    (state : ProtocolExecutionState) :
    simulateNonExportClientView
        {
          visibleBoundary := clientVisibleBoundaryOfState state
        }
      =
      nonExportClientView? state := by
  cases state.boundary.clientOutput <;> rfl

theorem simulateExplicitExportClientView_matches_state_projection
    (state : ProtocolExecutionState) :
    simulateExplicitExportClientView
        {
          visibleBoundary := clientVisibleBoundaryOfState state
        }
      =
      explicitExportClientView? state := by
  cases state.boundary.clientOutput <;> rfl

theorem simulateNonExportServerView_matches_state_projection
    (state : ProtocolExecutionState) :
    simulateNonExportServerView
        {
          visibleBoundary := serverVisibleBoundaryOfState state
        }
      =
      nonExportServerView? state := by
  cases state.boundary.operation.allowedOutputKind <;> rfl

theorem simulateExplicitExportServerView_matches_state_projection
    (state : ProtocolExecutionState) :
    simulateExplicitExportServerView
        {
          visibleBoundary := serverVisibleBoundaryOfState state
        }
      =
      explicitExportServerView? state := by
  cases state.boundary.operation.allowedOutputKind <;> rfl

end EcdsaHssPrivacy
