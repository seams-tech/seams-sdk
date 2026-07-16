import RouterAbEcdsaDerivationPrivacy.Views

namespace RouterAbEcdsaDerivationPrivacy

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
  | RouterAbEcdsaDerivationBoundary.ClientBoundaryModel.nonExport _ =>
    some { boundary := input.visibleBoundary }
  | RouterAbEcdsaDerivationBoundary.ClientBoundaryModel.explicitExport _ => none

def simulateExplicitExportClientView
    (input : ExplicitExportClientSimulatorInput) : Option ClientObservableProfile :=
  match input.visibleBoundary.clientOutput with
  | RouterAbEcdsaDerivationBoundary.ClientBoundaryModel.nonExport _ => none
  | RouterAbEcdsaDerivationBoundary.ClientBoundaryModel.explicitExport _ =>
    some { boundary := input.visibleBoundary }

def simulateNonExportServerView
    (input : NonExportServerSimulatorInput) : Option ServerObservableProfile :=
  match input.visibleBoundary.allowedOutputKind with
  | router_ab_ecdsa_derivation.wire.AllowedOutputKind.ThresholdMaterialOnly =>
    some { boundary := input.visibleBoundary }
  | router_ab_ecdsa_derivation.wire.AllowedOutputKind.ThresholdMaterialAndRelayerExportShare => none

def simulateExplicitExportServerView
    (input : ExplicitExportServerSimulatorInput) : Option ServerObservableProfile :=
  match input.visibleBoundary.allowedOutputKind with
  | router_ab_ecdsa_derivation.wire.AllowedOutputKind.ThresholdMaterialOnly => none
  | router_ab_ecdsa_derivation.wire.AllowedOutputKind.ThresholdMaterialAndRelayerExportShare =>
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
  cases state with
  | mk boundary canonicalX32 clientSecrets serverSecrets =>
    cases boundary with
    | mk operation clientOutput finalize retained =>
      cases operation with
      | mk operation allowedOutputKind =>
        cases allowedOutputKind <;> rfl

theorem simulateExplicitExportServerView_matches_state_projection
    (state : ProtocolExecutionState) :
    simulateExplicitExportServerView
        {
          visibleBoundary := serverVisibleBoundaryOfState state
        }
      =
      explicitExportServerView? state := by
  cases state with
  | mk boundary canonicalX32 clientSecrets serverSecrets =>
    cases boundary with
    | mk operation clientOutput finalize retained =>
      cases operation with
      | mk operation allowedOutputKind =>
        cases allowedOutputKind <;> rfl

end RouterAbEcdsaDerivationPrivacy
