import Ed25519HssPrivacy.Views

namespace Ed25519HssPrivacy

structure ClientAdversaryView where
  publicParameters : PublicParameters
  boundary : NonExportVisibleBoundary
  deriving Repr

structure ServerAdversaryView where
  publicParameters : PublicParameters
  boundary : NonExportVisibleBoundary
  deriving Repr

def nonExportClientAdversaryView
    (publicParameters : PublicParameters)
    (boundary : NonExportVisibleBoundary) : ClientAdversaryView :=
  {
    publicParameters,
    boundary,
  }

def nonExportServerAdversaryView
    (publicParameters : PublicParameters)
    (boundary : NonExportVisibleBoundary) : ServerAdversaryView :=
  {
    publicParameters,
    boundary,
  }

structure ClientSimulatorInput where
  publicParameters : PublicParameters
  boundary : NonExportVisibleBoundary
  deriving Repr

structure ServerSimulatorInput where
  publicParameters : PublicParameters
  boundary : NonExportVisibleBoundary
  deriving Repr

def simulateNonExportClientView
    (input : ClientSimulatorInput) : ClientAdversaryView :=
  nonExportClientAdversaryView input.publicParameters input.boundary

def simulateNonExportServerView
    (input : ServerSimulatorInput) : ServerAdversaryView :=
  nonExportServerAdversaryView input.publicParameters input.boundary

theorem simulateNonExportClientView_matches_projection
    (publicParameters : PublicParameters)
    (boundary : NonExportVisibleBoundary) :
    simulateNonExportClientView
        {
          publicParameters,
          boundary,
        }
      = nonExportClientAdversaryView publicParameters boundary := rfl

theorem simulateNonExportServerView_matches_projection
    (publicParameters : PublicParameters)
    (boundary : NonExportVisibleBoundary) :
    simulateNonExportServerView
        {
          publicParameters,
          boundary,
        }
      = nonExportServerAdversaryView publicParameters boundary := rfl

theorem simulateNonExportClientView_matches_clientView
    (publicParameters : PublicParameters)
    (boundary : NonExportVisibleBoundary) :
    (simulateNonExportClientView
        {
          publicParameters,
          boundary,
        }).boundary
      = (clientView publicParameters (.nonExport boundary)).boundary := rfl

theorem simulateNonExportServerView_matches_serverView
    (publicParameters : PublicParameters)
    (boundary : NonExportVisibleBoundary) :
    (simulateNonExportServerView
        {
          publicParameters,
          boundary,
        }).boundary
      = (serverView publicParameters (.nonExport boundary)).boundary := rfl

end Ed25519HssPrivacy
