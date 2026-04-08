import Ed25519HssPrivacy.Model

namespace Ed25519HssPrivacy

structure ClientView where
  publicParameters : PublicParameters
  boundary : NonExportVisibleBoundary
  deriving Repr

structure ServerView where
  publicParameters : PublicParameters
  boundary : NonExportVisibleBoundary
  deriving Repr

def clientView
    (publicParameters : PublicParameters)
    (boundary : VisibleBoundary) : ClientView :=
  {
    publicParameters with
    boundary := boundary.nonExportProjection,
  }

def serverView
    (publicParameters : PublicParameters)
    (boundary : VisibleBoundary) : ServerView :=
  {
    publicParameters with
    boundary := boundary.nonExportProjection,
  }

def clientViewAllowedOutputKind
    (publicParameters : PublicParameters)
    (boundary : VisibleBoundary) : AllowedOutputKind :=
  boundary.allowedOutputKind

def serverViewAllowedOutputKind
    (publicParameters : PublicParameters)
    (boundary : VisibleBoundary) : AllowedOutputKind :=
  boundary.allowedOutputKind

def clientViewSeedOutput?
    (_publicParameters : PublicParameters)
    (boundary : VisibleBoundary) : Option Bytes32 :=
  boundary.seedOutput?

def serverViewSeedOutput?
    (_publicParameters : PublicParameters)
    (boundary : VisibleBoundary) : Option Bytes32 :=
  boundary.seedOutput?

theorem clientView_uses_nonExport_projection
    (publicParameters : PublicParameters)
    (boundary : VisibleBoundary) :
    (clientView publicParameters boundary).boundary = boundary.nonExportProjection := rfl

theorem serverView_uses_nonExport_projection
    (publicParameters : PublicParameters)
    (boundary : VisibleBoundary) :
    (serverView publicParameters boundary).boundary = boundary.nonExportProjection := rfl

theorem clientView_nonExport_has_no_seed_output
    (publicParameters : PublicParameters)
    (boundary : NonExportVisibleBoundary) :
    clientViewSeedOutput? publicParameters (.nonExport boundary) = none := rfl

theorem serverView_nonExport_has_no_seed_output
    (publicParameters : PublicParameters)
    (boundary : NonExportVisibleBoundary) :
    serverViewSeedOutput? publicParameters (.nonExport boundary) = none := rfl

theorem clientView_explicitExport_has_seed_output
    (publicParameters : PublicParameters)
    (boundary : ExplicitExportBoundary) :
    clientViewSeedOutput? publicParameters (.explicitExport boundary) = some boundary.seedOutput := rfl

theorem serverView_explicitExport_has_seed_output
    (publicParameters : PublicParameters)
    (boundary : ExplicitExportBoundary) :
    serverViewSeedOutput? publicParameters (.explicitExport boundary) = some boundary.seedOutput := rfl

end Ed25519HssPrivacy
