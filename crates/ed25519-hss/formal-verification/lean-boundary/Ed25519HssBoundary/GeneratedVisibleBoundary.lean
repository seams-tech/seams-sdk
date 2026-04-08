import Ed25519Hss

namespace Ed25519HssBoundary

open ed25519_hss

abbrev GeneratedFExpandInput := shared.reference.FExpandInput
abbrev GeneratedFExpandOutput := shared.reference.FExpandOutput
abbrev GeneratedVisibleBoundary := shared.reference_boundary.FExpandVisibleBoundary

def generatedVisibleBoundaryCanonicalSeed
    (boundary : GeneratedVisibleBoundary) : Array UInt8 32#usize :=
  boundary.canonical_seed

def generatedVisibleBoundaryClientBase
    (boundary : GeneratedVisibleBoundary) : Array UInt8 32#usize :=
  boundary.x_client_base

def generatedVisibleBoundaryRelayerBase
    (boundary : GeneratedVisibleBoundary) : Array UInt8 32#usize :=
  boundary.x_relayer_base

theorem visibleBoundaryFromOutput_projectsCanonicalSeed
    (output : GeneratedFExpandOutput) :
    generatedVisibleBoundaryCanonicalSeed
        (by
          simpa using
            (shared.reference_boundary.visible_boundary_from_output output))
      = output.d := by
  rfl

theorem visibleBoundaryFromOutput_projectsClientBase
    (output : GeneratedFExpandOutput) :
    generatedVisibleBoundaryClientBase
        (by
          simpa using
            (shared.reference_boundary.visible_boundary_from_output output))
      = output.x_client_base := by
  rfl

theorem visibleBoundaryFromOutput_projectsRelayerBase
    (output : GeneratedFExpandOutput) :
    generatedVisibleBoundaryRelayerBase
        (by
          simpa using
            (shared.reference_boundary.visible_boundary_from_output output))
      = output.x_relayer_base := by
  rfl

end Ed25519HssBoundary
