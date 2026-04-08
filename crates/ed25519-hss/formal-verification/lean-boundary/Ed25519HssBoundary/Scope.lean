namespace Ed25519HssBoundary

/-- The initial Rust-to-Lean extraction target is intentionally narrow. -/
inductive ExtractionTarget where
  | sharedReferenceBoundary
  deriving DecidableEq, Repr

/-- The first bridge only needs the visible non-export boundary fields. -/
structure VisibleBoundaryFocus where
  canonicalSeed : String
  xClientBase : String
  xRelayerBase : String
  deriving DecidableEq, Repr

theorem initial_extraction_target_is_shared_reference_boundary :
    ExtractionTarget.sharedReferenceBoundary =
      ExtractionTarget.sharedReferenceBoundary := by
  rfl

end Ed25519HssBoundary
