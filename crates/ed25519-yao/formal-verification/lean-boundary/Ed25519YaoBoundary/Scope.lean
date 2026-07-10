import Ed25519Yao

namespace Ed25519YaoBoundary

/-- Checked reference to the generated wrapping-add translation. -/
abbrev wrappingAddLe256Extracted :=
  ed25519_yao_generator.wrapping_add_le_256

/-- Checked reference to the generated RFC 8032 clamp translation. -/
abbrev clampRfc8032Extracted :=
  ed25519_yao_generator.clamp_rfc8032

/-- The complete Rust-to-Lean extraction surface in FV1. -/
inductive ExtractionTarget where
  | wrappingAddLe256
  | clampRfc8032
  deriving DecidableEq, Repr

/-- FV1 extracts exactly two pure generator helpers. -/
def extractionTargetCount : Nat := 2

theorem extractionTargetCountIsTwo : extractionTargetCount = 2 := by
  rfl

theorem extractionTargetsAreDistinct :
    ExtractionTarget.wrappingAddLe256 ≠ ExtractionTarget.clampRfc8032 := by
  decide

end Ed25519YaoBoundary
