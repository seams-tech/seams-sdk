import EcdsaHss

namespace EcdsaHssBoundary

open ecdsa_hss

/-- The initial extraction target is intentionally narrow. -/
inductive ExtractionTarget where
  | stagedServerBoundary
  deriving DecidableEq, Repr

/-- Handwritten boundary model for operation-to-output-kind policy. -/
structure OperationBoundaryModel where
  operation : wire.ServerEvalOperationV1
  allowedOutputKind : wire.AllowedOutputKindV1
  deriving DecidableEq, Repr

/-- Handwritten boundary model for the visible non-export output. -/
structure NonExportBoundaryModel where
  xClient32 : Array UInt8 32#usize
  clientPublicKey33 : Array UInt8 33#usize
  thresholdPublicKey33 : Array UInt8 33#usize
  thresholdEthereumAddress20 : Array UInt8 20#usize
  retryCounter : UInt32
  deriving DecidableEq, Repr

/-- Handwritten boundary model for the visible explicit-export output. -/
structure ExplicitExportBoundaryModel where
  canonicalX32 : Array UInt8 32#usize
  canonicalPublicKey33 : Array UInt8 33#usize
  canonicalEthereumAddress20 : Array UInt8 20#usize
  xClient32 : Array UInt8 32#usize
  clientPublicKey33 : Array UInt8 33#usize
  thresholdPublicKey33 : Array UInt8 33#usize
  thresholdEthereumAddress20 : Array UInt8 20#usize
  retryCounter : UInt32
  deriving DecidableEq, Repr

/-- Handwritten boundary model for visible client output variants. -/
inductive ClientBoundaryModel where
  | nonExport (boundary : NonExportBoundaryModel)
  | explicitExport (boundary : ExplicitExportBoundaryModel)
  deriving DecidableEq, Repr

/-- Handwritten boundary model for the finalize envelope projection. -/
structure FinalizeBoundaryModel where
  operation : wire.ServerEvalOperationV1
  rawRootMaterialDropped : Bool
  thresholdPublicKey33 : Array UInt8 33#usize
  thresholdEthereumAddress20 : Array UInt8 20#usize
  retryCounter : UInt32
  deriving DecidableEq, Repr

/-- Handwritten boundary model for finalized retained server state. -/
structure RetainedStateBoundaryModel where
  rawRootMaterialDropped : Bool
  relayerThresholdShare32 : Array UInt8 32#usize
  relayerPublicKey33 : Array UInt8 33#usize
  thresholdPublicKey33 : Array UInt8 33#usize
  thresholdEthereumAddress20 : Array UInt8 20#usize
  retryCounter : UInt32
  deriving DecidableEq, Repr

/-- Handwritten boundary model for the full visible staged boundary. -/
structure RespondBoundaryModel where
  operation : OperationBoundaryModel
  clientOutput : ClientBoundaryModel
  finalize : FinalizeBoundaryModel
  retained : RetainedStateBoundaryModel
  deriving DecidableEq, Repr

/-- Handwritten policy function for the frozen v1 operation/output-kind mapping. -/
def expectedAllowedOutputKindForOperation
    (operation : wire.ServerEvalOperationV1) : wire.AllowedOutputKindV1 :=
  match operation with
  | wire.ServerEvalOperationV1.RegistrationBootstrap =>
    wire.AllowedOutputKindV1.ThresholdMaterialOnly
  | wire.ServerEvalOperationV1.SessionBootstrap =>
    wire.AllowedOutputKindV1.ThresholdMaterialOnly
  | wire.ServerEvalOperationV1.NonExportSign =>
    wire.AllowedOutputKindV1.ThresholdMaterialOnly
  | wire.ServerEvalOperationV1.ExplicitKeyExport =>
    wire.AllowedOutputKindV1.ThresholdMaterialAndCanonicalSecret

theorem initial_extraction_target_is_staged_server_boundary :
    ExtractionTarget.stagedServerBoundary =
      ExtractionTarget.stagedServerBoundary := by
  rfl

theorem expectedAllowedOutputKindForOperation_matches_frozen_v1_policy
    (operation : wire.ServerEvalOperationV1) :
    expectedAllowedOutputKindForOperation operation =
      match operation with
      | wire.ServerEvalOperationV1.RegistrationBootstrap =>
        wire.AllowedOutputKindV1.ThresholdMaterialOnly
      | wire.ServerEvalOperationV1.SessionBootstrap =>
        wire.AllowedOutputKindV1.ThresholdMaterialOnly
      | wire.ServerEvalOperationV1.NonExportSign =>
        wire.AllowedOutputKindV1.ThresholdMaterialOnly
      | wire.ServerEvalOperationV1.ExplicitKeyExport =>
        wire.AllowedOutputKindV1.ThresholdMaterialAndCanonicalSecret := by
  cases operation <;> rfl

end EcdsaHssBoundary
