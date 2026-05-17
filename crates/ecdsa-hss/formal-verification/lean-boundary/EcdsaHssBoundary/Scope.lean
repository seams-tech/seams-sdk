import EcdsaHss

namespace EcdsaHssBoundary

open Aeneas Aeneas.Std
open ecdsa_hss

instance {α : Type u} {n : Aeneas.Std.Usize} [DecidableEq α] :
    DecidableEq (Aeneas.Std.Array α n) := by
  unfold Aeneas.Std.Array
  infer_instance

instance {α : Type u} {n : Aeneas.Std.Usize} [Repr α] :
    Repr (Aeneas.Std.Array α n) where
  reprPrec value prec := reprPrec value.val prec

deriving instance DecidableEq for wire.ServerEvalOperationV1
deriving instance Repr for wire.ServerEvalOperationV1
deriving instance DecidableEq for wire.AllowedOutputKindV1
deriving instance Repr for wire.AllowedOutputKindV1
deriving instance DecidableEq for shared.context.EcdsaHssStableKeyContextV1
deriving instance Repr for shared.context.EcdsaHssStableKeyContextV1

/-- The initial extraction target is intentionally narrow. -/
inductive ExtractionTarget where
  | stagedServerBoundary
  | hiddenEvalBoundary
  deriving DecidableEq, Repr

/-- Handwritten boundary model for operation-to-output-kind policy. -/
structure OperationBoundaryModel where
  operation : wire.ServerEvalOperationV1
  allowedOutputKind : wire.AllowedOutputKindV1
  deriving DecidableEq, Repr

/-- Handwritten boundary model for the visible non-export output. -/
structure NonExportBoundaryModel where
  xClient32 : Array Std.U8 32#usize
  clientPublicKey33 : Array Std.U8 33#usize
  thresholdPublicKey33 : Array Std.U8 33#usize
  thresholdEthereumAddress20 : Array Std.U8 20#usize
  retryCounter : UInt32
  deriving DecidableEq, Repr

/-- Handwritten boundary model for the visible explicit-export output. -/
structure ExplicitExportBoundaryModel where
  canonicalX32 : Array Std.U8 32#usize
  canonicalPublicKey33 : Array Std.U8 33#usize
  canonicalEthereumAddress20 : Array Std.U8 20#usize
  xClient32 : Array Std.U8 32#usize
  clientPublicKey33 : Array Std.U8 33#usize
  thresholdPublicKey33 : Array Std.U8 33#usize
  thresholdEthereumAddress20 : Array Std.U8 20#usize
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
  thresholdPublicKey33 : Array Std.U8 33#usize
  thresholdEthereumAddress20 : Array Std.U8 20#usize
  retryCounter : UInt32
  deriving DecidableEq, Repr

/-- Handwritten boundary model for finalized retained server state. -/
structure RetainedStateBoundaryModel where
  rawRootMaterialDropped : Bool
  relayerThresholdShare32 : Array Std.U8 32#usize
  relayerPublicKey33 : Array Std.U8 33#usize
  thresholdPublicKey33 : Array Std.U8 33#usize
  thresholdEthereumAddress20 : Array Std.U8 20#usize
  retryCounter : UInt32
  deriving DecidableEq, Repr

/-- Handwritten boundary model for the full visible staged boundary. -/
structure RespondBoundaryModel where
  operation : OperationBoundaryModel
  clientOutput : ClientBoundaryModel
  finalize : FinalizeBoundaryModel
  retained : RetainedStateBoundaryModel
  deriving DecidableEq, Repr

/-- Handwritten boundary model for the hidden-eval/compiler-facing input seam. -/
structure HiddenEvalInputBoundaryModel where
  operation : wire.ServerEvalOperationV1
  allowedOutputKind : wire.AllowedOutputKindV1
  context : shared.context.EcdsaHssStableKeyContextV1
  yClient32Le : Array Std.U8 32#usize
  yRelayer32Le : Array Std.U8 32#usize
  deriving DecidableEq, Repr

/-- Handwritten boundary model for transport-visible response fields. -/
structure HiddenEvalTransportBoundaryModel where
  operation : OperationBoundaryModel
  clientOutput : ClientBoundaryModel
  finalize : FinalizeBoundaryModel
  deriving DecidableEq, Repr

/-- Handwritten boundary model for persisted state after accepted finalize. -/
structure HiddenEvalPersistedStateBoundaryModel where
  operation : wire.ServerEvalOperationV1
  rawRootMaterialDropped : Bool
  relayerThresholdShare32 : Array Std.U8 32#usize
  relayerPublicKey33 : Array Std.U8 33#usize
  thresholdPublicKey33 : Array Std.U8 33#usize
  thresholdEthereumAddress20 : Array Std.U8 20#usize
  retryCounter : UInt32
  deriving DecidableEq, Repr

/-- Handwritten boundary model for the frozen hidden-eval/reference seam. -/
structure HiddenEvalBoundaryModel where
  input : HiddenEvalInputBoundaryModel
  transport : HiddenEvalTransportBoundaryModel
  persisted : HiddenEvalPersistedStateBoundaryModel
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

theorem hidden_eval_extraction_target_is_frozen :
    ExtractionTarget.hiddenEvalBoundary =
      ExtractionTarget.hiddenEvalBoundary := by
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
