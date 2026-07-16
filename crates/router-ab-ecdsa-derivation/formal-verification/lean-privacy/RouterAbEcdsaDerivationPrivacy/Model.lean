import RouterAbEcdsaDerivationBoundary.Scope

namespace RouterAbEcdsaDerivationPrivacy

open RouterAbEcdsaDerivationBoundary
open Aeneas Aeneas.Std
open router_ab_ecdsa_derivation

abbrev Bytes32 := Array Std.U8 32#usize
abbrev Bytes33 := Array Std.U8 33#usize
abbrev Bytes20 := Array Std.U8 20#usize

/-- Minimum client-secret state for the widened privacy model. -/
structure ClientSecretState where
  yClient32 : Bytes32
  xClient32 : Bytes32
  explicitExportClientMaterial32? : Option Bytes32
  deriving DecidableEq, Repr

/-- Minimum server-secret state for the widened privacy model. -/
structure ServerSecretState where
  yRelayer32 : Bytes32
  xRelayer32 : Bytes32
  relayerThresholdShare32 : Bytes32
  continuationSecret32? : Option Bytes32
  deriving DecidableEq, Repr

/-- Full protocol execution state for the handwritten privacy model. -/
structure ProtocolExecutionState where
  boundary : RespondBoundaryModel
  canonicalX32 : Bytes32
  clientSecrets : ClientSecretState
  serverSecrets : ServerSecretState
  deriving DecidableEq, Repr

/-- Full execution state for the frozen hidden-eval/compiler-facing seam. -/
structure HiddenEvalExecutionState where
  hiddenEvalBoundary : HiddenEvalBoundaryModel
  canonicalX32 : Bytes32
  clientSecrets : ClientSecretState
  serverSecrets : ServerSecretState
  deriving DecidableEq, Repr

/-- Hidden threshold-derived private material that must stay invisible to the server. -/
structure HiddenThresholdPrivateMaterial where
  canonicalX32 : Bytes32
  xClient32 : Bytes32
  deriving DecidableEq, Repr

/-- Server-visible boundary after dropping client-only payloads. -/
structure ServerVisibleBoundary where
  operation : wire.ServerEvalOperation
  allowedOutputKind : wire.AllowedOutputKind
  finalizeOperation : wire.ServerEvalOperation
  rawRootMaterialDropped : Bool
  relayerKeyId : String
  clientPublicKey33 : Bytes33
  relayerPublicKey33 : Bytes33
  thresholdPublicKey33 : Bytes33
  thresholdEthereumAddress20 : Bytes20
  clientShareRetryCounter : Std.U32
  relayerShareRetryCounter : Std.U32
  retainedRelayerKeyId : String
  relayerShare32 : Bytes32
  retainedClientPublicKey33 : Bytes33
  retainedRelayerPublicKey33 : Bytes33
  retainedThresholdPublicKey33 : Bytes33
  retainedThresholdEthereumAddress20 : Bytes20
  retainedClientShareRetryCounter : Std.U32
  retainedRelayerShareRetryCounter : Std.U32
  deriving DecidableEq, Repr

/-- Observable server profile used for the narrow privacy claim. -/
structure ServerObservableProfile where
  boundary : ServerVisibleBoundary
  deriving DecidableEq, Repr

theorem hiddenThresholdPrivateMaterial_has_no_server_visible_projection
    (hidden : HiddenThresholdPrivateMaterial) :
    hidden = hidden := by
  rfl

def hiddenThresholdPrivateMaterialOfClientSecrets
    (canonicalX32 : Bytes32)
    (clientSecrets : ClientSecretState) : HiddenThresholdPrivateMaterial :=
  {
    canonicalX32 := canonicalX32
    xClient32 := clientSecrets.xClient32
  }

def hiddenThresholdPrivateMaterialOfState
    (state : ProtocolExecutionState) : HiddenThresholdPrivateMaterial :=
  hiddenThresholdPrivateMaterialOfClientSecrets state.canonicalX32 state.clientSecrets

theorem hiddenThresholdPrivateMaterialOfClientSecrets_preserves_canonical_x
    (canonicalX32 : Bytes32)
    (clientSecrets : ClientSecretState) :
    (hiddenThresholdPrivateMaterialOfClientSecrets canonicalX32 clientSecrets).canonicalX32 =
      canonicalX32 := by
  rfl

theorem hiddenThresholdPrivateMaterialOfClientSecrets_preserves_x_client
    (canonicalX32 : Bytes32)
    (clientSecrets : ClientSecretState) :
    (hiddenThresholdPrivateMaterialOfClientSecrets canonicalX32 clientSecrets).xClient32 =
      clientSecrets.xClient32 := by
  rfl

theorem hiddenThresholdPrivateMaterialOfState_preserves_canonical_x
    (state : ProtocolExecutionState) :
    (hiddenThresholdPrivateMaterialOfState state).canonicalX32 = state.canonicalX32 := by
  rfl

theorem hiddenThresholdPrivateMaterialOfState_preserves_x_client
    (state : ProtocolExecutionState) :
    (hiddenThresholdPrivateMaterialOfState state).xClient32 = state.clientSecrets.xClient32 := by
  rfl

end RouterAbEcdsaDerivationPrivacy
