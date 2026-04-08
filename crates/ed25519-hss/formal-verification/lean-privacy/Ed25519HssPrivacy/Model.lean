namespace Ed25519HssPrivacy

abbrev Bytes32 := Fin 32 → UInt8

inductive Operation where
  | registration
  | txSigning
  | linkDevice
  | emailRecovery
  | warmSessionReconstruction
  | explicitKeyExport
  deriving DecidableEq, Repr

inductive AllowedOutputKind where
  | clientOutputOnly
  | clientOutputAndSeedOutput
  deriving DecidableEq, Repr

def allowedOutputKindForOperation : Operation → AllowedOutputKind
  | .explicitKeyExport => .clientOutputAndSeedOutput
  | _ => .clientOutputOnly

def Operation.isExplicitExport : Operation → Bool
  | .explicitKeyExport => true
  | _ => false

structure PublicParameters where
  operation : Operation
  allowedOutputKind : AllowedOutputKind
  contextBinding : Bytes32
  runBinding : Bytes32
  publicKey : Bytes32
  deriving Repr

def PublicParameters.fromOperation
    (operation : Operation)
    (contextBinding runBinding publicKey : Bytes32) : PublicParameters :=
  {
    operation,
    allowedOutputKind := allowedOutputKindForOperation operation,
    contextBinding,
    runBinding,
    publicKey,
  }

structure ClientSecretState where
  yClient : Bytes32
  tauClient : Bytes32
  deriving Repr

structure ServerSecretState where
  yRelayer : Bytes32
  tauRelayer : Bytes32
  deriving Repr

structure NonExportVisibleBoundary where
  canonicalSeed : Bytes32
  xClientBase : Bytes32
  xRelayerBase : Bytes32
  deriving Repr

structure ExplicitExportBoundary where
  nonExport : NonExportVisibleBoundary
  seedOutput : Bytes32
  deriving Repr

inductive VisibleBoundary where
  | nonExport (boundary : NonExportVisibleBoundary)
  | explicitExport (boundary : ExplicitExportBoundary)
  deriving Repr

def VisibleBoundary.allowedOutputKind : VisibleBoundary → AllowedOutputKind
  | .nonExport _ => .clientOutputOnly
  | .explicitExport _ => .clientOutputAndSeedOutput

def VisibleBoundary.nonExportProjection : VisibleBoundary → NonExportVisibleBoundary
  | .nonExport boundary => boundary
  | .explicitExport boundary => boundary.nonExport

def VisibleBoundary.seedOutput? : VisibleBoundary → Option Bytes32
  | .nonExport _ => none
  | .explicitExport boundary => some boundary.seedOutput

theorem fromOperation_allowedOutputKind
    (operation : Operation)
    (contextBinding runBinding publicKey : Bytes32) :
    (PublicParameters.fromOperation operation contextBinding runBinding publicKey).allowedOutputKind
      = allowedOutputKindForOperation operation := rfl

theorem visibleBoundary_allowedOutputKind_nonExport
    (boundary : NonExportVisibleBoundary) :
    (VisibleBoundary.nonExport boundary).allowedOutputKind = .clientOutputOnly := rfl

theorem visibleBoundary_allowedOutputKind_explicitExport
    (boundary : ExplicitExportBoundary) :
    (VisibleBoundary.explicitExport boundary).allowedOutputKind = .clientOutputAndSeedOutput := rfl

end Ed25519HssPrivacy
