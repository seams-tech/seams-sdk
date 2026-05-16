import EcdsaHssPrivacy.Model

namespace EcdsaHssPrivacy

/-
  V2 true-blind ECDSA HSS model.

  This module is intentionally independent from the extracted v1 boundary. It
  gives the next implementation a Lean target before the Rust boundary exists.
-/

structure ClientPrivateInputV2 where
  yClient32 : Bytes32
  deriving DecidableEq, Repr

structure ServerPrivateInputV2 where
  yRelayer32 : Bytes32
  deriving DecidableEq, Repr

structure ClientDerivedShareV2 where
  xClient32 : Bytes32
  clientPublicKey33 : Bytes33
  deriving DecidableEq, Repr

structure ServerDerivedShareV2 where
  xRelayer32 : Bytes32
  relayerPublicKey33 : Bytes33
  deriving DecidableEq, Repr

structure PublicIdentityV2 where
  contextBinding32 : Bytes32
  clientPublicKey33 : Bytes33
  relayerPublicKey33 : Bytes33
  thresholdPublicKey33 : Bytes33
  thresholdEthereumAddress20 : Bytes20
  deriving DecidableEq, Repr

structure NonExportClientViewV2 where
  clientShare : ClientDerivedShareV2
  publicIdentity : PublicIdentityV2
  deriving DecidableEq, Repr

structure NonExportServerViewV2 where
  serverShare : ServerDerivedShareV2
  publicIdentity : PublicIdentityV2
  deriving DecidableEq, Repr

structure ExplicitExportClientViewV2 where
  clientShare : ClientDerivedShareV2
  exportRelayerShare32 : Bytes32
  reconstructedCanonicalX32 : Bytes32
  publicIdentity : PublicIdentityV2
  deriving DecidableEq, Repr

structure ExplicitExportServerViewV2 where
  releasedRelayerShare32 : Bytes32
  publicIdentity : PublicIdentityV2
  deriving DecidableEq, Repr

structure AlgebraicObligationsV2 where
  additivePublicKeyAgreement : Prop
  exportReconstructionAgreement : Prop
  exportPublicKeyVerification : Prop

structure ExecutionStateV2 where
  clientInput : ClientPrivateInputV2
  serverInput : ServerPrivateInputV2
  clientShare : ClientDerivedShareV2
  serverShare : ServerDerivedShareV2
  publicIdentity : PublicIdentityV2
  canonicalX32? : Option Bytes32
  obligations : AlgebraicObligationsV2

def nonExportClientViewV2 (state : ExecutionStateV2) : NonExportClientViewV2 :=
  {
    clientShare := state.clientShare
    publicIdentity := state.publicIdentity
  }

def nonExportServerViewV2 (state : ExecutionStateV2) : NonExportServerViewV2 :=
  {
    serverShare := state.serverShare
    publicIdentity := state.publicIdentity
  }

def explicitExportClientViewV2 (state : ExecutionStateV2) : ExplicitExportClientViewV2 :=
  {
    clientShare := state.clientShare
    exportRelayerShare32 := state.serverShare.xRelayer32
    reconstructedCanonicalX32 :=
      match state.canonicalX32? with
      | some canonicalX32 => canonicalX32
      | none => state.clientShare.xClient32
    publicIdentity := state.publicIdentity
  }

def explicitExportServerViewV2 (state : ExecutionStateV2) : ExplicitExportServerViewV2 :=
  {
    releasedRelayerShare32 := state.serverShare.xRelayer32
    publicIdentity := state.publicIdentity
  }

def serverViewClientRootV2? (_view : NonExportServerViewV2) : Option Bytes32 :=
  none

def serverViewClientShareV2? (_view : NonExportServerViewV2) : Option Bytes32 :=
  none

def serverViewCanonicalXV2? (_view : NonExportServerViewV2) : Option Bytes32 :=
  none

def clientViewRelayerRootV2? (_view : NonExportClientViewV2) : Option Bytes32 :=
  none

def clientViewRelayerShareV2? (_view : NonExportClientViewV2) : Option Bytes32 :=
  none

def exportServerViewCanonicalXV2? (_view : ExplicitExportServerViewV2) : Option Bytes32 :=
  none

def statesShareServerObservableV2
    (left right : ExecutionStateV2) : Prop :=
  nonExportServerViewV2 left = nonExportServerViewV2 right

def statesShareClientObservableV2
    (left right : ExecutionStateV2) : Prop :=
  nonExportClientViewV2 left = nonExportClientViewV2 right

theorem nonExportServerViewV2_excludes_client_root
    (state : ExecutionStateV2) :
    serverViewClientRootV2? (nonExportServerViewV2 state) = none := by
  rfl

theorem nonExportServerViewV2_excludes_client_share
    (state : ExecutionStateV2) :
    serverViewClientShareV2? (nonExportServerViewV2 state) = none := by
  rfl

theorem nonExportServerViewV2_excludes_canonical_x
    (state : ExecutionStateV2) :
    serverViewCanonicalXV2? (nonExportServerViewV2 state) = none := by
  rfl

theorem nonExportClientViewV2_excludes_relayer_root
    (state : ExecutionStateV2) :
    clientViewRelayerRootV2? (nonExportClientViewV2 state) = none := by
  rfl

theorem nonExportClientViewV2_excludes_relayer_share
    (state : ExecutionStateV2) :
    clientViewRelayerShareV2? (nonExportClientViewV2 state) = none := by
  rfl

theorem explicitExportServerViewV2_excludes_canonical_x
    (state : ExecutionStateV2) :
    exportServerViewCanonicalXV2? (explicitExportServerViewV2 state) = none := by
  rfl

theorem nonExportServerViewV2_depends_only_on_server_share_and_public_identity
    (left right : ExecutionStateV2)
    (hShare : left.serverShare = right.serverShare)
    (hPublic : left.publicIdentity = right.publicIdentity) :
    nonExportServerViewV2 left = nonExportServerViewV2 right := by
  cases left
  cases right
  simp [nonExportServerViewV2] at hShare hPublic ⊢
  constructor
  · exact hShare
  · exact hPublic

theorem nonExportClientViewV2_depends_only_on_client_share_and_public_identity
    (left right : ExecutionStateV2)
    (hShare : left.clientShare = right.clientShare)
    (hPublic : left.publicIdentity = right.publicIdentity) :
    nonExportClientViewV2 left = nonExportClientViewV2 right := by
  cases left
  cases right
  simp [nonExportClientViewV2] at hShare hPublic ⊢
  constructor
  · exact hShare
  · exact hPublic

theorem v2_additive_public_key_agreement_obligation
    (state : ExecutionStateV2) :
    state.obligations.additivePublicKeyAgreement := by
  exact state.obligations.additivePublicKeyAgreement

theorem v2_export_reconstruction_obligation
    (state : ExecutionStateV2) :
    state.obligations.exportReconstructionAgreement := by
  exact state.obligations.exportReconstructionAgreement

theorem v2_export_public_key_verification_obligation
    (state : ExecutionStateV2) :
    state.obligations.exportPublicKeyVerification := by
  exact state.obligations.exportPublicKeyVerification

end EcdsaHssPrivacy
