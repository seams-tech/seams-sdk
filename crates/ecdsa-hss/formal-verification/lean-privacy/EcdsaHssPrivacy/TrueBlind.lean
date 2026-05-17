import EcdsaHssPrivacy.Model

namespace EcdsaHssPrivacy.TrueBlind

noncomputable section

/-
  True-blind ECDSA HSS model.

  This module is intentionally independent from the extracted v1 boundary. It
  gives the next implementation a Lean target before the Rust boundary exists.
-/

def secp256k1Order : Nat :=
  115792089237316195423570985008687907852837564279074904382605163141518161494337

theorem secp256k1Order_pos : 0 < secp256k1Order := by
  native_decide

abbrev Scalar := Fin secp256k1Order

structure PublicPoint where
  compressed33 : Bytes33
  deriving DecidableEq, Repr

def scalarAdd (left right : Scalar) : Scalar :=
  ⟨(left.val + right.val) % secp256k1Order,
    Nat.mod_lt (left.val + right.val) secp256k1Order_pos⟩

axiom scalarToBytes32 : Scalar → Bytes32

axiom scalarBaseMul : Scalar → PublicPoint

axiom pointAdd : PublicPoint → PublicPoint → PublicPoint

axiom ethereumAddress : PublicPoint → Bytes20

def pointOfCompressed33 (bytes : Bytes33) : PublicPoint :=
  {
    compressed33 := bytes
  }

structure ClientPrivateInput where
  yClient32 : Bytes32
  deriving DecidableEq, Repr

structure ServerPrivateInput where
  yRelayer32 : Bytes32
  deriving DecidableEq, Repr

structure PublicContext where
  contextBinding32 : Bytes32
  deriving DecidableEq, Repr

structure ClientDerivedShare where
  xClient : Scalar
  xClient32 : Bytes32
  clientPublicPoint : PublicPoint
  clientPublicKey33 : Bytes33
  deriving DecidableEq, Repr

structure ServerDerivedShare where
  xRelayer : Scalar
  xRelayer32 : Bytes32
  relayerPublicPoint : PublicPoint
  relayerPublicKey33 : Bytes33
  deriving DecidableEq, Repr

axiom deriveClientShare : PublicContext → ClientPrivateInput → ClientDerivedShare

axiom deriveServerShare : PublicContext → ServerPrivateInput → ServerDerivedShare

structure PublicIdentity where
  contextBinding32 : Bytes32
  clientPublicKey33 : Bytes33
  relayerPublicKey33 : Bytes33
  thresholdPublicPoint : PublicPoint
  thresholdPublicKey33 : Bytes33
  thresholdEthereumAddress20 : Bytes20
  deriving DecidableEq, Repr

def thresholdPublicPointOfShares
    (clientShare : ClientDerivedShare)
    (serverShare : ServerDerivedShare) : PublicPoint :=
  pointAdd clientShare.clientPublicPoint serverShare.relayerPublicPoint

def derivePublicIdentity
    (context : PublicContext)
    (clientShare : ClientDerivedShare)
    (serverShare : ServerDerivedShare) : PublicIdentity :=
  let thresholdPublicPoint := thresholdPublicPointOfShares clientShare serverShare
  {
    contextBinding32 := context.contextBinding32
    clientPublicKey33 := clientShare.clientPublicKey33
    relayerPublicKey33 := serverShare.relayerPublicKey33
    thresholdPublicPoint := thresholdPublicPoint
    thresholdPublicKey33 := thresholdPublicPoint.compressed33
    thresholdEthereumAddress20 := ethereumAddress thresholdPublicPoint
  }

structure NonExportClientView where
  clientShare : ClientDerivedShare
  publicIdentity : PublicIdentity
  deriving DecidableEq, Repr

structure NonExportServerView where
  serverShare : ServerDerivedShare
  publicIdentity : PublicIdentity
  deriving DecidableEq, Repr

structure ExplicitExportClientView where
  clientShare : ClientDerivedShare
  exportRelayerShare32 : Bytes32
  reconstructedCanonicalX : Scalar
  reconstructedCanonicalX32 : Bytes32
  publicIdentity : PublicIdentity
  deriving DecidableEq, Repr

structure ExplicitExportServerView where
  releasedRelayerShare32 : Bytes32
  publicIdentity : PublicIdentity
  deriving DecidableEq, Repr

structure ExecutionState where
  clientInput : ClientPrivateInput
  serverInput : ServerPrivateInput
  clientShare : ClientDerivedShare
  serverShare : ServerDerivedShare
  publicIdentity : PublicIdentity
  deriving DecidableEq, Repr

def idealExecutionState
    (context : PublicContext)
    (clientInput : ClientPrivateInput)
    (serverInput : ServerPrivateInput) : ExecutionState :=
  let clientShare := deriveClientShare context clientInput
  let serverShare := deriveServerShare context serverInput
  {
    clientInput := clientInput
    serverInput := serverInput
    clientShare := clientShare
    serverShare := serverShare
    publicIdentity := derivePublicIdentity context clientShare serverShare
  }

def reconstructedCanonicalScalar (state : ExecutionState) : Scalar :=
  scalarAdd state.clientShare.xClient state.serverShare.xRelayer

def clientSharePublicKeyAgreement (share : ClientDerivedShare) : Prop :=
  share.xClient32 = scalarToBytes32 share.xClient ∧
  share.clientPublicPoint = scalarBaseMul share.xClient ∧
  share.clientPublicKey33 = share.clientPublicPoint.compressed33

def serverSharePublicKeyAgreement (share : ServerDerivedShare) : Prop :=
  share.xRelayer32 = scalarToBytes32 share.xRelayer ∧
  share.relayerPublicPoint = scalarBaseMul share.xRelayer ∧
  share.relayerPublicKey33 = share.relayerPublicPoint.compressed33

def additivePublicKeyAgreement (state : ExecutionState) : Prop :=
  state.publicIdentity.clientPublicKey33 = state.clientShare.clientPublicKey33 ∧
  state.publicIdentity.relayerPublicKey33 = state.serverShare.relayerPublicKey33 ∧
  state.publicIdentity.thresholdPublicPoint =
    pointAdd state.clientShare.clientPublicPoint state.serverShare.relayerPublicPoint ∧
  state.publicIdentity.thresholdPublicKey33 =
    state.publicIdentity.thresholdPublicPoint.compressed33

def exportReconstructionAgreement
    (state : ExecutionState)
    (view : ExplicitExportClientView) : Prop :=
  view.exportRelayerShare32 = state.serverShare.xRelayer32 ∧
  view.reconstructedCanonicalX = reconstructedCanonicalScalar state ∧
  view.reconstructedCanonicalX32 =
    scalarToBytes32 (reconstructedCanonicalScalar state)

def exportPublicKeyVerification (state : ExecutionState) : Prop :=
  state.publicIdentity.thresholdPublicPoint =
    scalarBaseMul (reconstructedCanonicalScalar state) ∧
  state.publicIdentity.thresholdPublicKey33 =
    state.publicIdentity.thresholdPublicPoint.compressed33

def addressAgreement (state : ExecutionState) : Prop :=
  state.publicIdentity.thresholdEthereumAddress20 =
    ethereumAddress state.publicIdentity.thresholdPublicPoint

def wellFormedExecutionState (state : ExecutionState) : Prop :=
  clientSharePublicKeyAgreement state.clientShare ∧
  serverSharePublicKeyAgreement state.serverShare ∧
  additivePublicKeyAgreement state ∧
  exportPublicKeyVerification state ∧
  addressAgreement state

structure DerivationAssumptions where
  clientShareAgreement :
    ∀ (context : PublicContext) (clientInput : ClientPrivateInput),
      clientSharePublicKeyAgreement (deriveClientShare context clientInput)
  serverShareAgreement :
    ∀ (context : PublicContext) (serverInput : ServerPrivateInput),
      serverSharePublicKeyAgreement (deriveServerShare context serverInput)
  scalarBaseMulAdd :
    ∀ (left right : Scalar),
      scalarBaseMul (scalarAdd left right) =
        pointAdd (scalarBaseMul left) (scalarBaseMul right)

def nonExportClientView (state : ExecutionState) : NonExportClientView :=
  {
    clientShare := state.clientShare
    publicIdentity := state.publicIdentity
  }

def nonExportServerView (state : ExecutionState) : NonExportServerView :=
  {
    serverShare := state.serverShare
    publicIdentity := state.publicIdentity
  }

def explicitExportClientView (state : ExecutionState) : ExplicitExportClientView :=
  {
    clientShare := state.clientShare
    exportRelayerShare32 := state.serverShare.xRelayer32
    reconstructedCanonicalX := reconstructedCanonicalScalar state
    reconstructedCanonicalX32 := scalarToBytes32 (reconstructedCanonicalScalar state)
    publicIdentity := state.publicIdentity
  }

def explicitExportServerView (state : ExecutionState) : ExplicitExportServerView :=
  {
    releasedRelayerShare32 := state.serverShare.xRelayer32
    publicIdentity := state.publicIdentity
  }

structure IdealFunctionalityOutput where
  state : ExecutionState
  nonExportClient : NonExportClientView
  nonExportServer : NonExportServerView
  explicitExportClient : ExplicitExportClientView
  explicitExportServer : ExplicitExportServerView
  deriving DecidableEq, Repr

def idealFunctionalityOutputOfState
    (state : ExecutionState) : IdealFunctionalityOutput :=
  {
    state := state
    nonExportClient := nonExportClientView state
    nonExportServer := nonExportServerView state
    explicitExportClient := explicitExportClientView state
    explicitExportServer := explicitExportServerView state
  }

def F_ecdsa_hss_true_blind
    (context : PublicContext)
    (clientInput : ClientPrivateInput)
    (serverInput : ServerPrivateInput) : IdealFunctionalityOutput :=
  idealFunctionalityOutputOfState
    (idealExecutionState context clientInput serverInput)

def idealFunctionalityWellFormed
    (context : PublicContext)
    (clientInput : ClientPrivateInput)
    (serverInput : ServerPrivateInput) : Prop :=
  wellFormedExecutionState
    (F_ecdsa_hss_true_blind context clientInput serverInput).state

structure NonExportClientSimulatorInput where
  clientShare : ClientDerivedShare
  publicIdentity : PublicIdentity
  deriving DecidableEq, Repr

structure NonExportServerSimulatorInput where
  serverShare : ServerDerivedShare
  publicIdentity : PublicIdentity
  deriving DecidableEq, Repr

structure ExplicitExportClientSimulatorInput where
  clientShare : ClientDerivedShare
  releasedRelayerShare : ServerDerivedShare
  publicIdentity : PublicIdentity
  deriving DecidableEq, Repr

structure ExplicitExportServerSimulatorInput where
  releasedRelayerShare32 : Bytes32
  publicIdentity : PublicIdentity
  deriving DecidableEq, Repr

def simulateNonExportClientView
    (input : NonExportClientSimulatorInput) : NonExportClientView :=
  {
    clientShare := input.clientShare
    publicIdentity := input.publicIdentity
  }

def simulateNonExportServerView
    (input : NonExportServerSimulatorInput) : NonExportServerView :=
  {
    serverShare := input.serverShare
    publicIdentity := input.publicIdentity
  }

def simulateExplicitExportClientView
    (input : ExplicitExportClientSimulatorInput) : ExplicitExportClientView :=
  let reconstructedCanonicalX :=
    scalarAdd input.clientShare.xClient input.releasedRelayerShare.xRelayer
  {
    clientShare := input.clientShare
    exportRelayerShare32 := input.releasedRelayerShare.xRelayer32
    reconstructedCanonicalX := reconstructedCanonicalX
    reconstructedCanonicalX32 := scalarToBytes32 reconstructedCanonicalX
    publicIdentity := input.publicIdentity
  }

def simulateExplicitExportServerView
    (input : ExplicitExportServerSimulatorInput) : ExplicitExportServerView :=
  {
    releasedRelayerShare32 := input.releasedRelayerShare32
    publicIdentity := input.publicIdentity
  }

def serverViewClientRoot? (_view : NonExportServerView) : Option Bytes32 :=
  none

def serverViewClientShare? (_view : NonExportServerView) : Option Bytes32 :=
  none

def serverViewCanonicalX? (_view : NonExportServerView) : Option Bytes32 :=
  none

def clientViewRelayerRoot? (_view : NonExportClientView) : Option Bytes32 :=
  none

def clientViewRelayerShare? (_view : NonExportClientView) : Option Bytes32 :=
  none

def exportServerViewCanonicalX? (_view : ExplicitExportServerView) : Option Bytes32 :=
  none

inductive ClientOperationView where
  | nonExport : NonExportClientView → ClientOperationView
  | explicitExport : ExplicitExportClientView → ClientOperationView
  deriving DecidableEq, Repr

inductive ServerOperationView where
  | nonExport : NonExportServerView → ServerOperationView
  | explicitExport : ExplicitExportServerView → ServerOperationView
  deriving DecidableEq, Repr

inductive OperationKind where
  | nonExport : OperationKind
  | explicitExport : OperationKind
  deriving DecidableEq, Repr

structure PublicTranscript where
  contextBinding32 : Bytes32
  clientPublicKey33 : Bytes33
  relayerPublicKey33 : Bytes33
  thresholdPublicKey33 : Bytes33
  thresholdEthereumAddress20 : Bytes20
  operation : OperationKind
  transcriptDigest32 : Bytes32
  deriving DecidableEq, Repr

axiom publicTranscriptDigest : PublicIdentity → OperationKind → Bytes32

def clientOperationViewRelayerRoot? : ClientOperationView → Option Bytes32
  | .nonExport view => clientViewRelayerRoot? view
  | .explicitExport _view => none

def clientOperationViewRelayerShare? : ClientOperationView → Option Bytes32
  | .nonExport view => clientViewRelayerShare? view
  | .explicitExport view => some view.exportRelayerShare32

def clientOperationViewCanonicalX? : ClientOperationView → Option Bytes32
  | .nonExport _view => none
  | .explicitExport view => some view.reconstructedCanonicalX32

def serverOperationViewClientRoot? : ServerOperationView → Option Bytes32
  | .nonExport view => serverViewClientRoot? view
  | .explicitExport _view => none

def serverOperationViewClientShare? : ServerOperationView → Option Bytes32
  | .nonExport view => serverViewClientShare? view
  | .explicitExport _view => none

def serverOperationViewCanonicalX? : ServerOperationView → Option Bytes32
  | .nonExport view => serverViewCanonicalX? view
  | .explicitExport view => exportServerViewCanonicalX? view

def clientOperationViewPublicIdentity : ClientOperationView → PublicIdentity
  | .nonExport view => view.publicIdentity
  | .explicitExport view => view.publicIdentity

def serverOperationViewPublicIdentity : ServerOperationView → PublicIdentity
  | .nonExport view => view.publicIdentity
  | .explicitExport view => view.publicIdentity

def clientOperationViewKind : ClientOperationView → OperationKind
  | .nonExport _view => .nonExport
  | .explicitExport _view => .explicitExport

def serverOperationViewKind : ServerOperationView → OperationKind
  | .nonExport _view => .nonExport
  | .explicitExport _view => .explicitExport

def publicTranscriptOfIdentity
    (publicIdentity : PublicIdentity)
    (operation : OperationKind) : PublicTranscript :=
  {
    contextBinding32 := publicIdentity.contextBinding32
    clientPublicKey33 := publicIdentity.clientPublicKey33
    relayerPublicKey33 := publicIdentity.relayerPublicKey33
    thresholdPublicKey33 := publicIdentity.thresholdPublicKey33
    thresholdEthereumAddress20 := publicIdentity.thresholdEthereumAddress20
    operation := operation
    transcriptDigest32 := publicTranscriptDigest publicIdentity operation
  }

def publicTranscriptOfClientOperationView
    (view : ClientOperationView) : PublicTranscript :=
  publicTranscriptOfIdentity
    (clientOperationViewPublicIdentity view)
    (clientOperationViewKind view)

def publicTranscriptOfServerOperationView
    (view : ServerOperationView) : PublicTranscript :=
  publicTranscriptOfIdentity
    (serverOperationViewPublicIdentity view)
    (serverOperationViewKind view)

def publicTranscriptClientRoot? (_transcript : PublicTranscript) : Option Bytes32 :=
  none

def publicTranscriptClientShare? (_transcript : PublicTranscript) : Option Bytes32 :=
  none

def publicTranscriptRelayerRoot? (_transcript : PublicTranscript) : Option Bytes32 :=
  none

def publicTranscriptRelayerShare? (_transcript : PublicTranscript) : Option Bytes32 :=
  none

def publicTranscriptCanonicalX? (_transcript : PublicTranscript) : Option Bytes32 :=
  none

def idealNonExportClientOperationView
    (output : IdealFunctionalityOutput) : ClientOperationView :=
  .nonExport output.nonExportClient

def idealExplicitExportClientOperationView
    (output : IdealFunctionalityOutput) : ClientOperationView :=
  .explicitExport output.explicitExportClient

def idealNonExportServerOperationView
    (output : IdealFunctionalityOutput) : ServerOperationView :=
  .nonExport output.nonExportServer

def idealExplicitExportServerOperationView
    (output : IdealFunctionalityOutput) : ServerOperationView :=
  .explicitExport output.explicitExportServer

def statesShareServerObservable
    (left right : ExecutionState) : Prop :=
  nonExportServerView left = nonExportServerView right

def statesShareClientObservable
    (left right : ExecutionState) : Prop :=
  nonExportClientView left = nonExportClientView right

def statesVaryOnlyInClientSecrets
    (left right : ExecutionState) : Prop :=
  left.serverShare = right.serverShare ∧
  left.publicIdentity = right.publicIdentity

def statesVaryOnlyInServerSecrets
    (left right : ExecutionState) : Prop :=
  left.clientShare = right.clientShare ∧
  left.publicIdentity = right.publicIdentity

def ServerViewIndistinguishableUnderClientSecretVariation : Prop :=
  ∀ (left right : ExecutionState),
    statesVaryOnlyInClientSecrets left right →
    nonExportServerView left = nonExportServerView right

def ClientViewIndistinguishableUnderServerSecretVariation : Prop :=
  ∀ (left right : ExecutionState),
    statesVaryOnlyInServerSecrets left right →
    nonExportClientView left = nonExportClientView right

theorem nonExportServerView_excludes_client_root
    (state : ExecutionState) :
    serverViewClientRoot? (nonExportServerView state) = none := by
  rfl

theorem nonExportServerView_excludes_client_share
    (state : ExecutionState) :
    serverViewClientShare? (nonExportServerView state) = none := by
  rfl

theorem nonExportServerView_excludes_canonical_x
    (state : ExecutionState) :
    serverViewCanonicalX? (nonExportServerView state) = none := by
  rfl

theorem nonExportClientView_excludes_relayer_root
    (state : ExecutionState) :
    clientViewRelayerRoot? (nonExportClientView state) = none := by
  rfl

theorem nonExportClientView_excludes_relayer_share
    (state : ExecutionState) :
    clientViewRelayerShare? (nonExportClientView state) = none := by
  rfl

theorem explicitExportServerView_excludes_canonical_x
    (state : ExecutionState) :
    exportServerViewCanonicalX? (explicitExportServerView state) = none := by
  rfl

theorem clientOperationView_non_export_excludes_relayer_root
    (view : NonExportClientView) :
    clientOperationViewRelayerRoot? (.nonExport view) = none := by
  rfl

theorem clientOperationView_non_export_excludes_relayer_share
    (view : NonExportClientView) :
    clientOperationViewRelayerShare? (.nonExport view) = none := by
  rfl

theorem clientOperationView_non_export_excludes_canonical_x
    (view : NonExportClientView) :
    clientOperationViewCanonicalX? (.nonExport view) = none := by
  rfl

theorem clientOperationView_explicit_export_excludes_relayer_root
    (view : ExplicitExportClientView) :
    clientOperationViewRelayerRoot? (.explicitExport view) = none := by
  rfl

theorem clientOperationView_explicit_export_releases_relayer_share
    (view : ExplicitExportClientView) :
    clientOperationViewRelayerShare? (.explicitExport view) =
      some view.exportRelayerShare32 := by
  rfl

theorem clientOperationView_explicit_export_releases_canonical_x
    (view : ExplicitExportClientView) :
    clientOperationViewCanonicalX? (.explicitExport view) =
      some view.reconstructedCanonicalX32 := by
  rfl

theorem serverOperationView_non_export_excludes_client_root
    (view : NonExportServerView) :
    serverOperationViewClientRoot? (.nonExport view) = none := by
  rfl

theorem serverOperationView_non_export_excludes_client_share
    (view : NonExportServerView) :
    serverOperationViewClientShare? (.nonExport view) = none := by
  rfl

theorem serverOperationView_non_export_excludes_canonical_x
    (view : NonExportServerView) :
    serverOperationViewCanonicalX? (.nonExport view) = none := by
  rfl

theorem serverOperationView_explicit_export_excludes_client_root
    (view : ExplicitExportServerView) :
    serverOperationViewClientRoot? (.explicitExport view) = none := by
  rfl

theorem serverOperationView_explicit_export_excludes_client_share
    (view : ExplicitExportServerView) :
    serverOperationViewClientShare? (.explicitExport view) = none := by
  rfl

theorem serverOperationView_explicit_export_excludes_canonical_x
    (view : ExplicitExportServerView) :
    serverOperationViewCanonicalX? (.explicitExport view) = none := by
  rfl

theorem idealNonExportClientOperationView_excludes_relayer_share
    (output : IdealFunctionalityOutput) :
    clientOperationViewRelayerShare?
        (idealNonExportClientOperationView output) =
      none := by
  rfl

theorem idealExplicitExportClientOperationView_releases_relayer_share
    (output : IdealFunctionalityOutput) :
    clientOperationViewRelayerShare?
        (idealExplicitExportClientOperationView output) =
      some output.explicitExportClient.exportRelayerShare32 := by
  rfl

theorem idealExplicitExportClientOperationView_releases_canonical_x
    (output : IdealFunctionalityOutput) :
    clientOperationViewCanonicalX?
        (idealExplicitExportClientOperationView output) =
      some output.explicitExportClient.reconstructedCanonicalX32 := by
  rfl

theorem idealExplicitExportServerOperationView_excludes_canonical_x
    (output : IdealFunctionalityOutput) :
    serverOperationViewCanonicalX?
        (idealExplicitExportServerOperationView output) =
      none := by
  rfl

theorem publicTranscriptOfIdentity_preserves_context
    (publicIdentity : PublicIdentity)
    (operation : OperationKind) :
    (publicTranscriptOfIdentity publicIdentity operation).contextBinding32 =
      publicIdentity.contextBinding32 := by
  rfl

theorem publicTranscriptOfIdentity_preserves_client_public_key
    (publicIdentity : PublicIdentity)
    (operation : OperationKind) :
    (publicTranscriptOfIdentity publicIdentity operation).clientPublicKey33 =
      publicIdentity.clientPublicKey33 := by
  rfl

theorem publicTranscriptOfIdentity_preserves_relayer_public_key
    (publicIdentity : PublicIdentity)
    (operation : OperationKind) :
    (publicTranscriptOfIdentity publicIdentity operation).relayerPublicKey33 =
      publicIdentity.relayerPublicKey33 := by
  rfl

theorem publicTranscriptOfIdentity_preserves_threshold_public_key
    (publicIdentity : PublicIdentity)
    (operation : OperationKind) :
    (publicTranscriptOfIdentity publicIdentity operation).thresholdPublicKey33 =
      publicIdentity.thresholdPublicKey33 := by
  rfl

theorem publicTranscriptOfIdentity_preserves_threshold_address
    (publicIdentity : PublicIdentity)
    (operation : OperationKind) :
    (publicTranscriptOfIdentity publicIdentity operation).thresholdEthereumAddress20 =
      publicIdentity.thresholdEthereumAddress20 := by
  rfl

theorem publicTranscript_excludes_client_root
    (transcript : PublicTranscript) :
    publicTranscriptClientRoot? transcript = none := by
  rfl

theorem publicTranscript_excludes_client_share
    (transcript : PublicTranscript) :
    publicTranscriptClientShare? transcript = none := by
  rfl

theorem publicTranscript_excludes_relayer_root
    (transcript : PublicTranscript) :
    publicTranscriptRelayerRoot? transcript = none := by
  rfl

theorem publicTranscript_excludes_relayer_share
    (transcript : PublicTranscript) :
    publicTranscriptRelayerShare? transcript = none := by
  rfl

theorem publicTranscript_excludes_canonical_x
    (transcript : PublicTranscript) :
    publicTranscriptCanonicalX? transcript = none := by
  rfl

theorem publicTranscriptOfClientOperationView_preserves_public_identity
    (view : ClientOperationView) :
    (publicTranscriptOfClientOperationView view).contextBinding32 =
      (clientOperationViewPublicIdentity view).contextBinding32 ∧
    (publicTranscriptOfClientOperationView view).clientPublicKey33 =
      (clientOperationViewPublicIdentity view).clientPublicKey33 ∧
    (publicTranscriptOfClientOperationView view).relayerPublicKey33 =
      (clientOperationViewPublicIdentity view).relayerPublicKey33 ∧
    (publicTranscriptOfClientOperationView view).thresholdPublicKey33 =
      (clientOperationViewPublicIdentity view).thresholdPublicKey33 ∧
    (publicTranscriptOfClientOperationView view).thresholdEthereumAddress20 =
      (clientOperationViewPublicIdentity view).thresholdEthereumAddress20 := by
  cases view <;> simp [
    publicTranscriptOfClientOperationView,
    publicTranscriptOfIdentity,
    clientOperationViewPublicIdentity,
    clientOperationViewKind,
  ]

theorem publicTranscriptOfServerOperationView_preserves_public_identity
    (view : ServerOperationView) :
    (publicTranscriptOfServerOperationView view).contextBinding32 =
      (serverOperationViewPublicIdentity view).contextBinding32 ∧
    (publicTranscriptOfServerOperationView view).clientPublicKey33 =
      (serverOperationViewPublicIdentity view).clientPublicKey33 ∧
    (publicTranscriptOfServerOperationView view).relayerPublicKey33 =
      (serverOperationViewPublicIdentity view).relayerPublicKey33 ∧
    (publicTranscriptOfServerOperationView view).thresholdPublicKey33 =
      (serverOperationViewPublicIdentity view).thresholdPublicKey33 ∧
    (publicTranscriptOfServerOperationView view).thresholdEthereumAddress20 =
      (serverOperationViewPublicIdentity view).thresholdEthereumAddress20 := by
  cases view <;> simp [
    publicTranscriptOfServerOperationView,
    publicTranscriptOfIdentity,
    serverOperationViewPublicIdentity,
    serverOperationViewKind,
  ]

theorem publicTranscriptOfClientOperationView_excludes_canonical_x
    (view : ClientOperationView) :
    publicTranscriptCanonicalX?
        (publicTranscriptOfClientOperationView view) =
      none := by
  rfl

theorem publicTranscriptOfServerOperationView_excludes_canonical_x
    (view : ServerOperationView) :
    publicTranscriptCanonicalX?
        (publicTranscriptOfServerOperationView view) =
      none := by
  rfl

theorem nonExportServerView_depends_only_on_server_share_and_public_identity
    (left right : ExecutionState)
    (hShare : left.serverShare = right.serverShare)
    (hPublic : left.publicIdentity = right.publicIdentity) :
    nonExportServerView left = nonExportServerView right := by
  cases left
  cases right
  simp [nonExportServerView] at hShare hPublic ⊢
  constructor
  · exact hShare
  · exact hPublic

theorem nonExportClientView_depends_only_on_client_share_and_public_identity
    (left right : ExecutionState)
    (hShare : left.clientShare = right.clientShare)
    (hPublic : left.publicIdentity = right.publicIdentity) :
    nonExportClientView left = nonExportClientView right := by
  cases left
  cases right
  simp [nonExportClientView] at hShare hPublic ⊢
  constructor
  · exact hShare
  · exact hPublic

theorem serverViewIndistinguishableUnderClientSecretVariation_proved :
    ServerViewIndistinguishableUnderClientSecretVariation := by
  intro left right hVariation
  rcases hVariation with ⟨hShare, hPublic⟩
  exact nonExportServerView_depends_only_on_server_share_and_public_identity
    left right hShare hPublic

theorem clientViewIndistinguishableUnderServerSecretVariation_proved :
    ClientViewIndistinguishableUnderServerSecretVariation := by
  intro left right hVariation
  rcases hVariation with ⟨hShare, hPublic⟩
  exact nonExportClientView_depends_only_on_client_share_and_public_identity
    left right hShare hPublic

theorem explicitExportClientView_reconstructs_additive_scalar
    (state : ExecutionState) :
    (explicitExportClientView state).reconstructedCanonicalX =
      scalarAdd state.clientShare.xClient state.serverShare.xRelayer := by
  rfl

theorem explicitExportClientView_releases_server_share
    (state : ExecutionState) :
    (explicitExportClientView state).exportRelayerShare32 =
      state.serverShare.xRelayer32 := by
  rfl

theorem explicitExportClientView_satisfies_reconstruction_relation
    (state : ExecutionState) :
    exportReconstructionAgreement state (explicitExportClientView state) := by
  constructor
  · rfl
  constructor
  · rfl
  · rfl

theorem simulateNonExportClientView_matches_state
    (state : ExecutionState) :
    simulateNonExportClientView
        {
          clientShare := state.clientShare
          publicIdentity := state.publicIdentity
        }
      =
      nonExportClientView state := by
  rfl

theorem simulateNonExportServerView_matches_state
    (state : ExecutionState) :
    simulateNonExportServerView
        {
          serverShare := state.serverShare
          publicIdentity := state.publicIdentity
        }
      =
      nonExportServerView state := by
  rfl

theorem simulateExplicitExportClientView_matches_state
    (state : ExecutionState) :
    simulateExplicitExportClientView
        {
          clientShare := state.clientShare
          releasedRelayerShare := state.serverShare
          publicIdentity := state.publicIdentity
        }
      =
      explicitExportClientView state := by
  rfl

theorem simulateExplicitExportServerView_matches_state
    (state : ExecutionState) :
    simulateExplicitExportServerView
        {
          releasedRelayerShare32 := state.serverShare.xRelayer32
          publicIdentity := state.publicIdentity
        }
      =
      explicitExportServerView state := by
  rfl

theorem idealExecutionState_additive_public_key_agreement
    (context : PublicContext)
    (clientInput : ClientPrivateInput)
    (serverInput : ServerPrivateInput) :
    additivePublicKeyAgreement
      (idealExecutionState context clientInput serverInput) := by
  simp [
    idealExecutionState,
    additivePublicKeyAgreement,
    derivePublicIdentity,
    thresholdPublicPointOfShares,
  ]

theorem idealExecutionState_client_share_public_key_agreement
    (assumptions : DerivationAssumptions)
    (context : PublicContext)
    (clientInput : ClientPrivateInput)
    (serverInput : ServerPrivateInput) :
    clientSharePublicKeyAgreement
      (idealExecutionState context clientInput serverInput).clientShare := by
  simpa [idealExecutionState]
    using assumptions.clientShareAgreement context clientInput

theorem idealExecutionState_server_share_public_key_agreement
    (assumptions : DerivationAssumptions)
    (context : PublicContext)
    (clientInput : ClientPrivateInput)
    (serverInput : ServerPrivateInput) :
    serverSharePublicKeyAgreement
      (idealExecutionState context clientInput serverInput).serverShare := by
  simpa [idealExecutionState]
    using assumptions.serverShareAgreement context serverInput

theorem idealExecutionState_export_public_key_verification
    (assumptions : DerivationAssumptions)
    (context : PublicContext)
    (clientInput : ClientPrivateInput)
    (serverInput : ServerPrivateInput) :
    exportPublicKeyVerification
      (idealExecutionState context clientInput serverInput) := by
  constructor
  · have hClient :=
      assumptions.clientShareAgreement context clientInput
    have hServer :=
      assumptions.serverShareAgreement context serverInput
    rcases hClient with ⟨_hClientBytes, hClientPoint, _hClientKey⟩
    rcases hServer with ⟨_hServerBytes, hServerPoint, _hServerKey⟩
    simp [
      idealExecutionState,
      reconstructedCanonicalScalar,
      derivePublicIdentity,
      thresholdPublicPointOfShares,
      hClientPoint,
      hServerPoint,
      assumptions.scalarBaseMulAdd,
    ]
  · simp [
      idealExecutionState,
      derivePublicIdentity,
      thresholdPublicPointOfShares,
    ]

theorem idealExecutionState_address_agreement
    (context : PublicContext)
    (clientInput : ClientPrivateInput)
    (serverInput : ServerPrivateInput) :
    addressAgreement
      (idealExecutionState context clientInput serverInput) := by
  simp [
    idealExecutionState,
    addressAgreement,
    derivePublicIdentity,
    thresholdPublicPointOfShares,
  ]

theorem idealExecutionState_well_formed
    (assumptions : DerivationAssumptions)
    (context : PublicContext)
    (clientInput : ClientPrivateInput)
    (serverInput : ServerPrivateInput) :
    wellFormedExecutionState
      (idealExecutionState context clientInput serverInput) := by
  constructor
  · exact idealExecutionState_client_share_public_key_agreement
      assumptions context clientInput serverInput
  constructor
  · exact idealExecutionState_server_share_public_key_agreement
      assumptions context clientInput serverInput
  constructor
  · exact idealExecutionState_additive_public_key_agreement
      context clientInput serverInput
  constructor
  · exact idealExecutionState_export_public_key_verification
      assumptions context clientInput serverInput
  · exact idealExecutionState_address_agreement
      context clientInput serverInput

theorem idealFunctionality_well_formed
    (assumptions : DerivationAssumptions)
    (context : PublicContext)
    (clientInput : ClientPrivateInput)
    (serverInput : ServerPrivateInput) :
    idealFunctionalityWellFormed context clientInput serverInput := by
  exact idealExecutionState_well_formed
    assumptions context clientInput serverInput

theorem simulateNonExportClientView_matches_ideal
    (context : PublicContext)
    (clientInput : ClientPrivateInput)
    (serverInput : ServerPrivateInput) :
    simulateNonExportClientView
        {
          clientShare :=
            (F_ecdsa_hss_true_blind context clientInput serverInput).state.clientShare
          publicIdentity :=
            (F_ecdsa_hss_true_blind context clientInput serverInput).state.publicIdentity
        }
      =
      (F_ecdsa_hss_true_blind context clientInput serverInput).nonExportClient := by
  rfl

theorem simulateNonExportServerView_matches_ideal
    (context : PublicContext)
    (clientInput : ClientPrivateInput)
    (serverInput : ServerPrivateInput) :
    simulateNonExportServerView
        {
          serverShare :=
            (F_ecdsa_hss_true_blind context clientInput serverInput).state.serverShare
          publicIdentity :=
            (F_ecdsa_hss_true_blind context clientInput serverInput).state.publicIdentity
        }
      =
      (F_ecdsa_hss_true_blind context clientInput serverInput).nonExportServer := by
  rfl

theorem simulateExplicitExportClientView_matches_ideal
    (context : PublicContext)
    (clientInput : ClientPrivateInput)
    (serverInput : ServerPrivateInput) :
    simulateExplicitExportClientView
        {
          clientShare :=
            (F_ecdsa_hss_true_blind context clientInput serverInput).state.clientShare
          releasedRelayerShare :=
            (F_ecdsa_hss_true_blind context clientInput serverInput).state.serverShare
          publicIdentity :=
            (F_ecdsa_hss_true_blind context clientInput serverInput).state.publicIdentity
        }
      =
      (F_ecdsa_hss_true_blind context clientInput serverInput).explicitExportClient := by
  rfl

theorem simulateExplicitExportServerView_matches_ideal
    (context : PublicContext)
    (clientInput : ClientPrivateInput)
    (serverInput : ServerPrivateInput) :
    simulateExplicitExportServerView
        {
          releasedRelayerShare32 :=
            (F_ecdsa_hss_true_blind context clientInput serverInput).state.serverShare.xRelayer32
          publicIdentity :=
            (F_ecdsa_hss_true_blind context clientInput serverInput).state.publicIdentity
        }
      =
      (F_ecdsa_hss_true_blind context clientInput serverInput).explicitExportServer := by
  rfl

theorem idealFunctionality_export_reconstruction_agreement
    (context : PublicContext)
    (clientInput : ClientPrivateInput)
    (serverInput : ServerPrivateInput) :
    exportReconstructionAgreement
      (F_ecdsa_hss_true_blind context clientInput serverInput).state
      (F_ecdsa_hss_true_blind context clientInput serverInput).explicitExportClient := by
  exact explicitExportClientView_satisfies_reconstruction_relation
    (F_ecdsa_hss_true_blind context clientInput serverInput).state

theorem idealFunctionality_outputs_share_public_identity
    (context : PublicContext)
    (clientInput : ClientPrivateInput)
    (serverInput : ServerPrivateInput) :
    (F_ecdsa_hss_true_blind context clientInput serverInput).nonExportClient.publicIdentity =
      (F_ecdsa_hss_true_blind context clientInput serverInput).nonExportServer.publicIdentity ∧
    (F_ecdsa_hss_true_blind context clientInput serverInput).explicitExportClient.publicIdentity =
      (F_ecdsa_hss_true_blind context clientInput serverInput).nonExportClient.publicIdentity ∧
    (F_ecdsa_hss_true_blind context clientInput serverInput).explicitExportServer.publicIdentity =
      (F_ecdsa_hss_true_blind context clientInput serverInput).nonExportServer.publicIdentity := by
  constructor
  · rfl
  constructor
  · rfl
  · rfl

theorem idealFunctionality_export_public_key_verification
    (assumptions : DerivationAssumptions)
    (context : PublicContext)
    (clientInput : ClientPrivateInput)
    (serverInput : ServerPrivateInput) :
    exportPublicKeyVerification
      (F_ecdsa_hss_true_blind context clientInput serverInput).state := by
  exact idealExecutionState_export_public_key_verification
    assumptions context clientInput serverInput

theorem F_ecdsa_hss_true_blind_non_export_server_excludes_client_root
    (context : PublicContext)
    (clientInput : ClientPrivateInput)
    (serverInput : ServerPrivateInput) :
    serverViewClientRoot?
        (F_ecdsa_hss_true_blind context clientInput serverInput).nonExportServer =
      none := by
  rfl

theorem F_ecdsa_hss_true_blind_non_export_server_excludes_canonical_x
    (context : PublicContext)
    (clientInput : ClientPrivateInput)
    (serverInput : ServerPrivateInput) :
    serverViewCanonicalX?
        (F_ecdsa_hss_true_blind context clientInput serverInput).nonExportServer =
      none := by
  rfl

theorem F_ecdsa_hss_true_blind_non_export_client_excludes_relayer_share
    (context : PublicContext)
    (clientInput : ClientPrivateInput)
    (serverInput : ServerPrivateInput) :
    clientViewRelayerShare?
        (F_ecdsa_hss_true_blind context clientInput serverInput).nonExportClient =
      none := by
  rfl

theorem F_ecdsa_hss_true_blind_non_export_client_operation_excludes_relayer_share
    (context : PublicContext)
    (clientInput : ClientPrivateInput)
    (serverInput : ServerPrivateInput) :
    clientOperationViewRelayerShare?
        (idealNonExportClientOperationView
          (F_ecdsa_hss_true_blind context clientInput serverInput)) =
      none := by
  rfl

theorem F_ecdsa_hss_true_blind_non_export_client_operation_excludes_canonical_x
    (context : PublicContext)
    (clientInput : ClientPrivateInput)
    (serverInput : ServerPrivateInput) :
    clientOperationViewCanonicalX?
        (idealNonExportClientOperationView
          (F_ecdsa_hss_true_blind context clientInput serverInput)) =
      none := by
  rfl

theorem F_ecdsa_hss_true_blind_explicit_export_client_operation_releases_relayer_share
    (context : PublicContext)
    (clientInput : ClientPrivateInput)
    (serverInput : ServerPrivateInput) :
    clientOperationViewRelayerShare?
        (idealExplicitExportClientOperationView
          (F_ecdsa_hss_true_blind context clientInput serverInput)) =
      some
        (F_ecdsa_hss_true_blind
          context clientInput serverInput).explicitExportClient.exportRelayerShare32 := by
  rfl

theorem F_ecdsa_hss_true_blind_explicit_export_client_operation_releases_canonical_x
    (context : PublicContext)
    (clientInput : ClientPrivateInput)
    (serverInput : ServerPrivateInput) :
    clientOperationViewCanonicalX?
        (idealExplicitExportClientOperationView
          (F_ecdsa_hss_true_blind context clientInput serverInput)) =
      some
        (F_ecdsa_hss_true_blind
          context clientInput serverInput).explicitExportClient.reconstructedCanonicalX32 := by
  rfl

theorem F_ecdsa_hss_true_blind_explicit_export_server_operation_excludes_canonical_x
    (context : PublicContext)
    (clientInput : ClientPrivateInput)
    (serverInput : ServerPrivateInput) :
    serverOperationViewCanonicalX?
        (idealExplicitExportServerOperationView
          (F_ecdsa_hss_true_blind context clientInput serverInput)) =
      none := by
  rfl

theorem wellFormedExecutionState_implies_additive_public_key_agreement
    (state : ExecutionState)
    (hWellFormed : wellFormedExecutionState state) :
    additivePublicKeyAgreement state := by
  rcases hWellFormed with
    ⟨_hClient, _hServer, hAdditive, _hExport, _hAddress⟩
  exact hAdditive

theorem wellFormedExecutionState_implies_export_public_key_verification
    (state : ExecutionState)
    (hWellFormed : wellFormedExecutionState state) :
    exportPublicKeyVerification state := by
  rcases hWellFormed with
    ⟨_hClient, _hServer, _hAdditive, hExport, _hAddress⟩
  exact hExport

theorem wellFormedExecutionState_implies_address_agreement
    (state : ExecutionState)
    (hWellFormed : wellFormedExecutionState state) :
    addressAgreement state := by
  rcases hWellFormed with
    ⟨_hClient, _hServer, _hAdditive, _hExport, hAddress⟩
  exact hAddress

end

end EcdsaHssPrivacy.TrueBlind
