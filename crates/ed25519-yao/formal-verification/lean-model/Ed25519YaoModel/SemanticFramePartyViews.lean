import Ed25519YaoModel.EvaluationInputs

/-!
Construction-independent structural model for semantic frame classes, delivery
states, cumulative role-local value-learning labels, and closed corruption-
interface shapes. Runtime bytes, sequencing, timing, authentication, durable
state, transactions, simulators, indistinguishability, selected-profile
satisfaction, and protocol-security theorems remain outside this model.
-/

namespace Ed25519YaoModel

inductive SemanticFrameClass where
  | ClientToRouterEvaluationRequest
  | RouterLocalActivationControl
  | RouterToDeriverAInputDelivery
  | RouterToDeriverBInputDelivery
  | DeriverAToDeriverBPeerProtocol
  | DeriverBToDeriverAPeerProtocol
  | DeriverAToRouterOutputPackages
  | DeriverBToRouterOutputPackages
  | RouterToClientRecipientDelivery
  | RouterToSigningWorkerRecipientDelivery
  | SigningWorkerToRouterActivationReceipt
  deriving DecidableEq, Repr

inductive SemanticDeliveryState where
  | CeremonyAdmitted
  | EvaluationInputsAccepted
  | PeerProtocolInProgress
  | OutputCommitted
  | EvaluatorAborted
  | ActivationMetadataConsumed
  | RecipientDeliveryUncertain
  | ActivationRecipientsReleased
  | ExportReleased
  | SigningWorkerActivated
  | ExactRedelivery
  deriving DecidableEq, Repr

inductive SemanticTraceRole where
  | DeriverA
  | DeriverB
  | Client
  | SigningWorker
  | Router
  | Observer
  | Diagnostics
  deriving DecidableEq, Repr

def allSemanticFrameClasses : List SemanticFrameClass :=
  [.ClientToRouterEvaluationRequest,
    .RouterLocalActivationControl,
    .RouterToDeriverAInputDelivery,
    .RouterToDeriverBInputDelivery,
    .DeriverAToDeriverBPeerProtocol,
    .DeriverBToDeriverAPeerProtocol,
    .DeriverAToRouterOutputPackages,
    .DeriverBToRouterOutputPackages,
    .RouterToClientRecipientDelivery,
    .RouterToSigningWorkerRecipientDelivery,
    .SigningWorkerToRouterActivationReceipt]

def allSemanticDeliveryStates : List SemanticDeliveryState :=
  [.CeremonyAdmitted,
    .EvaluationInputsAccepted,
    .PeerProtocolInProgress,
    .OutputCommitted,
    .EvaluatorAborted,
    .ActivationMetadataConsumed,
    .RecipientDeliveryUncertain,
    .ActivationRecipientsReleased,
    .ExportReleased,
    .SigningWorkerActivated,
    .ExactRedelivery]

def allSemanticTraceRoles : List SemanticTraceRole :=
  [.DeriverA, .DeriverB, .Client, .SigningWorker, .Router, .Observer, .Diagnostics]

structure SemanticTraceShape where
  states : List SemanticDeliveryState
  frames : List SemanticFrameClass
  deriving DecidableEq, Repr

def activationFamilySuccessTrace : SemanticTraceShape :=
  {
    states :=
      [.CeremonyAdmitted,
        .EvaluationInputsAccepted,
        .PeerProtocolInProgress,
        .OutputCommitted,
        .ActivationMetadataConsumed,
        .RecipientDeliveryUncertain,
        .ActivationRecipientsReleased,
        .ExactRedelivery,
        .SigningWorkerActivated]
    frames :=
      [.ClientToRouterEvaluationRequest,
        .RouterToDeriverAInputDelivery,
        .RouterToDeriverBInputDelivery,
        .DeriverAToDeriverBPeerProtocol,
        .DeriverBToDeriverAPeerProtocol,
        .DeriverAToRouterOutputPackages,
        .DeriverBToRouterOutputPackages,
        .RouterLocalActivationControl,
        .RouterToClientRecipientDelivery,
        .RouterToSigningWorkerRecipientDelivery,
        .RouterToClientRecipientDelivery,
        .RouterToSigningWorkerRecipientDelivery,
        .SigningWorkerToRouterActivationReceipt]
  }

def activationControlSuccessTrace : SemanticTraceShape :=
  {
    states :=
      [.CeremonyAdmitted,
        .ActivationMetadataConsumed,
        .RecipientDeliveryUncertain,
        .ActivationRecipientsReleased,
        .ExactRedelivery,
        .SigningWorkerActivated]
    frames :=
      [.ClientToRouterEvaluationRequest,
        .RouterLocalActivationControl,
        .RouterToClientRecipientDelivery,
        .RouterToSigningWorkerRecipientDelivery,
        .RouterToClientRecipientDelivery,
        .RouterToSigningWorkerRecipientDelivery,
        .SigningWorkerToRouterActivationReceipt]
  }

def exportSuccessTrace : SemanticTraceShape :=
  {
    states :=
      [.CeremonyAdmitted,
        .EvaluationInputsAccepted,
        .PeerProtocolInProgress,
        .OutputCommitted,
        .RecipientDeliveryUncertain,
        .ExportReleased,
        .ExactRedelivery]
    frames :=
      [.ClientToRouterEvaluationRequest,
        .RouterToDeriverAInputDelivery,
        .RouterToDeriverBInputDelivery,
        .DeriverAToDeriverBPeerProtocol,
        .DeriverBToDeriverAPeerProtocol,
        .DeriverAToRouterOutputPackages,
        .DeriverBToRouterOutputPackages,
        .RouterToClientRecipientDelivery,
        .RouterToClientRecipientDelivery]
  }

def evaluatorAbortTrace : SemanticTraceShape :=
  {
    states :=
      [.CeremonyAdmitted,
        .EvaluationInputsAccepted,
        .PeerProtocolInProgress,
        .EvaluatorAborted]
    frames :=
      [.ClientToRouterEvaluationRequest,
        .RouterToDeriverAInputDelivery,
        .RouterToDeriverBInputDelivery,
        .DeriverAToDeriverBPeerProtocol,
        .DeriverBToDeriverAPeerProtocol]
  }

def successTraceForRequest : RequestKind → SemanticTraceShape
  | .registration => activationFamilySuccessTrace
  | .activation => activationControlSuccessTrace
  | .recovery => activationFamilySuccessTrace
  | .refresh => activationFamilySuccessTrace
  | .export => exportSuccessTrace

def abortTraceForRequest : RequestKind → Option SemanticTraceShape
  | .registration => some evaluatorAbortTrace
  | .activation => none
  | .recovery => some evaluatorAbortTrace
  | .refresh => some evaluatorAbortTrace
  | .export => some evaluatorAbortTrace

def isEvaluatorFrame : SemanticFrameClass → Bool
  | .RouterToDeriverAInputDelivery => true
  | .RouterToDeriverBInputDelivery => true
  | .DeriverAToDeriverBPeerProtocol => true
  | .DeriverBToDeriverAPeerProtocol => true
  | .DeriverAToRouterOutputPackages => true
  | .DeriverBToRouterOutputPackages => true
  | _ => false

def isWorkerFrame : SemanticFrameClass → Bool
  | .RouterToSigningWorkerRecipientDelivery => true
  | .SigningWorkerToRouterActivationReceipt => true
  | _ => false

def isWorkerDeliveryState : SemanticDeliveryState → Bool
  | .ActivationMetadataConsumed => true
  | .ActivationRecipientsReleased => true
  | .SigningWorkerActivated => true
  | _ => false

inductive SemanticTraceStep :
    RequestKind → SemanticDeliveryState → SemanticDeliveryState → Prop where
  | evaluationInputsAccepted
      {request : RequestKind}
      (evaluated : request ≠ .activation) :
      SemanticTraceStep request .CeremonyAdmitted .EvaluationInputsAccepted
  | peerProtocolStarted
      {request : RequestKind}
      (evaluated : request ≠ .activation) :
      SemanticTraceStep request .EvaluationInputsAccepted .PeerProtocolInProgress
  | outputCommitted
      {request : RequestKind}
      (evaluated : request ≠ .activation) :
      SemanticTraceStep request .PeerProtocolInProgress .OutputCommitted
  | evaluatorAborted
      {request : RequestKind}
      (evaluated : request ≠ .activation) :
      SemanticTraceStep request .PeerProtocolInProgress .EvaluatorAborted
  | activationMetadataAfterOutput
      {request : RequestKind}
      (activationFamily : request ≠ .activation ∧ request ≠ .export) :
      SemanticTraceStep request .OutputCommitted .ActivationMetadataConsumed
  | activationMetadataControl :
      SemanticTraceStep .activation .CeremonyAdmitted .ActivationMetadataConsumed
  | activationDeliveryUncertain
      {request : RequestKind}
      (activationFamily : request ≠ .export) :
      SemanticTraceStep request .ActivationMetadataConsumed .RecipientDeliveryUncertain
  | activationRecipientsReleased
      {request : RequestKind}
      (activationFamily : request ≠ .export) :
      SemanticTraceStep request .RecipientDeliveryUncertain .ActivationRecipientsReleased
  | activationRedelivery
      {request : RequestKind}
      (activationFamily : request ≠ .export) :
      SemanticTraceStep request .ActivationRecipientsReleased .ExactRedelivery
  | signingWorkerActivated
      {request : RequestKind}
      (activationFamily : request ≠ .export) :
      SemanticTraceStep request .ExactRedelivery .SigningWorkerActivated
  | exportDeliveryUncertain :
      SemanticTraceStep .export .OutputCommitted .RecipientDeliveryUncertain
  | exportReleased :
      SemanticTraceStep .export .RecipientDeliveryUncertain .ExportReleased
  | exportRedelivery :
      SemanticTraceStep .export .ExportReleased .ExactRedelivery

def hasSuccessor
    (request : RequestKind) (state : SemanticDeliveryState) : Prop :=
  ∃ next, SemanticTraceStep request state next

inductive SemanticRecipient where
  | Client
  | SigningWorker
  deriving DecidableEq, Repr

structure RecipientDeliveryIdentity where
  request : RequestKind
  recipient : SemanticRecipient
  frameClass : SemanticFrameClass
  outputIdentity : Nat
  deriving DecidableEq, Repr

def exactRedeliveryIdentity
    (delivery : RecipientDeliveryIdentity) : RecipientDeliveryIdentity :=
  delivery

inductive SemanticLearnedValue where
  | PublicMetadata
  | ClientRoleScopedInput
  | DeriverAPrivateEvaluationInput
  | DeriverBPrivateEvaluationInput
  | DeriverAProtocolRandomness
  | DeriverBProtocolRandomness
  | DeriverAPeerProtocolMessage
  | DeriverBPeerProtocolMessage
  | DeriverAOutputPackage
  | DeriverBOutputPackage
  | RouterControl
  | RouterInputEnvelopeIdentity
  | RouterOutputPackageIdentity
  | RouterDeliveryReceiptControl
  | ClientScalarOutput
  | ClientSeedOutput
  | SigningWorkerReleaseAuthority
  | SigningWorkerScalarOutput
  | JoinedPrivateValue
  | FunctionalityOwnedCoin
  deriving DecidableEq, Repr

def isEvaluationRequest : RequestKind → Bool
  | .activation => false
  | _ => true

def evaluationInputsReached : SemanticDeliveryState → Bool
  | .CeremonyAdmitted => false
  | .ActivationMetadataConsumed => true
  | .RecipientDeliveryUncertain => true
  | .ActivationRecipientsReleased => true
  | .ExportReleased => true
  | .ExactRedelivery => true
  | .SigningWorkerActivated => true
  | _ => true

def peerProtocolReached : SemanticDeliveryState → Bool
  | .CeremonyAdmitted => false
  | .EvaluationInputsAccepted => false
  | .ActivationMetadataConsumed => true
  | .RecipientDeliveryUncertain => true
  | .ActivationRecipientsReleased => true
  | .ExportReleased => true
  | .ExactRedelivery => true
  | .SigningWorkerActivated => true
  | _ => true

def outputCommittedReached : SemanticDeliveryState → Bool
  | .OutputCommitted => true
  | .ActivationMetadataConsumed => true
  | .RecipientDeliveryUncertain => true
  | .ActivationRecipientsReleased => true
  | .ExportReleased => true
  | .ExactRedelivery => true
  | .SigningWorkerActivated => true
  | _ => false

def activationReleaseReached : SemanticDeliveryState → Bool
  | .ActivationRecipientsReleased => true
  | .ExactRedelivery => true
  | .SigningWorkerActivated => true
  | _ => false

def exportReleaseReached : SemanticDeliveryState → Bool
  | .ExportReleased => true
  | .ExactRedelivery => true
  | _ => false

def deliveryControlReached : SemanticDeliveryState → Bool
  | .ActivationMetadataConsumed => true
  | .RecipientDeliveryUncertain => true
  | .ActivationRecipientsReleased => true
  | .ExportReleased => true
  | .ExactRedelivery => true
  | .SigningWorkerActivated => true
  | _ => false

def mayLearnSemanticValue :
    SemanticTraceRole → RequestKind → SemanticDeliveryState →
      SemanticLearnedValue → Bool
  | _, _, _, .PublicMetadata => true
  | .Client, _, _, .ClientRoleScopedInput => true
  | .DeriverA, request, state, .DeriverAPrivateEvaluationInput =>
      isEvaluationRequest request && evaluationInputsReached state
  | .DeriverB, request, state, .DeriverBPrivateEvaluationInput =>
      isEvaluationRequest request && evaluationInputsReached state
  | .DeriverA, request, state, .DeriverAProtocolRandomness =>
      isEvaluationRequest request && peerProtocolReached state
  | .DeriverB, request, state, .DeriverBProtocolRandomness =>
      isEvaluationRequest request && peerProtocolReached state
  | .DeriverA, request, state, .DeriverAPeerProtocolMessage =>
      isEvaluationRequest request && peerProtocolReached state
  | .DeriverB, request, state, .DeriverBPeerProtocolMessage =>
      isEvaluationRequest request && peerProtocolReached state
  | .DeriverA, request, state, .DeriverAOutputPackage =>
      isEvaluationRequest request && outputCommittedReached state
  | .DeriverB, request, state, .DeriverBOutputPackage =>
      isEvaluationRequest request && outputCommittedReached state
  | .Router, _, _, .RouterControl => true
  | .Router, request, state, .RouterInputEnvelopeIdentity =>
      isEvaluationRequest request && evaluationInputsReached state
  | .Router, request, state, .RouterOutputPackageIdentity =>
      isEvaluationRequest request && outputCommittedReached state
  | .Router, _, state, .RouterDeliveryReceiptControl => deliveryControlReached state
  | .Client, .export, state, .ClientSeedOutput => exportReleaseReached state
  | .Client, request, state, .ClientScalarOutput =>
      (request != .export) && activationReleaseReached state
  | .SigningWorker, request, state, .SigningWorkerReleaseAuthority =>
      (request != .export) && activationReleaseReached state
  | .SigningWorker, request, .SigningWorkerActivated, .SigningWorkerScalarOutput =>
      request != .export
  | _, _, _, _ => false

def frameClassOwners : SemanticFrameClass → List SemanticTraceRole
  | .ClientToRouterEvaluationRequest => [.Client, .Router]
  | .RouterLocalActivationControl => [.Router]
  | .RouterToDeriverAInputDelivery => [.Router, .DeriverA]
  | .RouterToDeriverBInputDelivery => [.Router, .DeriverB]
  | .DeriverAToDeriverBPeerProtocol => [.DeriverA, .DeriverB]
  | .DeriverBToDeriverAPeerProtocol => [.DeriverB, .DeriverA]
  | .DeriverAToRouterOutputPackages => [.DeriverA, .Router]
  | .DeriverBToRouterOutputPackages => [.DeriverB, .Router]
  | .RouterToClientRecipientDelivery => [.Router, .Client]
  | .RouterToSigningWorkerRecipientDelivery => [.Router, .SigningWorker]
  | .SigningWorkerToRouterActivationReceipt => [.SigningWorker, .Router]

def roleObservesFrameClass : SemanticTraceRole → SemanticFrameClass → Bool
  | .Diagnostics, _ => true
  | .Observer, _ => false
  | role, frame => role ∈ frameClassOwners frame

def isPrivateSemanticValue : SemanticLearnedValue → Bool
  | .DeriverAPrivateEvaluationInput => true
  | .DeriverBPrivateEvaluationInput => true
  | .DeriverAProtocolRandomness => true
  | .DeriverBProtocolRandomness => true
  | .ClientScalarOutput => true
  | .ClientSeedOutput => true
  | .SigningWorkerReleaseAuthority => true
  | .SigningWorkerScalarOutput => true
  | .JoinedPrivateValue => true
  | .FunctionalityOwnedCoin => true
  | _ => false

structure SemanticRoleValueView where
  role : SemanticTraceRole
  request : RequestKind
  state : SemanticDeliveryState
  deriving DecidableEq, Repr

def semanticRoleViews
    (request : RequestKind) (state : SemanticDeliveryState) :
    List SemanticRoleValueView :=
  allSemanticTraceRoles.map fun role => { role, request, state }

inductive CorruptionMarker where
  | HonestExecution
  | RouterOnly
  | PassiveDeriverA
  | PassiveDeriverB
  | RouterAndPassiveDeriverA
  | RouterAndPassiveDeriverB
  | ActiveDeriverA
  | ActiveDeriverB
  | RouterAndActiveDeriverA
  | RouterAndActiveDeriverB
  deriving DecidableEq, Repr

def allCorruptionMarkers : List CorruptionMarker :=
  [.HonestExecution,
    .RouterOnly,
    .PassiveDeriverA,
    .PassiveDeriverB,
    .RouterAndPassiveDeriverA,
    .RouterAndPassiveDeriverB,
    .ActiveDeriverA,
    .ActiveDeriverB,
    .RouterAndActiveDeriverA,
    .RouterAndActiveDeriverB]

def markerCorrupts : CorruptionMarker → SemanticTraceRole → Bool
  | .HonestExecution, _ => false
  | .RouterOnly, .Router => true
  | .PassiveDeriverA, .DeriverA => true
  | .PassiveDeriverB, .DeriverB => true
  | .RouterAndPassiveDeriverA, .Router => true
  | .RouterAndPassiveDeriverA, .DeriverA => true
  | .RouterAndPassiveDeriverB, .Router => true
  | .RouterAndPassiveDeriverB, .DeriverB => true
  | .ActiveDeriverA, .DeriverA => true
  | .ActiveDeriverB, .DeriverB => true
  | .RouterAndActiveDeriverA, .Router => true
  | .RouterAndActiveDeriverA, .DeriverA => true
  | .RouterAndActiveDeriverB, .Router => true
  | .RouterAndActiveDeriverB, .DeriverB => true
  | _, _ => false

inductive CorruptionInterfaceKind where
  | corruptedViewInput
  | selectedProfileRealExecution
  | selectedProfileIdealSimulator
  | selectedProfileSecurityExperiment
  deriving DecidableEq, Repr

structure CorruptionInterfaceShape where
  kind : CorruptionInterfaceKind
  publicInputCount : Nat
  corruptedViewInputCount : Nat
  traceOutputCount : Nat
  experimentOutputCount : Nat
  deriving DecidableEq, Repr

def CorruptedViewInput (shape : CorruptionInterfaceShape) : Prop :=
  shape = ⟨.corruptedViewInput, 1, 1, 0, 0⟩

def SelectedProfileRealExecution (shape : CorruptionInterfaceShape) : Prop :=
  shape = ⟨.selectedProfileRealExecution, 1, 1, 1, 0⟩

def SelectedProfileIdealSimulator (shape : CorruptionInterfaceShape) : Prop :=
  shape = ⟨.selectedProfileIdealSimulator, 1, 1, 1, 0⟩

def SelectedProfileSecurityExperiment (shape : CorruptionInterfaceShape) : Prop :=
  shape = ⟨.selectedProfileSecurityExperiment, 1, 0, 0, 1⟩

theorem semanticFrameClassesAreExactlyEleven :
    allSemanticFrameClasses =
      [.ClientToRouterEvaluationRequest,
        .RouterLocalActivationControl,
        .RouterToDeriverAInputDelivery,
        .RouterToDeriverBInputDelivery,
        .DeriverAToDeriverBPeerProtocol,
        .DeriverBToDeriverAPeerProtocol,
        .DeriverAToRouterOutputPackages,
        .DeriverBToRouterOutputPackages,
        .RouterToClientRecipientDelivery,
        .RouterToSigningWorkerRecipientDelivery,
        .SigningWorkerToRouterActivationReceipt] ∧
      allSemanticFrameClasses.length = 11 := by
  decide

theorem semanticDeliveryStatesAreExactlyEleven :
    allSemanticDeliveryStates =
      [.CeremonyAdmitted,
        .EvaluationInputsAccepted,
        .PeerProtocolInProgress,
        .OutputCommitted,
        .EvaluatorAborted,
        .ActivationMetadataConsumed,
        .RecipientDeliveryUncertain,
        .ActivationRecipientsReleased,
        .ExportReleased,
        .SigningWorkerActivated,
        .ExactRedelivery] ∧
      allSemanticDeliveryStates.length = 11 := by
  decide

theorem semanticTraceRolesAreExactlySeven :
    allSemanticTraceRoles =
      [.DeriverA, .DeriverB, .Client, .SigningWorker, .Router, .Observer, .Diagnostics] ∧
      allSemanticTraceRoles.length = 7 := by
  decide

theorem activationFamilySuccessTraceHasExactShape :
    successTraceForRequest .registration = activationFamilySuccessTrace ∧
      successTraceForRequest .recovery = activationFamilySuccessTrace ∧
      successTraceForRequest .refresh = activationFamilySuccessTrace := by
  exact ⟨rfl, rfl, rfl⟩

theorem activationControlSuccessTraceHasExactShape :
    successTraceForRequest .activation = activationControlSuccessTrace ∧
      activationControlSuccessTrace.frames.head? =
        some .ClientToRouterEvaluationRequest := by
  exact ⟨rfl, rfl⟩

theorem exportSuccessAndRedeliveryTraceHasExactShape :
    successTraceForRequest .export = exportSuccessTrace ∧
      exportSuccessTrace.states.getLast? = some .ExactRedelivery ∧
      exportSuccessTrace.frames.getLast? = some .RouterToClientRecipientDelivery := by
  decide

theorem evaluatorAbortTraceHasExactShape :
    abortTraceForRequest .registration = some evaluatorAbortTrace ∧
      abortTraceForRequest .activation = none ∧
      abortTraceForRequest .recovery = some evaluatorAbortTrace ∧
      abortTraceForRequest .refresh = some evaluatorAbortTrace ∧
      abortTraceForRequest .export = some evaluatorAbortTrace := by
  exact ⟨rfl, rfl, rfl, rfl, rfl⟩

theorem activationEmitsZeroEvaluatorFrames
    (frame : SemanticFrameClass)
    (present : frame ∈ activationControlSuccessTrace.frames) :
    isEvaluatorFrame frame = false := by
  cases frame <;> simp_all [activationControlSuccessTrace, isEvaluatorFrame]

theorem exportExcludesWorkerDeliveryStatesAndFrames
    (state : SemanticDeliveryState) (frame : SemanticFrameClass)
    (statePresent : state ∈ exportSuccessTrace.states)
    (framePresent : frame ∈ exportSuccessTrace.frames) :
    isWorkerDeliveryState state = false ∧ isWorkerFrame frame = false := by
  cases state <;> cases frame <;>
    simp_all [exportSuccessTrace, isWorkerDeliveryState, isWorkerFrame]

theorem evaluatorAbortIsTerminal (request : RequestKind) :
    ¬ hasSuccessor request .EvaluatorAborted := by
  intro successor
  rcases successor with ⟨next, step⟩
  cases step

theorem exactRedeliveryPreservesRecipientDeliveryIdentity
    (delivery : RecipientDeliveryIdentity) :
    exactRedeliveryIdentity delivery = delivery := by
  rfl

theorem semanticStateProjectionHasExactlySevenOrderedViews
    (request : RequestKind) (state : SemanticDeliveryState) :
    (semanticRoleViews request state).map SemanticRoleValueView.role =
        allSemanticTraceRoles ∧
      (semanticRoleViews request state).length = 7 := by
  simp [semanticRoleViews, allSemanticTraceRoles]

theorem allRolesLearnPublicMetadata
    (role : SemanticTraceRole) (request : RequestKind) (state : SemanticDeliveryState) :
    mayLearnSemanticValue role request state .PublicMetadata = true := by
  cases role <;> rfl

theorem deriversLearnOwnAcceptedInputsAndProtocolRandomness (request : RequestKind)
    (evaluated : request ≠ .activation) :
    mayLearnSemanticValue .DeriverA request .EvaluationInputsAccepted
        .DeriverAPrivateEvaluationInput = true ∧
      mayLearnSemanticValue .DeriverB request .EvaluationInputsAccepted
        .DeriverBPrivateEvaluationInput = true ∧
      mayLearnSemanticValue .DeriverA request .PeerProtocolInProgress
        .DeriverAProtocolRandomness = true ∧
      mayLearnSemanticValue .DeriverB request .PeerProtocolInProgress
        .DeriverBProtocolRandomness = true := by
  cases request <;> simp_all [mayLearnSemanticValue, isEvaluationRequest,
    evaluationInputsReached, peerProtocolReached]

theorem deriversLearnOwnCommittedOutputPackages (request : RequestKind)
    (evaluated : request ≠ .activation) :
    mayLearnSemanticValue .DeriverA request .OutputCommitted
        .DeriverAOutputPackage = true ∧
      mayLearnSemanticValue .DeriverB request .OutputCommitted
        .DeriverBOutputPackage = true := by
  cases request <;> simp_all [mayLearnSemanticValue, isEvaluationRequest,
    outputCommittedReached]

theorem deriversExcludePeerJoinedAndFunctionalityValues
    (request : RequestKind) (state : SemanticDeliveryState) :
    mayLearnSemanticValue .DeriverA request state .DeriverBPrivateEvaluationInput = false ∧
      mayLearnSemanticValue .DeriverB request state .DeriverAPrivateEvaluationInput = false ∧
      mayLearnSemanticValue .DeriverA request state .JoinedPrivateValue = false ∧
      mayLearnSemanticValue .DeriverB request state .JoinedPrivateValue = false ∧
      mayLearnSemanticValue .DeriverA request state .FunctionalityOwnedCoin = false ∧
      mayLearnSemanticValue .DeriverB request state .FunctionalityOwnedCoin = false := by
  cases request <;> cases state <;> decide

theorem clientLearnsRoleScopedInputAndPrivateOutputsOnlyAfterRelease
    (request : RequestKind) (state : SemanticDeliveryState)
    (value : SemanticLearnedValue)
    (privateValue : isPrivateSemanticValue value = true)
    (learned : mayLearnSemanticValue .Client request state value = true) :
    mayLearnSemanticValue .Client request .CeremonyAdmitted .ClientRoleScopedInput = true ∧
      ((request = .export ∧ value = .ClientSeedOutput ∧
          exportReleaseReached state = true) ∨
        (request ≠ .export ∧ value = .ClientScalarOutput ∧
          activationReleaseReached state = true)) := by
  cases request <;> cases state <;> cases value <;>
    simp_all [mayLearnSemanticValue, isPrivateSemanticValue, activationReleaseReached,
      exportReleaseReached]

theorem signingWorkerLearnsPrivateOutputOnlyAfterActivation
    (request : RequestKind) (state : SemanticDeliveryState)
    (learned : mayLearnSemanticValue .SigningWorker request state
      .SigningWorkerScalarOutput = true) :
    request ≠ .export ∧ state = .SigningWorkerActivated := by
  cases request <;> cases state <;>
    simp_all [mayLearnSemanticValue]

theorem infrastructureLearnsNoPrivateValues
    (role : SemanticTraceRole)
    (infrastructure : role = .Router ∨ role = .Observer ∨ role = .Diagnostics)
    (request : RequestKind) (state : SemanticDeliveryState)
    (value : SemanticLearnedValue) (privateValue : isPrivateSemanticValue value = true) :
    mayLearnSemanticValue role request state value = false := by
  rcases infrastructure with rfl | rfl | rfl <;>
    cases request <;> cases state <;> cases value <;>
      simp_all [mayLearnSemanticValue, isPrivateSemanticValue]

theorem routerKnowledgeFollowsControlInputOutputDeliveryStages
    (request : RequestKind) (state : SemanticDeliveryState)
    (role : SemanticTraceRole) (notRouter : role ≠ .Router) :
    mayLearnSemanticValue .Router request .CeremonyAdmitted .RouterControl = true ∧
      mayLearnSemanticValue .Router request .CeremonyAdmitted
        .RouterInputEnvelopeIdentity = false ∧
      mayLearnSemanticValue .Router request .EvaluationInputsAccepted
        .RouterInputEnvelopeIdentity = isEvaluationRequest request ∧
      mayLearnSemanticValue .Router request .PeerProtocolInProgress
        .RouterOutputPackageIdentity = false ∧
      mayLearnSemanticValue .Router request .OutputCommitted
        .RouterOutputPackageIdentity = isEvaluationRequest request ∧
      mayLearnSemanticValue .Router request .OutputCommitted
        .RouterDeliveryReceiptControl = false ∧
      mayLearnSemanticValue .Router request .RecipientDeliveryUncertain
        .RouterDeliveryReceiptControl = true ∧
      mayLearnSemanticValue role request state .RouterControl = false ∧
      mayLearnSemanticValue role request state .RouterInputEnvelopeIdentity = false ∧
      mayLearnSemanticValue role request state .RouterOutputPackageIdentity = false ∧
      mayLearnSemanticValue role request state .RouterDeliveryReceiptControl = false := by
  cases role <;> simp_all [mayLearnSemanticValue, evaluationInputsReached,
    outputCommittedReached, deliveryControlReached]

theorem diagnosticsObservesEveryFrameClassAndObserverObservesNone
    (role : SemanticTraceRole) (frame : SemanticFrameClass) :
    roleObservesFrameClass .Diagnostics frame = true ∧
      roleObservesFrameClass .Observer frame = false ∧
      roleObservesFrameClass role frame =
        (role == .Diagnostics || role ∈ frameClassOwners frame) := by
  cases role <;> cases frame <;> decide

set_option maxHeartbeats 1000000 in
theorem semanticValueLearningIsMonotoneAcrossEveryTraceStep
    (request : RequestKind) (before after : SemanticDeliveryState)
    (step : SemanticTraceStep request before after)
    (role : SemanticTraceRole) (value : SemanticLearnedValue)
    (learned : mayLearnSemanticValue role request before value = true) :
    mayLearnSemanticValue role request after value = true := by
  cases request <;> cases step <;> cases role <;> cases value <;>
    simp_all [mayLearnSemanticValue, isEvaluationRequest, evaluationInputsReached,
      peerProtocolReached, outputCommittedReached, activationReleaseReached,
      exportReleaseReached, deliveryControlReached]

theorem closedCorruptionMarkersAreExactlyTenAndExcludeOutOfScopeCoalitions :
    allCorruptionMarkers =
      [.HonestExecution,
        .RouterOnly,
        .PassiveDeriverA,
        .PassiveDeriverB,
        .RouterAndPassiveDeriverA,
        .RouterAndPassiveDeriverB,
        .ActiveDeriverA,
        .ActiveDeriverB,
        .RouterAndActiveDeriverA,
        .RouterAndActiveDeriverB] ∧
      allCorruptionMarkers.length = 10 ∧
      ∀ marker,
        ¬ (markerCorrupts marker .DeriverA = true ∧
          markerCorrupts marker .DeriverB = true) ∧
        markerCorrupts marker .Client = false ∧
        markerCorrupts marker .SigningWorker = false := by
  exact ⟨rfl, rfl, by intro marker; cases marker <;> decide⟩

theorem corruptionInterfacesHaveExactlyFourFixedShapes :
    CorruptedViewInput ⟨.corruptedViewInput, 1, 1, 0, 0⟩ ∧
      SelectedProfileRealExecution ⟨.selectedProfileRealExecution, 1, 1, 1, 0⟩ ∧
      SelectedProfileIdealSimulator ⟨.selectedProfileIdealSimulator, 1, 1, 1, 0⟩ ∧
      SelectedProfileSecurityExperiment
        ⟨.selectedProfileSecurityExperiment, 1, 0, 0, 1⟩ := by
  exact ⟨rfl, rfl, rfl, rfl⟩

end Ed25519YaoModel
