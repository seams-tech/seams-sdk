import Ed25519YaoModel.EvaluationInputs
import Ed25519YaoModel.RuntimePublicShape

namespace Ed25519YaoModel

inductive PassiveHybridStage where
  | real
  | idealBaseOt
  | idealOtExtension
  | simulatedInputLabels
  | simulatedGarbling
  | ideal
  deriving DecidableEq, Repr

inductive AuthorizedOutputClass where
  | activationClientPackageShare
  | activationSigningWorkerPackageShare
  | exportPackageShare
  deriving DecidableEq, Repr

inductive PassiveComponentClass where
  | baseOt
  | otExtension
  | inputLabels
  | garbledTables
  | outputMessages
  deriving DecidableEq, Repr

abbrev PassiveBytes := List UInt8

structure PrivateInputValue where
  bytes : PassiveBytes
  deriving DecidableEq, Repr

structure PassiveRandomTape where
  bytes : PassiveBytes
  deriving DecidableEq, Repr

structure AuthorizedPackageShare where
  bytes : PassiveBytes
  deriving DecidableEq, Repr

structure AuthorizedOutputValues where
  activationClientPackageShare : AuthorizedPackageShare
  activationSigningWorkerPackageShare : AuthorizedPackageShare
  exportPackageShare : AuthorizedPackageShare
  deriving DecidableEq, Repr

structure AuthorizedOutput where
  outputClass : AuthorizedOutputClass
  packageShare : AuthorizedPackageShare
  deriving DecidableEq, Repr

abbrev PrivateInputAssignment := EvaluationInputClass → PrivateInputValue

structure PassiveExperimentInput where
  corruptedPrivateValues : PrivateInputAssignment
  honestPrivateValues : PrivateInputAssignment
  authorizedOutputs : AuthorizedOutputValues
  corruptedRandomTape : PassiveRandomTape
  realCoins : PassiveRandomTape
  simulatorCoins : PassiveRandomTape

structure PassiveSimulatorInput where
  family : RuntimeProtocolFamily
  role : RuntimeDeriverRole
  corruptedPrivateInputs : List (EvaluationInputClass × PrivateInputValue)
  authorizedOutputs : List AuthorizedOutput
  corruptedRandomTape : PassiveRandomTape
  publicView : RuntimeRoleView
  deriving DecidableEq, Repr

structure PassiveObservedMessage where
  shape : RuntimeMessageShape
  payload : PassiveBytes
  deriving DecidableEq, Repr

structure PassiveInternalStateSnapshot where
  component : PassiveComponentClass
  stateBytes : PassiveBytes
  deriving DecidableEq, Repr

structure PassiveComponentView where
  messages : List PassiveObservedMessage
  internalState : List PassiveInternalStateSnapshot
  deriving DecidableEq, Repr

structure PassivePayloadCore where
  baseOt : PassiveComponentView
  otExtension : PassiveComponentView
  inputLabels : PassiveComponentView
  garbledTables : PassiveComponentView
  outputMessages : PassiveComponentView
  deriving DecidableEq, Repr

structure PassivePayloadView where
  core : PassivePayloadCore
  orderedMessages : List PassiveObservedMessage
  transcript : PassiveBytes
  deriving DecidableEq, Repr

structure PassiveObservedView where
  leakage : PassiveSimulatorInput
  payload : PassivePayloadView
  deriving DecidableEq, Repr

structure PassiveProtocolSemantics where
  realBaseOt :
    RuntimeProtocolFamily → RuntimeDeriverRole →
      PassiveExperimentInput → PassiveComponentView
  realOtExtension :
    RuntimeProtocolFamily → RuntimeDeriverRole →
      PassiveExperimentInput → PassiveComponentView
  realInputLabels :
    RuntimeProtocolFamily → RuntimeDeriverRole →
      PassiveExperimentInput → PassiveComponentView
  realGarbledTables :
    RuntimeProtocolFamily → RuntimeDeriverRole →
      PassiveExperimentInput → PassiveComponentView
  realOutputMessages :
    RuntimeProtocolFamily → RuntimeDeriverRole →
      PassiveExperimentInput → PassiveComponentView
  simulateBaseOt : PassiveSimulatorInput → PassiveRandomTape → PassiveComponentView
  simulateOtExtension :
    PassiveSimulatorInput → PassiveRandomTape → PassiveComponentView
  simulateInputLabels :
    PassiveSimulatorInput → PassiveRandomTape → PassiveComponentView
  simulateGarbledTables :
    PassiveSimulatorInput → PassiveRandomTape → PassiveComponentView
  simulateOutputMessages :
    PassiveSimulatorInput → PassiveRandomTape → PassiveComponentView
  orderedMessages :
    RuntimeRoleView → PassivePayloadCore → List PassiveObservedMessage
  transcript : RuntimeRoleView → PassivePayloadCore → PassiveBytes

def rolePrivateInputClasses :
    RuntimeProtocolFamily → RuntimeDeriverRole → List EvaluationInputClass
  | .activation, .deriverA =>
      [.activationDeriverAYClient,
        .activationDeriverAYServer,
        .activationDeriverATauClient,
        .activationDeriverATauServer]
  | .activation, .deriverB =>
      [.activationDeriverBYClient,
        .activationDeriverBYServer,
        .activationDeriverBTauClient,
        .activationDeriverBTauServer]
  | .export, .deriverA =>
      [.exportDeriverAYClient, .exportDeriverAYServer]
  | .export, .deriverB =>
      [.exportDeriverBYClient, .exportDeriverBYServer]

def inputOwner : EvaluationInputClass → RuntimeDeriverRole
  | .activationDeriverAYClient => .deriverA
  | .activationDeriverAYServer => .deriverA
  | .activationDeriverATauClient => .deriverA
  | .activationDeriverATauServer => .deriverA
  | .activationDeriverBYClient => .deriverB
  | .activationDeriverBYServer => .deriverB
  | .activationDeriverBTauClient => .deriverB
  | .activationDeriverBTauServer => .deriverB
  | .exportDeriverAYClient => .deriverA
  | .exportDeriverAYServer => .deriverA
  | .exportDeriverBYClient => .deriverB
  | .exportDeriverBYServer => .deriverB

def authorizedOutputClasses :
    RuntimeProtocolFamily → List AuthorizedOutputClass
  | .activation =>
      [.activationClientPackageShare, .activationSigningWorkerPackageShare]
  | .export => [.exportPackageShare]

def selectAuthorizedOutputs
    (family : RuntimeProtocolFamily)
    (values : AuthorizedOutputValues) :
    List AuthorizedOutput :=
  match family with
  | .activation =>
      [⟨.activationClientPackageShare, values.activationClientPackageShare⟩,
        ⟨.activationSigningWorkerPackageShare,
          values.activationSigningWorkerPackageShare⟩]
  | .export =>
      [⟨.exportPackageShare, values.exportPackageShare⟩]

def selectCorruptedPrivateInputs
    (family : RuntimeProtocolFamily)
    (role : RuntimeDeriverRole)
    (privateInputs : PrivateInputAssignment) :
    List (EvaluationInputClass × PrivateInputValue) :=
  (rolePrivateInputClasses family role).map
    (fun input => (input, privateInputs input))

def passiveSimulatorInput
    (family : RuntimeProtocolFamily)
    (role : RuntimeDeriverRole)
    (experiment : PassiveExperimentInput) :
    PassiveSimulatorInput :=
  { family
    role
    corruptedPrivateInputs :=
      selectCorruptedPrivateInputs family role experiment.corruptedPrivateValues
    authorizedOutputs := selectAuthorizedOutputs family experiment.authorizedOutputs
    corruptedRandomTape := experiment.corruptedRandomTape
    publicView := runtimeRoleView family role }

def passiveHybridCore
    (semantics : PassiveProtocolSemantics)
    (family : RuntimeProtocolFamily)
    (role : RuntimeDeriverRole)
    (stage : PassiveHybridStage)
    (experiment : PassiveExperimentInput) :
    PassivePayloadCore :=
  let simulatorInput := passiveSimulatorInput family role experiment
  let simulatorCoins := experiment.simulatorCoins
  match stage with
  | .real =>
      ⟨semantics.realBaseOt family role experiment,
        semantics.realOtExtension family role experiment,
        semantics.realInputLabels family role experiment,
        semantics.realGarbledTables family role experiment,
        semantics.realOutputMessages family role experiment⟩
  | .idealBaseOt =>
      ⟨semantics.simulateBaseOt simulatorInput simulatorCoins,
        semantics.realOtExtension family role experiment,
        semantics.realInputLabels family role experiment,
        semantics.realGarbledTables family role experiment,
        semantics.realOutputMessages family role experiment⟩
  | .idealOtExtension =>
      ⟨semantics.simulateBaseOt simulatorInput simulatorCoins,
        semantics.simulateOtExtension simulatorInput simulatorCoins,
        semantics.realInputLabels family role experiment,
        semantics.realGarbledTables family role experiment,
        semantics.realOutputMessages family role experiment⟩
  | .simulatedInputLabels =>
      ⟨semantics.simulateBaseOt simulatorInput simulatorCoins,
        semantics.simulateOtExtension simulatorInput simulatorCoins,
        semantics.simulateInputLabels simulatorInput simulatorCoins,
        semantics.realGarbledTables family role experiment,
        semantics.realOutputMessages family role experiment⟩
  | .simulatedGarbling =>
      ⟨semantics.simulateBaseOt simulatorInput simulatorCoins,
        semantics.simulateOtExtension simulatorInput simulatorCoins,
        semantics.simulateInputLabels simulatorInput simulatorCoins,
        semantics.simulateGarbledTables simulatorInput simulatorCoins,
        semantics.realOutputMessages family role experiment⟩
  | .ideal =>
      ⟨semantics.simulateBaseOt simulatorInput simulatorCoins,
        semantics.simulateOtExtension simulatorInput simulatorCoins,
        semantics.simulateInputLabels simulatorInput simulatorCoins,
        semantics.simulateGarbledTables simulatorInput simulatorCoins,
        semantics.simulateOutputMessages simulatorInput simulatorCoins⟩

def passivePayloadFromCore
    (semantics : PassiveProtocolSemantics)
    (publicView : RuntimeRoleView)
    (core : PassivePayloadCore) :
    PassivePayloadView :=
  { core
    orderedMessages := semantics.orderedMessages publicView core
    transcript := semantics.transcript publicView core }

def passiveObservedView
    (semantics : PassiveProtocolSemantics)
    (simulatorInput : PassiveSimulatorInput)
    (core : PassivePayloadCore) :
    PassiveObservedView :=
  { leakage := simulatorInput
    payload := passivePayloadFromCore semantics simulatorInput.publicView core }

def passiveIdealSimulator
    (semantics : PassiveProtocolSemantics)
    (simulatorInput : PassiveSimulatorInput)
    (simulatorCoins : PassiveRandomTape) :
    PassiveObservedView :=
  passiveObservedView semantics simulatorInput
    ⟨semantics.simulateBaseOt simulatorInput simulatorCoins,
      semantics.simulateOtExtension simulatorInput simulatorCoins,
      semantics.simulateInputLabels simulatorInput simulatorCoins,
      semantics.simulateGarbledTables simulatorInput simulatorCoins,
      semantics.simulateOutputMessages simulatorInput simulatorCoins⟩

abbrev PassiveSecurityGame := PassiveExperimentInput → PassiveObservedView
abbrev PassiveDistinguisher := PassiveObservedView → Bool
abbrev PassiveAdvantageBound := Nat → Nat

def passiveSecurityGame
    (semantics : PassiveProtocolSemantics)
    (family : RuntimeProtocolFamily)
    (role : RuntimeDeriverRole)
    (stage : PassiveHybridStage) :
    PassiveSecurityGame :=
  fun experiment =>
    let simulatorInput := passiveSimulatorInput family role experiment
    match stage with
    | .ideal =>
        passiveIdealSimulator semantics simulatorInput experiment.simulatorCoins
    | stage =>
        passiveObservedView semantics simulatorInput
          (passiveHybridCore semantics family role stage experiment)

def passiveAcceptanceCount
    (game : PassiveSecurityGame)
    (samples : List PassiveExperimentInput)
    (distinguisher : PassiveDistinguisher) :
    Nat :=
  samples.countP (fun sample => distinguisher (game sample))

def ConcreteStatisticallyClose
    (bound : PassiveAdvantageBound)
    (left right : PassiveSecurityGame) :
    Prop :=
  ∀ samples distinguisher,
    passiveAcceptanceCount left samples distinguisher ≤
        passiveAcceptanceCount right samples distinguisher +
          bound samples.length ∧
      passiveAcceptanceCount right samples distinguisher ≤
        passiveAcceptanceCount left samples distinguisher +
          bound samples.length

def concreteClosenessTrans
    (left middle right : PassiveSecurityGame)
    (leftBound rightBound : PassiveAdvantageBound)
    (leftMiddle : ConcreteStatisticallyClose leftBound left middle)
    (middleRight : ConcreteStatisticallyClose rightBound middle right) :
    ConcreteStatisticallyClose
      (fun sampleCount => leftBound sampleCount + rightBound sampleCount)
      left right := by
  intro samples distinguisher
  have first := leftMiddle samples distinguisher
  have second := middleRight samples distinguisher
  constructor
  · change passiveAcceptanceCount left samples distinguisher ≤
      passiveAcceptanceCount right samples distinguisher +
        (leftBound samples.length + rightBound samples.length)
    omega
  · change passiveAcceptanceCount right samples distinguisher ≤
      passiveAcceptanceCount left samples distinguisher +
        (leftBound samples.length + rightBound samples.length)
    omega

structure PassiveHybridTransitionAssumptions
    (semantics : PassiveProtocolSemantics) where
  baseOtBound : PassiveAdvantageBound
  otExtensionBound : PassiveAdvantageBound
  inputLabelsBound : PassiveAdvantageBound
  garblingBound : PassiveAdvantageBound
  outputBound : PassiveAdvantageBound
  baseOt :
    ∀ family role,
      ConcreteStatisticallyClose baseOtBound
        (passiveSecurityGame semantics family role .real)
        (passiveSecurityGame semantics family role .idealBaseOt)
  otExtension :
    ∀ family role,
      ConcreteStatisticallyClose otExtensionBound
        (passiveSecurityGame semantics family role .idealBaseOt)
        (passiveSecurityGame semantics family role .idealOtExtension)
  inputLabels :
    ∀ family role,
      ConcreteStatisticallyClose inputLabelsBound
        (passiveSecurityGame semantics family role .idealOtExtension)
        (passiveSecurityGame semantics family role .simulatedInputLabels)
  garbling :
    ∀ family role,
      ConcreteStatisticallyClose garblingBound
        (passiveSecurityGame semantics family role .simulatedInputLabels)
        (passiveSecurityGame semantics family role .simulatedGarbling)
  output :
    ∀ family role,
      ConcreteStatisticallyClose outputBound
        (passiveSecurityGame semantics family role .simulatedGarbling)
        (passiveSecurityGame semantics family role .ideal)

def passiveCompositionBound
    {semantics : PassiveProtocolSemantics}
    (assumptions : PassiveHybridTransitionAssumptions semantics) :
    PassiveAdvantageBound :=
  fun sampleCount =>
    assumptions.baseOtBound sampleCount +
      (assumptions.otExtensionBound sampleCount +
        (assumptions.inputLabelsBound sampleCount +
          (assumptions.garblingBound sampleCount +
            assumptions.outputBound sampleCount)))

structure ExportDeriverALeakage where
  yClient : PrivateInputValue
  yServer : PrivateInputValue
  outputPackageShare : AuthorizedPackageShare
  corruptedRandomTape : PassiveRandomTape
  deriving DecidableEq, Repr

def exportDeriverASimulatorInput
    (leakage : ExportDeriverALeakage) :
    PassiveSimulatorInput :=
  { family := .export
    role := .deriverA
    corruptedPrivateInputs :=
      [(.exportDeriverAYClient, leakage.yClient),
        (.exportDeriverAYServer, leakage.yServer)]
    authorizedOutputs :=
      [⟨.exportPackageShare, leakage.outputPackageShare⟩]
    corruptedRandomTape := leakage.corruptedRandomTape
    publicView := exportDeriverAView }

def exportDeriverASimulator
    (semantics : PassiveProtocolSemantics)
    (leakage : ExportDeriverALeakage)
    (simulatorCoins : PassiveRandomTape) :
    PassiveObservedView :=
  passiveIdealSimulator semantics
    (exportDeriverASimulatorInput leakage) simulatorCoins

theorem activationSimulatorReceivesExactlyOwnFourInputs
    (role : RuntimeDeriverRole) :
    rolePrivateInputClasses .activation role =
      match role with
      | .deriverA =>
          [.activationDeriverAYClient,
            .activationDeriverAYServer,
            .activationDeriverATauClient,
            .activationDeriverATauServer]
      | .deriverB =>
          [.activationDeriverBYClient,
            .activationDeriverBYServer,
            .activationDeriverBTauClient,
            .activationDeriverBTauServer] := by
  cases role <;> rfl

theorem exportSimulatorReceivesExactlyOwnTwoInputs
    (role : RuntimeDeriverRole) :
    rolePrivateInputClasses .export role =
      match role with
      | .deriverA =>
          [.exportDeriverAYClient, .exportDeriverAYServer]
      | .deriverB =>
          [.exportDeriverBYClient, .exportDeriverBYServer] := by
  cases role <;> rfl

theorem simulatorExcludesEveryPeerPrivateInput
    (family : RuntimeProtocolFamily)
    (role : RuntimeDeriverRole)
    (input : EvaluationInputClass)
    (included : input ∈ rolePrivateInputClasses family role) :
    inputOwner input = role := by
  cases family <;> cases role <;> cases input <;>
    simp_all [rolePrivateInputClasses, inputOwner]

theorem exportDeriverASimulatorUsesExactTypedLeakage
    (semantics : PassiveProtocolSemantics)
    (leakage : ExportDeriverALeakage)
    (simulatorCoins : PassiveRandomTape) :
    (exportDeriverASimulator semantics leakage simulatorCoins).leakage =
      exportDeriverASimulatorInput leakage ∧
    (exportDeriverASimulator semantics leakage simulatorCoins).leakage.publicView =
      exportDeriverAView := by
  exact ⟨rfl, rfl⟩

theorem everyHybridPreservesTheProductionLinkedPublicView
    (semantics : PassiveProtocolSemantics)
    (family : RuntimeProtocolFamily)
    (role : RuntimeDeriverRole)
    (stage : PassiveHybridStage)
    (experiment : PassiveExperimentInput) :
    ((passiveSecurityGame semantics family role stage) experiment).leakage.publicView =
      runtimeRoleView family role := by
  cases stage <;> rfl

theorem idealSimulatorIsIndependentOfHonestPrivateInputsAndRealCoins
    (semantics : PassiveProtocolSemantics)
    (family : RuntimeProtocolFamily)
    (role : RuntimeDeriverRole)
    (corruptedPrivateValues : PrivateInputAssignment)
    (honestLeft honestRight : PrivateInputAssignment)
    (authorizedOutputs : AuthorizedOutputValues)
    (corruptedRandomTape realCoinsLeft realCoinsRight simulatorCoins :
      PassiveRandomTape) :
    (passiveSecurityGame semantics family role .ideal)
        ⟨corruptedPrivateValues, honestLeft, authorizedOutputs,
          corruptedRandomTape, realCoinsLeft, simulatorCoins⟩ =
      (passiveSecurityGame semantics family role .ideal)
        ⟨corruptedPrivateValues, honestRight, authorizedOutputs,
          corruptedRandomTape, realCoinsRight, simulatorCoins⟩ := by
  rfl

theorem passiveConditionalCompositionBound
    (semantics : PassiveProtocolSemantics)
    (assumptions : PassiveHybridTransitionAssumptions semantics)
    (family : RuntimeProtocolFamily)
    (role : RuntimeDeriverRole) :
    ConcreteStatisticallyClose (passiveCompositionBound assumptions)
      (passiveSecurityGame semantics family role .real)
      (passiveSecurityGame semantics family role .ideal) := by
  exact concreteClosenessTrans _ _ _
    assumptions.baseOtBound
    (fun sampleCount =>
      assumptions.otExtensionBound sampleCount +
        (assumptions.inputLabelsBound sampleCount +
          (assumptions.garblingBound sampleCount +
            assumptions.outputBound sampleCount)))
    (assumptions.baseOt family role)
    (concreteClosenessTrans _ _ _
      assumptions.otExtensionBound
      (fun sampleCount =>
        assumptions.inputLabelsBound sampleCount +
          (assumptions.garblingBound sampleCount +
            assumptions.outputBound sampleCount))
      (assumptions.otExtension family role)
      (concreteClosenessTrans _ _ _
        assumptions.inputLabelsBound
        (fun sampleCount =>
          assumptions.garblingBound sampleCount +
            assumptions.outputBound sampleCount)
        (assumptions.inputLabels family role)
        (concreteClosenessTrans _ _ _
          assumptions.garblingBound
          assumptions.outputBound
          (assumptions.garbling family role)
          (assumptions.output family role))))

theorem exportPassiveDeriverAConditionalComposition
    (semantics : PassiveProtocolSemantics)
    (assumptions : PassiveHybridTransitionAssumptions semantics) :
    ConcreteStatisticallyClose (passiveCompositionBound assumptions)
      (passiveSecurityGame semantics .export .deriverA .real)
      (passiveSecurityGame semantics .export .deriverA .ideal) := by
  exact passiveConditionalCompositionBound
    semantics assumptions .export .deriverA

theorem exportPassiveDeriverBConditionalComposition
    (semantics : PassiveProtocolSemantics)
    (assumptions : PassiveHybridTransitionAssumptions semantics) :
    ConcreteStatisticallyClose (passiveCompositionBound assumptions)
      (passiveSecurityGame semantics .export .deriverB .real)
      (passiveSecurityGame semantics .export .deriverB .ideal) := by
  exact passiveConditionalCompositionBound
    semantics assumptions .export .deriverB

theorem activationPassiveDeriverAConditionalComposition
    (semantics : PassiveProtocolSemantics)
    (assumptions : PassiveHybridTransitionAssumptions semantics) :
    ConcreteStatisticallyClose (passiveCompositionBound assumptions)
      (passiveSecurityGame semantics .activation .deriverA .real)
      (passiveSecurityGame semantics .activation .deriverA .ideal) := by
  exact passiveConditionalCompositionBound
    semantics assumptions .activation .deriverA

theorem activationPassiveDeriverBConditionalComposition
    (semantics : PassiveProtocolSemantics)
    (assumptions : PassiveHybridTransitionAssumptions semantics) :
    ConcreteStatisticallyClose (passiveCompositionBound assumptions)
      (passiveSecurityGame semantics .activation .deriverB .real)
      (passiveSecurityGame semantics .activation .deriverB .ideal) := by
  exact passiveConditionalCompositionBound
    semantics assumptions .activation .deriverB

end Ed25519YaoModel
