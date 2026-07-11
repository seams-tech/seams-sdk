import Ed25519YaoModel.PartyViews

namespace Ed25519YaoModel

/-- The five frozen lifecycle stages at the evaluation-input boundary. -/
inductive EvaluationStage where
  | registration
  | activation
  | recovery
  | refresh
  | export
  deriving DecidableEq, Repr

/-- Family-specific private inputs. Activation and export fields stay distinct. -/
inductive EvaluationInputClass where
  | activationDeriverAYClient
  | activationDeriverAYServer
  | activationDeriverATauClient
  | activationDeriverATauServer
  | activationDeriverBYClient
  | activationDeriverBYServer
  | activationDeriverBTauClient
  | activationDeriverBTauServer
  | exportDeriverAYClient
  | exportDeriverAYServer
  | exportDeriverBYClient
  | exportDeriverBYServer
  deriving DecidableEq, Repr

/-- Randomness owned by the ideal functionality, never by a party view. -/
inductive FunctionalityCoinClass where
  | clientScalarOutput
  | signingWorkerScalarOutput
  | exportSeedOutput
  deriving DecidableEq, Repr

/-- Closed accepted-evaluation plan families. -/
inductive EvaluationPlan where
  | oneActivationEvaluation
  | zeroEvaluationContinuation
  | oneExportEvaluation
  deriving DecidableEq, Repr

/-- Exact evaluator-window counters in specification field order. -/
structure EvaluationCounts where
  yaoEvaluations : Nat
  deriverAInvocations : Nat
  deriverBInvocations : Nat
  contributionDerivations : Nat
  idealOutputShareSamples : Nat
  deriving DecidableEq, Repr

/-- Construction-independent pre-state classes at the accepted boundary. -/
inductive EvaluationPreStateClass where
  | unregistered
  | metadataContinuation
  | registered
  deriving DecidableEq, Repr

/-- The only role-private extension selected by a static observation. -/
inductive EvaluationInputOwner where
  | deriverA
  | deriverB
  deriving DecidableEq, Repr

def requestKindForEvaluationStage : EvaluationStage → RequestKind
  | .registration => .registration
  | .activation => .activation
  | .recovery => .recovery
  | .refresh => .refresh
  | .export => .export

def evaluationPlanAndCounts : EvaluationStage → EvaluationPlan × EvaluationCounts
  | .registration =>
      (.oneActivationEvaluation, ⟨1, 1, 1, 0, 2⟩)
  | .activation =>
      (.zeroEvaluationContinuation, ⟨0, 0, 0, 0, 0⟩)
  | .recovery =>
      (.oneActivationEvaluation, ⟨1, 1, 1, 0, 2⟩)
  | .refresh =>
      (.oneActivationEvaluation, ⟨1, 1, 1, 0, 2⟩)
  | .export =>
      (.oneExportEvaluation, ⟨1, 1, 1, 0, 1⟩)

def preStateClassForEvaluationStage : EvaluationStage → EvaluationPreStateClass
  | .registration => .unregistered
  | .activation => .metadataContinuation
  | .recovery => .registered
  | .refresh => .registered
  | .export => .registered

def staticEvaluationInputObservation : Party → Option EvaluationInputOwner
  | .deriverA => some .deriverA
  | .deriverB => some .deriverB
  | _ => none

def evaluationInputParties : List Party :=
  [.deriverA, .deriverB, .client, .signingWorker, .router, .observer, .diagnostics]

def isActivationEvaluationStage : EvaluationStage → Bool
  | .registration => true
  | .recovery => true
  | .refresh => true
  | .activation => false
  | .export => false

def isDeriverAActivationInput : EvaluationInputClass → Bool
  | .activationDeriverAYClient => true
  | .activationDeriverAYServer => true
  | .activationDeriverATauClient => true
  | .activationDeriverATauServer => true
  | _ => false

def isDeriverBActivationInput : EvaluationInputClass → Bool
  | .activationDeriverBYClient => true
  | .activationDeriverBYServer => true
  | .activationDeriverBTauClient => true
  | .activationDeriverBTauServer => true
  | _ => false

def isDeriverAExportSeedDomainInput : EvaluationInputClass → Bool
  | .exportDeriverAYClient => true
  | .exportDeriverAYServer => true
  | _ => false

def isDeriverBExportSeedDomainInput : EvaluationInputClass → Bool
  | .exportDeriverBYClient => true
  | .exportDeriverBYServer => true
  | _ => false

def isDeriverAInput : EvaluationInputClass → Bool
  | .activationDeriverAYClient => true
  | .activationDeriverAYServer => true
  | .activationDeriverATauClient => true
  | .activationDeriverATauServer => true
  | .exportDeriverAYClient => true
  | .exportDeriverAYServer => true
  | _ => false

def isDeriverBInput : EvaluationInputClass → Bool
  | .activationDeriverBYClient => true
  | .activationDeriverBYServer => true
  | .activationDeriverBTauClient => true
  | .activationDeriverBTauServer => true
  | .exportDeriverBYClient => true
  | .exportDeriverBYServer => true
  | _ => false

def isTauInput : EvaluationInputClass → Bool
  | .activationDeriverATauClient => true
  | .activationDeriverATauServer => true
  | .activationDeriverBTauClient => true
  | .activationDeriverBTauServer => true
  | _ => false

def mayReceivePrivateEvaluationInput :
    Party → EvaluationStage → EvaluationInputClass → Bool
  | .deriverA, .registration, input => isDeriverAActivationInput input
  | .deriverA, .recovery, input => isDeriverAActivationInput input
  | .deriverA, .refresh, input => isDeriverAActivationInput input
  | .deriverA, .export, input => isDeriverAExportSeedDomainInput input
  | .deriverB, .registration, input => isDeriverBActivationInput input
  | .deriverB, .recovery, input => isDeriverBActivationInput input
  | .deriverB, .refresh, input => isDeriverBActivationInput input
  | .deriverB, .export, input => isDeriverBExportSeedDomainInput input
  | _, _, _ => false

def functionalityUsesCoin : EvaluationStage → FunctionalityCoinClass → Bool
  | .registration, .clientScalarOutput => true
  | .registration, .signingWorkerScalarOutput => true
  | .recovery, .clientScalarOutput => true
  | .recovery, .signingWorkerScalarOutput => true
  | .refresh, .clientScalarOutput => true
  | .refresh, .signingWorkerScalarOutput => true
  | .export, .exportSeedOutput => true
  | _, _ => false

def isScalarOutputCoin : FunctionalityCoinClass → Bool
  | .clientScalarOutput => true
  | .signingWorkerScalarOutput => true
  | .exportSeedOutput => false

/-- Functionality randomness has no party-view projection. -/
def partyMayObserveFunctionalityCoin :
    Party → EvaluationStage → FunctionalityCoinClass → Bool
  | _, _, _ => false

theorem activationHasNoEvaluationInputOrCoin
    (party : Party) (input : EvaluationInputClass) (coin : FunctionalityCoinClass) :
    mayReceivePrivateEvaluationInput party .activation input = false ∧
      functionalityUsesCoin .activation coin = false := by
  cases party <;> cases input <;> cases coin <;>
    simp [mayReceivePrivateEvaluationInput, functionalityUsesCoin]

theorem deriverAActivationFamilyGetsExactlyOwnFourInputs
    (stage : EvaluationStage) (input : EvaluationInputClass)
    (activationFamily : isActivationEvaluationStage stage = true) :
    mayReceivePrivateEvaluationInput .deriverA stage input = true ↔
      isDeriverAActivationInput input = true := by
  cases stage <;> cases input <;>
    simp_all [mayReceivePrivateEvaluationInput, isActivationEvaluationStage,
      isDeriverAActivationInput]

theorem deriverBActivationFamilyGetsExactlyOwnFourInputs
    (stage : EvaluationStage) (input : EvaluationInputClass)
    (activationFamily : isActivationEvaluationStage stage = true) :
    mayReceivePrivateEvaluationInput .deriverB stage input = true ↔
      isDeriverBActivationInput input = true := by
  cases stage <;> cases input <;>
    simp_all [mayReceivePrivateEvaluationInput, isActivationEvaluationStage,
      isDeriverBActivationInput]

theorem deriverAExportGetsExactlyOwnTwoSeedDomainInputs
    (input : EvaluationInputClass) :
    mayReceivePrivateEvaluationInput .deriverA .export input = true ↔
      isDeriverAExportSeedDomainInput input = true := by
  cases input <;>
    simp [mayReceivePrivateEvaluationInput, isDeriverAExportSeedDomainInput]

theorem deriverBExportGetsExactlyOwnTwoSeedDomainInputs
    (input : EvaluationInputClass) :
    mayReceivePrivateEvaluationInput .deriverB .export input = true ↔
      isDeriverBExportSeedDomainInput input = true := by
  cases input <;>
    simp [mayReceivePrivateEvaluationInput, isDeriverBExportSeedDomainInput]

theorem exportEvaluationHasNoTauInput
    (party : Party) (input : EvaluationInputClass)
    (received : mayReceivePrivateEvaluationInput party .export input = true) :
    isTauInput input = false := by
  cases party <;> cases input <;>
    simp_all [mayReceivePrivateEvaluationInput, isDeriverAExportSeedDomainInput,
      isDeriverBExportSeedDomainInput, isTauInput]

theorem clientHasNoPrivateEvaluationInput
    (stage : EvaluationStage) (input : EvaluationInputClass) :
    mayReceivePrivateEvaluationInput .client stage input = false := by
  cases stage <;> cases input <;> rfl

theorem routerHasNoPrivateEvaluationInput
    (stage : EvaluationStage) (input : EvaluationInputClass) :
    mayReceivePrivateEvaluationInput .router stage input = false := by
  cases stage <;> cases input <;> rfl

theorem signingWorkerHasNoPrivateEvaluationInput
    (stage : EvaluationStage) (input : EvaluationInputClass) :
    mayReceivePrivateEvaluationInput .signingWorker stage input = false := by
  cases stage <;> cases input <;> rfl

theorem observerHasNoPrivateEvaluationInput
    (stage : EvaluationStage) (input : EvaluationInputClass) :
    mayReceivePrivateEvaluationInput .observer stage input = false := by
  cases stage <;> cases input <;> rfl

theorem diagnosticsHasNoPrivateEvaluationInput
    (stage : EvaluationStage) (input : EvaluationInputClass) :
    mayReceivePrivateEvaluationInput .diagnostics stage input = false := by
  cases stage <;> cases input <;> rfl

theorem deriverAExcludesPeerEvaluationInput
    (stage : EvaluationStage) (input : EvaluationInputClass)
    (peerOwned : isDeriverBInput input = true) :
    mayReceivePrivateEvaluationInput .deriverA stage input = false := by
  cases stage <;> cases input <;>
    simp_all [mayReceivePrivateEvaluationInput, isDeriverBInput,
      isDeriverAActivationInput, isDeriverAExportSeedDomainInput]

theorem deriverBExcludesPeerEvaluationInput
    (stage : EvaluationStage) (input : EvaluationInputClass)
    (peerOwned : isDeriverAInput input = true) :
    mayReceivePrivateEvaluationInput .deriverB stage input = false := by
  cases stage <;> cases input <;>
    simp_all [mayReceivePrivateEvaluationInput, isDeriverAInput,
      isDeriverBActivationInput, isDeriverBExportSeedDomainInput]

theorem functionalityOwnedCoinsAreAbsentFromAllPartyViews
    (party : Party) (stage : EvaluationStage) (coin : FunctionalityCoinClass) :
    partyMayObserveFunctionalityCoin party stage coin = false := by
  rfl

theorem scalarCoinsAreUsedExactlyForRegistrationRecoveryRefresh
    (stage : EvaluationStage) (coin : FunctionalityCoinClass)
    (scalar : isScalarOutputCoin coin = true) :
    functionalityUsesCoin stage coin = true ↔
      isActivationEvaluationStage stage = true := by
  cases stage <;> cases coin <;>
    simp_all [functionalityUsesCoin, isScalarOutputCoin, isActivationEvaluationStage]

theorem seedCoinIsUsedExactlyForExport (stage : EvaluationStage) :
    functionalityUsesCoin stage .exportSeedOutput = true ↔ stage = .export := by
  cases stage <;> simp [functionalityUsesCoin]

theorem evaluationStagesMapToExactRequestKinds :
    requestKindForEvaluationStage .registration = .registration ∧
      requestKindForEvaluationStage .activation = .activation ∧
      requestKindForEvaluationStage .recovery = .recovery ∧
      requestKindForEvaluationStage .refresh = .refresh ∧
      requestKindForEvaluationStage .export = .export := by
  simp [requestKindForEvaluationStage]

theorem evaluationStagesDetermineExactPlansAndCounts :
    evaluationPlanAndCounts .registration =
        (.oneActivationEvaluation, ⟨1, 1, 1, 0, 2⟩) ∧
      evaluationPlanAndCounts .activation =
        (.zeroEvaluationContinuation, ⟨0, 0, 0, 0, 0⟩) ∧
      evaluationPlanAndCounts .recovery =
        (.oneActivationEvaluation, ⟨1, 1, 1, 0, 2⟩) ∧
      evaluationPlanAndCounts .refresh =
        (.oneActivationEvaluation, ⟨1, 1, 1, 0, 2⟩) ∧
      evaluationPlanAndCounts .export =
        (.oneExportEvaluation, ⟨1, 1, 1, 0, 1⟩) := by
  simp [evaluationPlanAndCounts]

theorem evaluationStagesDetermineExactPreStateClasses :
    preStateClassForEvaluationStage .registration = .unregistered ∧
      preStateClassForEvaluationStage .activation = .metadataContinuation ∧
      preStateClassForEvaluationStage .recovery = .registered ∧
      preStateClassForEvaluationStage .refresh = .registered ∧
      preStateClassForEvaluationStage .export = .registered := by
  simp [preStateClassForEvaluationStage]

theorem evaluationInputRoleUniverseHasExactlySevenParties :
    evaluationInputParties =
      [.deriverA, .deriverB, .client, .signingWorker, .router, .observer, .diagnostics] := by
  rfl

theorem staticDeriverInputObservationsAreExact :
    staticEvaluationInputObservation .deriverA = some .deriverA ∧
      staticEvaluationInputObservation .deriverB = some .deriverB := by
  simp [staticEvaluationInputObservation]

theorem infrastructureHasNoStaticEvaluationInputObservation
    (party : Party)
    (infrastructure : party ≠ .deriverA ∧ party ≠ .deriverB) :
    staticEvaluationInputObservation party = none := by
  cases party <;> simp_all [staticEvaluationInputObservation]

end Ed25519YaoModel
