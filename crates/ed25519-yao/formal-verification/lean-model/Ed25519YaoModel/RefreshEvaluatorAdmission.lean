import Ed25519YaoModel.RecoveryEvaluatorAdmission

/-!
Construction-independent structural model for refresh evaluator admission.
Opposite-delta proof validity, refresh-delta entropy and anti-bias, selected-
mechanism evidence validity, authenticated store cryptography, durable replay,
selected-profile security, and production constant-time behavior remain
assumptions or later obligations.
-/

namespace Ed25519YaoModel

inductive RefreshEvaluatorPublicState where
  | registeredActive
  | preparedNextState
  | pendingActivation
  | promotedActive
  deriving DecidableEq, Repr

structure RefreshRoleStateBinding where
  roleRootRecord : Nat
  rootBindingArtifact : Nat
  roleRootEpoch : Nat
  stateRecord : Nat
  inputStateEpoch : Nat
  deriving DecidableEq, Repr

structure RefreshRegisteredIdentity where
  registeredPublicKey : Nat
  stableScope : Nat
  activeCredential : Nat
  activeActivationEpoch : Nat
  deriverA : RefreshRoleStateBinding
  deriverB : RefreshRoleStateBinding
  deriving DecidableEq, Repr

structure RefreshAdmissionCommon where
  durableIdentityScope : Nat
  request : Nat
  authorization : Nat
  transcript : Nat
  provenancePair : Nat
  deriverAStatement : Nat
  deriverBStatement : Nat
  signedStoreResolution : Nat
  storeAuthorityEpoch : Nat
  storeAuthorityDigest : Nat
  activeStateVersion : Nat
  currentIdentity : RefreshRegisteredIdentity
  nextDeriverA : RefreshRoleStateBinding
  nextDeriverB : RefreshRoleStateBinding
  continuityEvidenceArtifact : Nat
  selectedMechanismAcceptanceEvidence : Nat
  selectedMechanismAcceptanceEvidenceIsNonzero :
    selectedMechanismAcceptanceEvidence ≠ 0
  nextActivationEpoch : Nat
  activationEpochAdvances :
    currentIdentity.activeActivationEpoch < nextActivationEpoch
  deriverAEpochAdvances :
    currentIdentity.deriverA.inputStateEpoch < nextDeriverA.inputStateEpoch
  deriverBEpochAdvances :
    currentIdentity.deriverB.inputStateEpoch < nextDeriverB.inputStateEpoch
  oneUseExecution : Nat
  oneUseExecutionIsNonzero : oneUseExecution ≠ 0
  checkedAtUnixMs : Nat
  checkedAtIsNonzero : checkedAtUnixMs ≠ 0
  requestExpiryUnixMs : Nat
  acceptedBeforeExpiry : checkedAtUnixMs ≤ requestExpiryUnixMs
  deriving Repr

structure TerminalRefreshEvaluatorAdmission where
  common : RefreshAdmissionCommon
  admissionDigest : Nat
  deriving Repr

structure AcceptedRefreshEvaluation where
  terminal : TerminalRefreshEvaluatorAdmission
  before : RefreshEvaluatorPublicState := .registeredActive
  after : RefreshEvaluatorPublicState := .preparedNextState
  evaluationCount : Nat := 1
  deriving Repr

structure RefreshEvaluationCandidate where
  terminal : TerminalRefreshEvaluatorAdmission
  registeredPublicKey : Nat
  outputCommittedReceipt : Nat
  deriving Repr

structure RefreshEvaluatorPendingActivation where
  candidate : RefreshEvaluationCandidate
  state : RefreshEvaluatorPublicState := .pendingActivation
  deriving Repr

structure RefreshEvaluatorMetadataConsumed where
  candidate : RefreshEvaluationCandidate
  deriving Repr

structure RefreshEvaluatorWorkerActivated where
  candidate : RefreshEvaluationCandidate
  deriving Repr

structure RefreshPromotedIdentity where
  registeredPublicKey : Nat
  stableScope : Nat
  activeCredential : Nat
  activeActivationEpoch : Nat
  deriverA : RefreshRoleStateBinding
  deriverB : RefreshRoleStateBinding
  deriving DecidableEq, Repr

structure RefreshEvaluatorPromoted where
  terminal : TerminalRefreshEvaluatorAdmission
  identity : RefreshPromotedIdentity
  activeStateVersion : Nat
  stateVersionAdvances : terminal.common.activeStateVersion < activeStateVersion
  state : RefreshEvaluatorPublicState := .promotedActive
  deriving Repr

structure AbortedRefreshEvaluation where
  terminal : TerminalRefreshEvaluatorAdmission
  currentIdentity : RefreshRegisteredIdentity
  burnedExecution : Nat
  before : RefreshEvaluatorPublicState := .registeredActive
  after : RefreshEvaluatorPublicState := .registeredActive
  deriving Repr

def admitRefresh
    (terminal : TerminalRefreshEvaluatorAdmission) : AcceptedRefreshEvaluation :=
  { terminal }

def commitRefreshCandidate
    (evaluation : AcceptedRefreshEvaluation)
    (outputCommittedReceipt : Nat) : RefreshEvaluatorPendingActivation :=
  { candidate := {
      terminal := evaluation.terminal
      registeredPublicKey :=
        evaluation.terminal.common.currentIdentity.registeredPublicKey
      outputCommittedReceipt } }

def consumeRefreshEvaluatorMetadata
    (pending : RefreshEvaluatorPendingActivation) : RefreshEvaluatorMetadataConsumed :=
  { candidate := pending.candidate }

def activateRefreshEvaluatorWorker
    (consumed : RefreshEvaluatorMetadataConsumed) : RefreshEvaluatorWorkerActivated :=
  { candidate := consumed.candidate }

def promoteRefreshEvaluatorWorker
    (activated : RefreshEvaluatorWorkerActivated)
    (nextStateVersion : Nat)
    (stateVersionAdvances :
      activated.candidate.terminal.common.activeStateVersion < nextStateVersion) :
    RefreshEvaluatorPromoted :=
  let terminal := activated.candidate.terminal
  {
    terminal
    identity := {
      registeredPublicKey := terminal.common.currentIdentity.registeredPublicKey
      stableScope := terminal.common.currentIdentity.stableScope
      activeCredential := terminal.common.currentIdentity.activeCredential
      activeActivationEpoch := terminal.common.nextActivationEpoch
      deriverA := terminal.common.nextDeriverA
      deriverB := terminal.common.nextDeriverB }
    activeStateVersion := nextStateVersion
    stateVersionAdvances
  }

def abortRefreshEvaluation
    (evaluation : AcceptedRefreshEvaluation) : AbortedRefreshEvaluation :=
  {
    terminal := evaluation.terminal
    currentIdentity := evaluation.terminal.common.currentIdentity
    burnedExecution := evaluation.terminal.common.oneUseExecution
  }

theorem refreshAdmissionIsActiveToPreparedBoundary
    (terminal : TerminalRefreshEvaluatorAdmission) :
    (admitRefresh terminal).before = .registeredActive ∧
      (admitRefresh terminal).after = .preparedNextState := by
  exact ⟨rfl, rfl⟩

theorem refreshAdmissionBindsOneDurableIdentityAndRequest
    (terminal : TerminalRefreshEvaluatorAdmission) :
    (admitRefresh terminal).terminal.common.durableIdentityScope =
        terminal.common.durableIdentityScope ∧
      (admitRefresh terminal).terminal.common.request = terminal.common.request := by
  exact ⟨rfl, rfl⟩

theorem refreshAdmissionBindsOneAuthorizationAndTranscript
    (terminal : TerminalRefreshEvaluatorAdmission) :
    (admitRefresh terminal).terminal.common.authorization =
        terminal.common.authorization ∧
      (admitRefresh terminal).terminal.common.transcript = terminal.common.transcript := by
  exact ⟨rfl, rfl⟩

theorem refreshAdmissionBindsOrderedProvenanceStatements
    (terminal : TerminalRefreshEvaluatorAdmission) :
    (admitRefresh terminal).terminal.common.provenancePair =
        terminal.common.provenancePair ∧
      (admitRefresh terminal).terminal.common.deriverAStatement =
        terminal.common.deriverAStatement ∧
      (admitRefresh terminal).terminal.common.deriverBStatement =
        terminal.common.deriverBStatement := by
  exact ⟨rfl, rfl, rfl⟩

theorem refreshAdmissionBindsAuthenticatedStoreAuthorityAndVersion
    (terminal : TerminalRefreshEvaluatorAdmission) :
    (admitRefresh terminal).terminal.common.signedStoreResolution =
        terminal.common.signedStoreResolution ∧
      (admitRefresh terminal).terminal.common.storeAuthorityEpoch =
        terminal.common.storeAuthorityEpoch ∧
      (admitRefresh terminal).terminal.common.storeAuthorityDigest =
        terminal.common.storeAuthorityDigest ∧
      (admitRefresh terminal).terminal.common.activeStateVersion =
        terminal.common.activeStateVersion := by
  exact ⟨rfl, rfl, rfl, rfl⟩

theorem refreshAdmissionBindsCompleteCurrentIdentity
    (terminal : TerminalRefreshEvaluatorAdmission) :
    (admitRefresh terminal).terminal.common.currentIdentity =
      terminal.common.currentIdentity := by
  rfl

theorem refreshAdmissionBindsCompleteNextRoleStates
    (terminal : TerminalRefreshEvaluatorAdmission) :
    (admitRefresh terminal).terminal.common.nextDeriverA =
        terminal.common.nextDeriverA ∧
      (admitRefresh terminal).terminal.common.nextDeriverB =
        terminal.common.nextDeriverB := by
  exact ⟨rfl, rfl⟩

theorem refreshAdmissionBindsBothContinuityEvidenceIdentities
    (terminal : TerminalRefreshEvaluatorAdmission) :
    (admitRefresh terminal).terminal.common.continuityEvidenceArtifact =
        terminal.common.continuityEvidenceArtifact ∧
      (admitRefresh terminal).terminal.common.selectedMechanismAcceptanceEvidence =
        terminal.common.selectedMechanismAcceptanceEvidence ∧
      terminal.common.selectedMechanismAcceptanceEvidence ≠ 0 := by
  exact ⟨rfl, rfl, terminal.common.selectedMechanismAcceptanceEvidenceIsNonzero⟩

theorem refreshAdmissionBindsStrictEpochAdvancesExecutionAndValidTime
    (terminal : TerminalRefreshEvaluatorAdmission) :
    terminal.common.currentIdentity.activeActivationEpoch <
        terminal.common.nextActivationEpoch ∧
      terminal.common.currentIdentity.deriverA.inputStateEpoch <
        terminal.common.nextDeriverA.inputStateEpoch ∧
      terminal.common.currentIdentity.deriverB.inputStateEpoch <
        terminal.common.nextDeriverB.inputStateEpoch ∧
      (admitRefresh terminal).terminal.common.oneUseExecution =
        terminal.common.oneUseExecution ∧
      terminal.common.oneUseExecution ≠ 0 ∧
      terminal.common.checkedAtUnixMs ≠ 0 ∧
      terminal.common.checkedAtUnixMs ≤ terminal.common.requestExpiryUnixMs := by
  exact ⟨terminal.common.activationEpochAdvances,
    terminal.common.deriverAEpochAdvances,
    terminal.common.deriverBEpochAdvances,
    rfl,
    terminal.common.oneUseExecutionIsNonzero,
    terminal.common.checkedAtIsNonzero,
    terminal.common.acceptedBeforeExpiry⟩

theorem acceptedRefreshRunsExactlyOneEvaluation
    (terminal : TerminalRefreshEvaluatorAdmission) :
    (admitRefresh terminal).evaluationCount = 1 := by
  rfl

theorem refreshCommitmentRetainsTerminalThroughWorkerActivationAndPromotion
    (terminal : TerminalRefreshEvaluatorAdmission)
    (outputCommittedReceipt nextStateVersion : Nat)
    (stateVersionAdvances : terminal.common.activeStateVersion < nextStateVersion) :
    let pending := commitRefreshCandidate (admitRefresh terminal) outputCommittedReceipt
    let activated := activateRefreshEvaluatorWorker
      (consumeRefreshEvaluatorMetadata pending)
    let promoted := promoteRefreshEvaluatorWorker
      activated nextStateVersion stateVersionAdvances
    pending.state = .pendingActivation ∧
      pending.candidate.terminal = terminal ∧
      pending.candidate.registeredPublicKey =
        terminal.common.currentIdentity.registeredPublicKey ∧
      pending.candidate.outputCommittedReceipt = outputCommittedReceipt ∧
      activated.candidate = pending.candidate ∧
      promoted.terminal = terminal ∧
      promoted.state = .promotedActive ∧
      promoted.identity.registeredPublicKey =
        terminal.common.currentIdentity.registeredPublicKey ∧
      promoted.identity.stableScope = terminal.common.currentIdentity.stableScope ∧
      promoted.identity.activeCredential = terminal.common.currentIdentity.activeCredential ∧
      promoted.identity.activeActivationEpoch = terminal.common.nextActivationEpoch ∧
      promoted.identity.deriverA = terminal.common.nextDeriverA ∧
      promoted.identity.deriverB = terminal.common.nextDeriverB := by
  simp [commitRefreshCandidate, admitRefresh, consumeRefreshEvaluatorMetadata,
    activateRefreshEvaluatorWorker, promoteRefreshEvaluatorWorker]

theorem refreshAbortKeepsCurrentActiveRetainsTerminalAndBurnsExecution
    (terminal : TerminalRefreshEvaluatorAdmission) :
    let aborted := abortRefreshEvaluation (admitRefresh terminal)
    aborted.before = .registeredActive ∧
      aborted.after = .registeredActive ∧
      aborted.terminal = terminal ∧
      aborted.currentIdentity = terminal.common.currentIdentity ∧
      aborted.burnedExecution = terminal.common.oneUseExecution := by
  simp [abortRefreshEvaluation, admitRefresh]

end Ed25519YaoModel
