import Ed25519YaoModel.RecoveryCredentialTransition

/-!
Construction-independent structural model for recovery evaluator admission.
Same-root proof validity, selected-mechanism evidence validity, authenticated
store verification, durable replay, and production constant-time behavior
remain assumptions or later obligations.
-/

namespace Ed25519YaoModel

inductive RecoveryEvaluatorPublicState where
  | registeredActive
  | credentialSuspended
  | pendingActivation
  deriving DecidableEq, Repr

structure RecoveryAdmissionCommon where
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
  registeredIdentity : RecoveryIdentityBinding
  activeStateVersion : Nat
  activeCredential : Nat
  replacementCredential : Nat
  replacementIsDistinct : replacementCredential ≠ activeCredential
  sameRootEvidenceArtifact : Nat
  selectedMechanismAcceptanceEvidence : Nat
  selectedMechanismAcceptanceEvidenceIsNonzero :
    selectedMechanismAcceptanceEvidence ≠ 0
  currentActivationEpoch : Nat
  nextActivationEpoch : Nat
  activationEpochAdvances : currentActivationEpoch < nextActivationEpoch
  oneUseExecution : Nat
  oneUseExecutionIsNonzero : oneUseExecution ≠ 0
  checkedAtUnixMs : Nat
  checkedAtIsNonzero : checkedAtUnixMs ≠ 0
  requestExpiryUnixMs : Nat
  acceptedBeforeExpiry : checkedAtUnixMs ≤ requestExpiryUnixMs
  deriving Repr

structure TerminalRecoveryEvaluatorAdmission where
  common : RecoveryAdmissionCommon
  admissionDigest : Nat
  deriving Repr

def TerminalRecoveryEvaluatorAdmission.suspension
    (terminal : TerminalRecoveryEvaluatorAdmission) : SuspendedRecoveryCredentialState :=
  {
    identity := terminal.common.registeredIdentity
    oldCredential := terminal.common.activeCredential
    replacementCredential := terminal.common.replacementCredential
    activeStateVersion := terminal.common.activeStateVersion
    activeActivationEpoch := terminal.common.currentActivationEpoch
    replacementIsDistinct := terminal.common.replacementIsDistinct
  }

structure AcceptedRecoveryEvaluation where
  terminal : TerminalRecoveryEvaluatorAdmission
  before : RecoveryEvaluatorPublicState := .registeredActive
  after : RecoveryEvaluatorPublicState := .credentialSuspended
  evaluationCount : Nat := 1
  deriving Repr

structure RecoveryEvaluationCandidate where
  terminal : TerminalRecoveryEvaluatorAdmission
  registeredPublicKey : Nat
  outputCommittedReceipt : Nat
  deriving Repr

structure RecoveryEvaluatorPendingActivation where
  candidate : RecoveryEvaluationCandidate
  state : RecoveryEvaluatorPublicState := .pendingActivation
  deriving Repr

structure RecoveryEvaluatorMetadataConsumed where
  candidate : RecoveryEvaluationCandidate
  deriving Repr

structure RecoveryEvaluatorWorkerActivated where
  candidate : RecoveryEvaluationCandidate
  deriving Repr

structure RecoveryEvaluatorPromoted where
  terminal : TerminalRecoveryEvaluatorAdmission
  credentialState : PromotedRecoveryCredentialState

structure AbortedRecoveryEvaluation where
  terminal : TerminalRecoveryEvaluatorAdmission
  suspension : SuspendedRecoveryCredentialState
  burnedExecution : Nat
  before : RecoveryEvaluatorPublicState := .credentialSuspended
  after : RecoveryEvaluatorPublicState := .credentialSuspended

def admitRecovery
    (terminal : TerminalRecoveryEvaluatorAdmission) : AcceptedRecoveryEvaluation :=
  { terminal }

def commitRecoveryCandidate
    (evaluation : AcceptedRecoveryEvaluation)
    (outputCommittedReceipt : Nat) : RecoveryEvaluatorPendingActivation :=
  { candidate := {
      terminal := evaluation.terminal
      registeredPublicKey :=
        evaluation.terminal.common.registeredIdentity.registeredPublicKey
      outputCommittedReceipt } }

def consumeRecoveryEvaluatorMetadata
    (pending : RecoveryEvaluatorPendingActivation) : RecoveryEvaluatorMetadataConsumed :=
  { candidate := pending.candidate }

def activateRecoveryEvaluatorWorker
    (consumed : RecoveryEvaluatorMetadataConsumed) : RecoveryEvaluatorWorkerActivated :=
  { candidate := consumed.candidate }

def promoteRecoveryEvaluatorWorker
    (activated : RecoveryEvaluatorWorkerActivated)
    (nextStateVersion : Nat)
    (stateVersionAdvances :
      activated.candidate.terminal.common.activeStateVersion < nextStateVersion) :
    RecoveryEvaluatorPromoted :=
  let terminal := activated.candidate.terminal
  let authority : VerifiedRecoveryPromotionAuthority :=
    {
      workerActivated := ⟨terminal.suspension⟩
      nextStateVersion
      nextActivationEpoch := terminal.common.nextActivationEpoch
      stateVersionAdvances
      activationEpochAdvances := terminal.common.activationEpochAdvances
    }
  {
    terminal
    credentialState := promoteVerifiedRecovery authority
  }

def abortRecoveryEvaluation
    (evaluation : AcceptedRecoveryEvaluation) : AbortedRecoveryEvaluation :=
  {
    terminal := evaluation.terminal
    suspension := evaluation.terminal.suspension
    burnedExecution := evaluation.terminal.common.oneUseExecution
  }

theorem recoveryAdmissionIsActiveToSuspendedBoundary
    (terminal : TerminalRecoveryEvaluatorAdmission) :
    (admitRecovery terminal).before = .registeredActive ∧
      (admitRecovery terminal).after = .credentialSuspended := by
  exact ⟨rfl, rfl⟩

theorem recoveryAdmissionBindsOneDurableIdentityAndRequest
    (terminal : TerminalRecoveryEvaluatorAdmission) :
    (admitRecovery terminal).terminal.common.durableIdentityScope =
        terminal.common.durableIdentityScope ∧
      (admitRecovery terminal).terminal.common.request = terminal.common.request := by
  exact ⟨rfl, rfl⟩

theorem recoveryAdmissionBindsOneAuthorizationAndTranscript
    (terminal : TerminalRecoveryEvaluatorAdmission) :
    (admitRecovery terminal).terminal.common.authorization =
        terminal.common.authorization ∧
      (admitRecovery terminal).terminal.common.transcript = terminal.common.transcript := by
  exact ⟨rfl, rfl⟩

theorem recoveryAdmissionBindsOrderedProvenanceStatements
    (terminal : TerminalRecoveryEvaluatorAdmission) :
    (admitRecovery terminal).terminal.common.provenancePair =
        terminal.common.provenancePair ∧
      (admitRecovery terminal).terminal.common.deriverAStatement =
        terminal.common.deriverAStatement ∧
      (admitRecovery terminal).terminal.common.deriverBStatement =
        terminal.common.deriverBStatement := by
  exact ⟨rfl, rfl, rfl⟩

theorem recoveryAdmissionBindsAuthenticatedStoreAuthorityAndVersion
    (terminal : TerminalRecoveryEvaluatorAdmission) :
    (admitRecovery terminal).terminal.common.signedStoreResolution =
        terminal.common.signedStoreResolution ∧
      (admitRecovery terminal).terminal.common.storeAuthorityEpoch =
        terminal.common.storeAuthorityEpoch ∧
      (admitRecovery terminal).terminal.common.storeAuthorityDigest =
        terminal.common.storeAuthorityDigest ∧
      (admitRecovery terminal).terminal.common.activeStateVersion =
        terminal.common.activeStateVersion := by
  exact ⟨rfl, rfl, rfl, rfl⟩

theorem recoveryAdmissionBindsCompleteRegisteredIdentity
    (terminal : TerminalRecoveryEvaluatorAdmission) :
    (admitRecovery terminal).terminal.suspension.identity =
      terminal.common.registeredIdentity := by
  rfl

theorem recoveryAdmissionSuspendsExactDistinctCredentialTransition
    (terminal : TerminalRecoveryEvaluatorAdmission) :
    let suspension := (admitRecovery terminal).terminal.suspension
    suspension.oldCredential = terminal.common.activeCredential ∧
      suspension.replacementCredential = terminal.common.replacementCredential ∧
      suspension.replacementCredential ≠ suspension.oldCredential := by
  exact ⟨rfl, rfl, terminal.common.replacementIsDistinct⟩

theorem recoveryAdmissionBindsBothContinuityEvidenceIdentities
    (terminal : TerminalRecoveryEvaluatorAdmission) :
    (admitRecovery terminal).terminal.common.sameRootEvidenceArtifact =
        terminal.common.sameRootEvidenceArtifact ∧
      (admitRecovery terminal).terminal.common.selectedMechanismAcceptanceEvidence =
        terminal.common.selectedMechanismAcceptanceEvidence ∧
      terminal.common.selectedMechanismAcceptanceEvidence ≠ 0 := by
  exact ⟨rfl, rfl, terminal.common.selectedMechanismAcceptanceEvidenceIsNonzero⟩

theorem recoveryAdmissionBindsAdvancingEpochExecutionAndValidTime
    (terminal : TerminalRecoveryEvaluatorAdmission) :
    (admitRecovery terminal).terminal.common.currentActivationEpoch =
        terminal.common.currentActivationEpoch ∧
      (admitRecovery terminal).terminal.common.nextActivationEpoch =
        terminal.common.nextActivationEpoch ∧
      terminal.common.currentActivationEpoch < terminal.common.nextActivationEpoch ∧
      (admitRecovery terminal).terminal.common.oneUseExecution =
        terminal.common.oneUseExecution ∧
      terminal.common.oneUseExecution ≠ 0 ∧
      terminal.common.checkedAtUnixMs ≠ 0 ∧
      terminal.common.checkedAtUnixMs ≤ terminal.common.requestExpiryUnixMs := by
  exact ⟨rfl, rfl, terminal.common.activationEpochAdvances, rfl,
    terminal.common.oneUseExecutionIsNonzero, terminal.common.checkedAtIsNonzero,
    terminal.common.acceptedBeforeExpiry⟩

theorem acceptedRecoveryRunsExactlyOneEvaluation
    (terminal : TerminalRecoveryEvaluatorAdmission) :
    (admitRecovery terminal).evaluationCount = 1 := by
  rfl

theorem recoveryCommitmentRetainsTerminalThroughWorkerActivation
    (terminal : TerminalRecoveryEvaluatorAdmission)
    (outputCommittedReceipt nextStateVersion : Nat)
    (stateVersionAdvances : terminal.common.activeStateVersion < nextStateVersion) :
    let pending := commitRecoveryCandidate (admitRecovery terminal) outputCommittedReceipt
    let activated := activateRecoveryEvaluatorWorker
      (consumeRecoveryEvaluatorMetadata pending)
    let promoted := promoteRecoveryEvaluatorWorker
      activated nextStateVersion stateVersionAdvances
    pending.state = .pendingActivation ∧
      pending.candidate.terminal = terminal ∧
      pending.candidate.registeredPublicKey =
        terminal.common.registeredIdentity.registeredPublicKey ∧
      pending.candidate.outputCommittedReceipt = outputCommittedReceipt ∧
      activated.candidate = pending.candidate ∧
      promoted.terminal = terminal ∧
      promoted.credentialState.activeCredential = terminal.common.replacementCredential := by
  simp [commitRecoveryCandidate, admitRecovery, consumeRecoveryEvaluatorMetadata,
    activateRecoveryEvaluatorWorker, promoteRecoveryEvaluatorWorker,
    promoteVerifiedRecovery, TerminalRecoveryEvaluatorAdmission.suspension]

theorem recoveryAbortRetainsSuspensionTerminalAndBurnedExecution
    (terminal : TerminalRecoveryEvaluatorAdmission) :
    let aborted := abortRecoveryEvaluation (admitRecovery terminal)
    aborted.before = .credentialSuspended ∧
      aborted.after = .credentialSuspended ∧
      aborted.terminal = terminal ∧
      aborted.suspension = terminal.suspension ∧
      aborted.burnedExecution = terminal.common.oneUseExecution := by
  simp [abortRecoveryEvaluation, admitRecovery]

end Ed25519YaoModel
