import Ed25519YaoModel.EvaluatorAbortViews

/-!
Construction-independent structural model for registration evaluator admission.
Authenticated absence, durable uniqueness, input-opening consistency, selected-
profile security, and production constant-time behavior remain assumptions or
later obligations.
-/

namespace Ed25519YaoModel

inductive RegistrationPublicState where
  | unregistered
  | pendingActivation
  deriving DecidableEq, Repr

structure RegistrationAdmissionCommon where
  durableIdentityScope : Nat
  request : Nat
  authorization : Nat
  transcript : Nat
  intent : Nat
  provenancePair : Nat
  provenanceSelectionArtifact : Nat
  selectedMechanismAcceptanceEvidence : Nat
  activationEpoch : Nat
  oneUseExecution : Nat
  checkedAtUnixMs : Nat
  requestExpiryUnixMs : Nat
  acceptedBeforeExpiry : checkedAtUnixMs ≤ requestExpiryUnixMs
  deriving Repr

structure TerminalRegistrationSelection where
  common : RegistrationAdmissionCommon
  selectionAttempt : Nat
  admissionDigest : Nat
  deriving Repr

structure AcceptedRegistrationEvaluation where
  selection : TerminalRegistrationSelection
  preState : RegistrationPublicState := .unregistered
  evaluationCount : Nat := 1
  deriving Repr

structure RegistrationCandidate where
  selection : TerminalRegistrationSelection
  registeredPublicKey : Nat
  outputCommittedReceipt : Nat
  deriving Repr

structure RegistrationPendingActivation where
  candidate : RegistrationCandidate
  state : RegistrationPublicState := .pendingActivation
  deriving Repr

structure MetadataConsumedRegistration where
  candidate : RegistrationCandidate
  deriving Repr

structure WorkerActivatedRegistration where
  candidate : RegistrationCandidate
  deriving Repr

structure AbortedRegistrationEvaluation where
  selection : TerminalRegistrationSelection
  burnedExecution : Nat
  before : RegistrationPublicState := .unregistered
  after : RegistrationPublicState := .unregistered
  deriving Repr

def admitRegistration
    (selection : TerminalRegistrationSelection) : AcceptedRegistrationEvaluation :=
  { selection }

def commitRegistrationCandidate
    (evaluation : AcceptedRegistrationEvaluation)
    (registeredPublicKey outputCommittedReceipt : Nat) : RegistrationPendingActivation :=
  { candidate := {
      selection := evaluation.selection
      registeredPublicKey
      outputCommittedReceipt } }

def consumeRegistrationMetadata
    (pending : RegistrationPendingActivation) : MetadataConsumedRegistration :=
  { candidate := pending.candidate }

def activateRegistrationWorker
    (consumed : MetadataConsumedRegistration) : WorkerActivatedRegistration :=
  { candidate := consumed.candidate }

def abortRegistration
    (evaluation : AcceptedRegistrationEvaluation) : AbortedRegistrationEvaluation :=
  { selection := evaluation.selection
    burnedExecution := evaluation.selection.common.oneUseExecution }

theorem registrationAdmissionRequiresUnregisteredPreState
    (selection : TerminalRegistrationSelection) :
    (admitRegistration selection).preState = .unregistered := by
  rfl

theorem registrationAdmissionBindsOneIdentityScope
    (selection : TerminalRegistrationSelection) :
    (admitRegistration selection).selection.common.durableIdentityScope =
      selection.common.durableIdentityScope := by
  rfl

theorem registrationAdmissionBindsOneRequest
    (selection : TerminalRegistrationSelection) :
    (admitRegistration selection).selection.common.request = selection.common.request := by
  rfl

theorem registrationAdmissionBindsOneAuthorization
    (selection : TerminalRegistrationSelection) :
    (admitRegistration selection).selection.common.authorization =
      selection.common.authorization := by
  rfl

theorem registrationAdmissionBindsOneTranscript
    (selection : TerminalRegistrationSelection) :
    (admitRegistration selection).selection.common.transcript = selection.common.transcript := by
  rfl

theorem registrationAdmissionBindsOneIntent
    (selection : TerminalRegistrationSelection) :
    (admitRegistration selection).selection.common.intent = selection.common.intent := by
  rfl

theorem registrationAdmissionBindsOneProvenancePair
    (selection : TerminalRegistrationSelection) :
    (admitRegistration selection).selection.common.provenancePair =
      selection.common.provenancePair := by
  rfl

theorem registrationAdmissionBindsOneInputSelection
    (selection : TerminalRegistrationSelection) :
    (admitRegistration selection).selection.common.provenanceSelectionArtifact =
        selection.common.provenanceSelectionArtifact ∧
      (admitRegistration selection).selection.common.selectedMechanismAcceptanceEvidence =
        selection.common.selectedMechanismAcceptanceEvidence := by
  exact ⟨rfl, rfl⟩

theorem registrationAdmissionBindsOneEpochExecutionAndValidTime
    (selection : TerminalRegistrationSelection) :
    (admitRegistration selection).selection.common.activationEpoch =
        selection.common.activationEpoch ∧
      (admitRegistration selection).selection.common.oneUseExecution =
        selection.common.oneUseExecution ∧
      selection.common.checkedAtUnixMs ≤ selection.common.requestExpiryUnixMs := by
  exact ⟨rfl, rfl, selection.common.acceptedBeforeExpiry⟩

theorem acceptedRegistrationRunsExactlyOneEvaluation
    (selection : TerminalRegistrationSelection) :
    (admitRegistration selection).evaluationCount = 1 := by
  rfl

theorem registrationCommitmentEstablishesExactlyOnePendingIdentity
    (selection : TerminalRegistrationSelection)
    (registeredPublicKey outputCommittedReceipt : Nat) :
    let pending := commitRegistrationCandidate
      (admitRegistration selection) registeredPublicKey outputCommittedReceipt
    pending.state = .pendingActivation ∧
      pending.candidate.selection.admissionDigest = selection.admissionDigest ∧
      pending.candidate.registeredPublicKey = registeredPublicKey ∧
      (activateRegistrationWorker (consumeRegistrationMetadata pending)).candidate =
        pending.candidate := by
  simp [commitRegistrationCandidate, admitRegistration, consumeRegistrationMetadata,
    activateRegistrationWorker]

theorem registrationAbortRetainsUnregisteredStateAndTerminalSelection
    (selection : TerminalRegistrationSelection) :
    let aborted := abortRegistration (admitRegistration selection)
    aborted.before = .unregistered ∧
      aborted.after = .unregistered ∧
      aborted.selection = selection ∧
      aborted.burnedExecution = selection.common.oneUseExecution := by
  simp [abortRegistration, admitRegistration]

end Ed25519YaoModel
