/-!
Construction-independent recovery credential transition policy. The model
tracks suspension through activation delivery and permits promotion only from a
verified worker-activation authority.
-/

namespace Ed25519YaoModel

inductive RecoveryCredentialAdmission where
  | active
  | suspended
  | tombstoned
  | notAdmitted
  deriving DecidableEq, Repr

structure RecoveryIdentityBinding where
  registeredPublicKey : Nat
  stableScope : Nat
  deriverARootRecord : Nat
  deriverARootBinding : Nat
  deriverARootEpoch : Nat
  deriverAInputStateRecord : Nat
  deriverAInputStateEpoch : Nat
  deriverBRootRecord : Nat
  deriverBRootBinding : Nat
  deriverBRootEpoch : Nat
  deriverBInputStateRecord : Nat
  deriverBInputStateEpoch : Nat
  deriving DecidableEq, Repr

structure ActiveRecoveryCredentialState where
  identity : RecoveryIdentityBinding
  activeCredential : Nat
  activeStateVersion : Nat
  activeActivationEpoch : Nat
  deriving DecidableEq, Repr

structure SuspendedRecoveryCredentialState where
  identity : RecoveryIdentityBinding
  oldCredential : Nat
  replacementCredential : Nat
  activeStateVersion : Nat
  activeActivationEpoch : Nat
  replacementIsDistinct : replacementCredential ≠ oldCredential

structure RecoveryOutputCommittedState where
  suspension : SuspendedRecoveryCredentialState

structure RecoveryMetadataConsumedState where
  suspension : SuspendedRecoveryCredentialState

structure RecoveryRecipientsReleasedState where
  suspension : SuspendedRecoveryCredentialState

structure RecoveryWorkerActivatedState where
  suspension : SuspendedRecoveryCredentialState

structure VerifiedRecoveryPromotionAuthority where
  workerActivated : RecoveryWorkerActivatedState
  nextStateVersion : Nat
  nextActivationEpoch : Nat
  stateVersionAdvances : workerActivated.suspension.activeStateVersion < nextStateVersion
  activationEpochAdvances :
    workerActivated.suspension.activeActivationEpoch < nextActivationEpoch

structure RecoveryCredentialTombstone where
  credential : Nat
  retiredAtStateVersion : Nat
  deriving DecidableEq, Repr

structure PromotedRecoveryCredentialState where
  identity : RecoveryIdentityBinding
  activeCredential : Nat
  activeStateVersion : Nat
  activeActivationEpoch : Nat
  oldCredentialTombstone : RecoveryCredentialTombstone
  deriving DecidableEq, Repr

inductive RecoveryPromotionAttempt where
  | verified (authority : VerifiedRecoveryPromotionAuthority)
  | unverified (workerActivated : RecoveryWorkerActivatedState)

def beginRecoveryCredentialTransition
    (active : ActiveRecoveryCredentialState)
    (replacementCredential : Nat)
    (replacementIsDistinct : replacementCredential ≠ active.activeCredential) :
    SuspendedRecoveryCredentialState :=
  {
    identity := active.identity
    oldCredential := active.activeCredential
    replacementCredential
    activeStateVersion := active.activeStateVersion
    activeActivationEpoch := active.activeActivationEpoch
    replacementIsDistinct
  }

def activeCredentialAdmission
    (state : ActiveRecoveryCredentialState) (credential : Nat) :
    RecoveryCredentialAdmission :=
  if credential = state.activeCredential then .active else .notAdmitted

def suspendedCredentialAdmission
    (state : SuspendedRecoveryCredentialState) (credential : Nat) :
    RecoveryCredentialAdmission :=
  if credential = state.oldCredential then .suspended else .notAdmitted

def evaluatorAbortRecovery
    (state : SuspendedRecoveryCredentialState) :
    SuspendedRecoveryCredentialState :=
  state

def commitRecoveryOutput
    (state : SuspendedRecoveryCredentialState) : RecoveryOutputCommittedState :=
  ⟨state⟩

def consumeRecoveryMetadata
    (state : RecoveryOutputCommittedState) : RecoveryMetadataConsumedState :=
  ⟨state.suspension⟩

def releaseRecoveryRecipients
    (state : RecoveryMetadataConsumedState) : RecoveryRecipientsReleasedState :=
  ⟨state.suspension⟩

def recordRecoveryWorkerActivation
    (state : RecoveryRecipientsReleasedState) : RecoveryWorkerActivatedState :=
  ⟨state.suspension⟩

def promoteVerifiedRecovery
    (authority : VerifiedRecoveryPromotionAuthority) :
    PromotedRecoveryCredentialState :=
  {
    identity := authority.workerActivated.suspension.identity
    activeCredential := authority.workerActivated.suspension.replacementCredential
    activeStateVersion := authority.nextStateVersion
    activeActivationEpoch := authority.nextActivationEpoch
    oldCredentialTombstone := {
      credential := authority.workerActivated.suspension.oldCredential
      retiredAtStateVersion :=
        authority.workerActivated.suspension.activeStateVersion
    }
  }

def promoteRecoveryAttempt :
    RecoveryPromotionAttempt → Option PromotedRecoveryCredentialState
  | .verified authority => some (promoteVerifiedRecovery authority)
  | .unverified _ => none

def promotedCredentialAdmission
    (state : PromotedRecoveryCredentialState) (credential : Nat) :
    RecoveryCredentialAdmission :=
  if credential = state.activeCredential then .active
  else if credential = state.oldCredentialTombstone.credential then .tombstoned
  else .notAdmitted

theorem recoveryStartSuspendsTheExactPreviouslyActiveCredential
    (active : ActiveRecoveryCredentialState)
    (replacement : Nat)
    (distinct : replacement ≠ active.activeCredential) :
    let suspended := beginRecoveryCredentialTransition active replacement distinct
    activeCredentialAdmission active active.activeCredential = .active ∧
      suspendedCredentialAdmission suspended active.activeCredential = .suspended ∧
      suspended.identity = active.identity ∧
      suspended.activeStateVersion = active.activeStateVersion ∧
      suspended.activeActivationEpoch = active.activeActivationEpoch := by
  simp [beginRecoveryCredentialTransition, activeCredentialAdmission,
    suspendedCredentialAdmission]

theorem evaluatorAbortIsExactSuspensionSelfLoop
    (suspended : SuspendedRecoveryCredentialState) :
    evaluatorAbortRecovery suspended = suspended := by
  rfl

theorem outputCommitmentRetainsExactCredentialSuspension
    (suspended : SuspendedRecoveryCredentialState) :
    (commitRecoveryOutput suspended).suspension = suspended := by
  rfl

theorem metadataConsumptionRetainsExactCredentialSuspension
    (committed : RecoveryOutputCommittedState) :
    (consumeRecoveryMetadata committed).suspension = committed.suspension := by
  rfl

theorem recipientReleaseRetainsExactCredentialSuspension
    (consumed : RecoveryMetadataConsumedState) :
    (releaseRecoveryRecipients consumed).suspension = consumed.suspension := by
  rfl

theorem workerActivationRetainsExactCredentialSuspension
    (released : RecoveryRecipientsReleasedState) :
    (recordRecoveryWorkerActivation released).suspension = released.suspension := by
  rfl

theorem recoveryPromotionSucceedsExactlyForVerifiedAuthority
    (attempt : RecoveryPromotionAttempt) :
    promoteRecoveryAttempt attempt ≠ none ↔
      ∃ authority, attempt = .verified authority := by
  cases attempt <;> simp [promoteRecoveryAttempt]

theorem promotedCredentialIsTheDistinctReplacement
    (authority : VerifiedRecoveryPromotionAuthority) :
    let promoted := promoteVerifiedRecovery authority
    promoted.activeCredential =
        authority.workerActivated.suspension.replacementCredential ∧
      promoted.activeCredential ≠
        authority.workerActivated.suspension.oldCredential := by
  simp [promoteVerifiedRecovery,
    authority.workerActivated.suspension.replacementIsDistinct]

theorem promotionCreatesExactOldCredentialTombstone
    (authority : VerifiedRecoveryPromotionAuthority) :
    let promoted := promoteVerifiedRecovery authority
    promoted.oldCredentialTombstone.credential =
        authority.workerActivated.suspension.oldCredential ∧
      promoted.oldCredentialTombstone.retiredAtStateVersion =
        authority.workerActivated.suspension.activeStateVersion ∧
      promotedCredentialAdmission promoted
        promoted.oldCredentialTombstone.credential = .tombstoned := by
  have oldIsNotReplacement :
      authority.workerActivated.suspension.oldCredential ≠
        authority.workerActivated.suspension.replacementCredential :=
    Ne.symm authority.workerActivated.suspension.replacementIsDistinct
  simp [promoteVerifiedRecovery, promotedCredentialAdmission, oldIsNotReplacement]

theorem promotionPreservesCompleteIdentityBinding
    (authority : VerifiedRecoveryPromotionAuthority) :
    let before := authority.workerActivated.suspension.identity
    let after := (promoteVerifiedRecovery authority).identity
    after = before := by
  simp [promoteVerifiedRecovery]

theorem promotionStrictlyAdvancesStateVersionAndActivationEpoch
    (authority : VerifiedRecoveryPromotionAuthority) :
    let suspended := authority.workerActivated.suspension
    let promoted := promoteVerifiedRecovery authority
    suspended.activeStateVersion < promoted.activeStateVersion ∧
      suspended.activeActivationEpoch < promoted.activeActivationEpoch := by
  exact ⟨authority.stateVersionAdvances, authority.activationEpochAdvances⟩

theorem promotedStateCannotContainTwoDistinctActiveCredentials
    (authority : VerifiedRecoveryPromotionAuthority)
    (left right : Nat)
    (leftActive : promotedCredentialAdmission
      (promoteVerifiedRecovery authority) left = .active)
    (rightActive : promotedCredentialAdmission
      (promoteVerifiedRecovery authority) right = .active) :
    left = right := by
  have leftEqualsActive :
      left = (promoteVerifiedRecovery authority).activeCredential := by
    by_cases leftIsActive :
      left = (promoteVerifiedRecovery authority).activeCredential
    · exact leftIsActive
    · simp only [promotedCredentialAdmission, leftIsActive, ↓reduceIte] at leftActive
      by_cases leftIsTombstoned :
        left = (promoteVerifiedRecovery authority).oldCredentialTombstone.credential
      · rw [if_pos leftIsTombstoned] at leftActive
        cases leftActive
      · rw [if_neg leftIsTombstoned] at leftActive
        cases leftActive
  have rightEqualsActive :
      right = (promoteVerifiedRecovery authority).activeCredential := by
    by_cases rightIsActive :
      right = (promoteVerifiedRecovery authority).activeCredential
    · exact rightIsActive
    · simp only [promotedCredentialAdmission, rightIsActive, ↓reduceIte] at rightActive
      by_cases rightIsTombstoned :
        right = (promoteVerifiedRecovery authority).oldCredentialTombstone.credential
      · rw [if_pos rightIsTombstoned] at rightActive
        cases rightActive
      · rw [if_neg rightIsTombstoned] at rightActive
        cases rightActive
  exact leftEqualsActive.trans rightEqualsActive.symm

end Ed25519YaoModel
