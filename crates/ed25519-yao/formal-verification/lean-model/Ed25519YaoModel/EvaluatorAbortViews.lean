import Ed25519YaoModel.UniformAbort

namespace Ed25519YaoModel

inductive EvaluatorAbortPreStateClass where
  | unregistered
  | credentialSuspended
  | registered
  deriving DecidableEq, Repr

inductive EvaluatorAbortTransition where
  | selfLoop
  deriving DecidableEq, Repr

def evaluatorRequestKinds : List RequestKind :=
  [.registration, .recovery, .refresh, .export]

def evaluatorAbortParties : List Party :=
  [.deriverA, .deriverB, .client, .signingWorker, .router, .observer, .diagnostics]

def evaluatorAbortPreStateClass : RequestKind → Option EvaluatorAbortPreStateClass
  | .registration => some .unregistered
  | .recovery => some .credentialSuspended
  | .refresh => some .registered
  | .export => some .registered
  | .activation => none

def evaluatorAbortTransition (_ : RequestKind) : EvaluatorAbortTransition := .selfLoop

def evaluatorAbortViewFields (_ : Party) : List UniformAbortField := uniformAbortFields

theorem evaluatorAbortHasExactlyFourRequestKinds :
    evaluatorRequestKinds = [.registration, .recovery, .refresh, .export] := by
  rfl

theorem activationHasNoEvaluatorAbortProjection :
    evaluatorAbortPreStateClass .activation = none := by
  rfl

theorem registrationRetainsUnregisteredState :
    evaluatorAbortPreStateClass .registration = some .unregistered := by
  rfl

theorem evaluatorBranchesRetainRequiredStateClass :
    evaluatorAbortPreStateClass .recovery = some .credentialSuspended ∧
      evaluatorAbortPreStateClass .refresh = some .registered ∧
      evaluatorAbortPreStateClass .export = some .registered := by
  decide

theorem everyEvaluatorAbortIsAStateSelfLoop (request : RequestKind) :
    evaluatorAbortTransition request = .selfLoop := by
  cases request <;> rfl

theorem evaluatorAbortHasExactlySevenPartyViews :
    evaluatorAbortParties =
      [.deriverA, .deriverB, .client, .signingWorker, .router, .observer, .diagnostics] := by
  rfl

theorem everyEvaluatorAbortPartySeesOnlyUniformAbortFields (party : Party) :
    evaluatorAbortViewFields party =
      [.requestKind, .publicTranscriptDigest, .publicFailureCode, .terminal] := by
  cases party <;> rfl

end Ed25519YaoModel
