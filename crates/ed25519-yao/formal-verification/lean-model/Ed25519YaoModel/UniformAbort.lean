import Ed25519YaoModel.PartyViews

namespace Ed25519YaoModel

inductive UniformAbortField where
  | requestKind
  | publicTranscriptDigest
  | publicFailureCode
  | terminal
  | requestContextDigest
  | authorizationDigest
  | deriverBlame
  | privatePayload
  deriving DecidableEq, Repr

inductive UniformAbortCode where
  | rejected
  deriving DecidableEq, Repr

inductive UniformAbortTerminal where
  | aborted
  deriving DecidableEq, Repr

def uniformAbortFields : List UniformAbortField :=
  [.requestKind, .publicTranscriptDigest, .publicFailureCode, .terminal]

def uniformAbortCode (_ : RequestKind) : UniformAbortCode := .rejected

def uniformAbortTerminal (_ : RequestKind) : UniformAbortTerminal := .aborted

theorem uniformAbortHasExactlyFourPublicFields :
    uniformAbortFields =
      [.requestKind, .publicTranscriptDigest, .publicFailureCode, .terminal] := by
  rfl

theorem uniformAbortExcludesRequestContextAuthorizationBlameAndPrivatePayload :
    .requestContextDigest ∉ uniformAbortFields ∧
      .authorizationDigest ∉ uniformAbortFields ∧
      .deriverBlame ∉ uniformAbortFields ∧
      .privatePayload ∉ uniformAbortFields := by
  simp [uniformAbortFields]

theorem everyRequestKindUsesOneRedactedFailureCode (request : RequestKind) :
    uniformAbortCode request = .rejected := by
  cases request <;> rfl

theorem everyRequestKindUsesOneAbortedTerminal (request : RequestKind) :
    uniformAbortTerminal request = .aborted := by
  cases request <;> rfl

end Ed25519YaoModel
