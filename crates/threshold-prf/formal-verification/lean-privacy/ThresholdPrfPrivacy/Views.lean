import ThresholdPrfPrivacy.Model

namespace ThresholdPrfPrivacy

def oneServerView
    (state : FullExecutionState) : OneServerState :=
  {
    publicContext := state.publicContext
    leftShare := state.shareOne
    rightShare := state.shareTwo
    yServer := state.yServer
  }

def participantOneView
    (state : FullExecutionState) : TwoServerParticipantState :=
  {
    publicContext := state.publicContext
    ownShare := state.shareOne
    ownPartial := state.partialOne
  }

def participantTwoView
    (state : FullExecutionState) : TwoServerParticipantState :=
  {
    publicContext := state.publicContext
    ownShare := state.shareTwo
    ownPartial := state.partialTwo
  }

def combinerView
    (state : FullExecutionState) : CombinerState :=
  {
    publicContext := state.publicContext
    leftPartial := state.partialOne
    rightPartial := state.partialTwo
    yServer := state.yServer
  }

def publicOutputView
    (state : FullExecutionState) : PublicOutputState :=
  {
    publicContext := state.publicContext
    yServer := state.yServer
  }

theorem oneServerView_has_two_or_more_plaintext_shares
    (state : FullExecutionState) :
    shareCountOfOneServerState (oneServerView state) = .twoOrMore := by
  rfl

theorem participantOneView_has_one_plaintext_share
    (state : FullExecutionState) :
    shareCountOfTwoServerParticipantState (participantOneView state) = .one := by
  rfl

theorem participantTwoView_has_one_plaintext_share
    (state : FullExecutionState) :
    shareCountOfTwoServerParticipantState (participantTwoView state) = .one := by
  rfl

theorem combinerView_has_zero_plaintext_shares
    (state : FullExecutionState) :
    shareCountOfCombinerState (combinerView state) = .zero := by
  rfl

theorem publicOutputView_has_zero_plaintext_shares
    (state : FullExecutionState) :
    shareCountOfPublicOutputState (publicOutputView state) = .zero := by
  rfl

end ThresholdPrfPrivacy
