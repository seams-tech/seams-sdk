import ThresholdPrfPrivacy.Views

namespace ThresholdPrfPrivacy

def OneServerModeCanReconstructKOrg : Prop :=
  ∀ (state : FullExecutionState),
    CanReconstructKOrgFromShareCount
      (shareCountOfOneServerState (oneServerView state))

def ParticipantOneCannotReconstructKOrg : Prop :=
  ∀ (state : FullExecutionState),
    ¬ CanReconstructKOrgFromShareCount
      (shareCountOfTwoServerParticipantState (participantOneView state))

def ParticipantTwoCannotReconstructKOrg : Prop :=
  ∀ (state : FullExecutionState),
    ¬ CanReconstructKOrgFromShareCount
      (shareCountOfTwoServerParticipantState (participantTwoView state))

def CombinerCannotReconstructKOrg : Prop :=
  ∀ (state : FullExecutionState),
    ¬ CanReconstructKOrgFromShareCount
      (shareCountOfCombinerState (combinerView state))

def PublicOutputCannotReconstructKOrg : Prop :=
  ∀ (state : FullExecutionState),
    ¬ CanReconstructKOrgFromShareCount
      (shareCountOfPublicOutputState (publicOutputView state))

def CombinerVisibleStateExcludesPlaintextRootAndShares : Prop :=
  ∀ (state : FullExecutionState),
    ¬ CombinerStateCarriesPlaintextKOrg (combinerView state) ∧
    ¬ CombinerStateCarriesPlaintextRootShares (combinerView state)

def PublicOutputExcludesPlaintextRootAndShares : Prop :=
  ∀ (state : FullExecutionState),
    ¬ PublicOutputCarriesPlaintextKOrg (publicOutputView state) ∧
    ¬ PublicOutputCarriesPlaintextRootShares (publicOutputView state)

def TwoServerParticipantCannotReconstructKOrg : Prop :=
  ParticipantOneCannotReconstructKOrg ∧ ParticipantTwoCannotReconstructKOrg

def TwoServerPrivacyStructuralGoal : Prop :=
  TwoServerParticipantCannotReconstructKOrg ∧
  CombinerCannotReconstructKOrg ∧
  PublicOutputCannotReconstructKOrg ∧
  CombinerVisibleStateExcludesPlaintextRootAndShares ∧
  PublicOutputExcludesPlaintextRootAndShares

def OneServerModeIsNotPrivacyBoundary : Prop :=
  OneServerModeCanReconstructKOrg

theorem oneServerModeCanReconstructKOrg_proved :
    OneServerModeCanReconstructKOrg := by
  intro state
  rfl

theorem participantOneCannotReconstructKOrg_proved :
    ParticipantOneCannotReconstructKOrg := by
  intro state h
  cases h

theorem participantTwoCannotReconstructKOrg_proved :
    ParticipantTwoCannotReconstructKOrg := by
  intro state h
  cases h

theorem combinerCannotReconstructKOrg_proved :
    CombinerCannotReconstructKOrg := by
  intro state h
  cases h

theorem publicOutputCannotReconstructKOrg_proved :
    PublicOutputCannotReconstructKOrg := by
  intro state h
  cases h

theorem combinerVisibleStateExcludesPlaintextRootAndShares_proved :
    CombinerVisibleStateExcludesPlaintextRootAndShares := by
  intro state
  constructor <;> intro h <;> exact h

theorem publicOutputExcludesPlaintextRootAndShares_proved :
    PublicOutputExcludesPlaintextRootAndShares := by
  intro state
  constructor <;> intro h <;> exact h

theorem twoServerParticipantCannotReconstructKOrg_proved :
    TwoServerParticipantCannotReconstructKOrg := by
  constructor
  · exact participantOneCannotReconstructKOrg_proved
  · exact participantTwoCannotReconstructKOrg_proved

theorem twoServerPrivacyStructuralGoal_proved :
    TwoServerPrivacyStructuralGoal := by
  constructor
  · exact twoServerParticipantCannotReconstructKOrg_proved
  · constructor
    · exact combinerCannotReconstructKOrg_proved
    · constructor
      · exact publicOutputCannotReconstructKOrg_proved
      · constructor
        · exact combinerVisibleStateExcludesPlaintextRootAndShares_proved
        · exact publicOutputExcludesPlaintextRootAndShares_proved

theorem oneServerModeIsNotPrivacyBoundary_proved :
    OneServerModeIsNotPrivacyBoundary := by
  exact oneServerModeCanReconstructKOrg_proved

end ThresholdPrfPrivacy
