namespace ThresholdPrfPrivacy

abbrev SecretScalar := Nat
abbrev PublicBytes := Nat

inductive ShareId where
  | one
  | two
  | three
  deriving DecidableEq, Repr

inductive PlaintextShareCount where
  | zero
  | one
  | twoOrMore
  deriving DecidableEq, Repr

structure PublicContext where
  suiteId : PublicBytes
  purpose : PublicBytes
  contextBinding : PublicBytes
  deriving DecidableEq, Repr

structure RootShare where
  id : ShareId
  scalar : SecretScalar
  deriving DecidableEq, Repr

structure PrfPartial where
  id : ShareId
  contextTag : PublicBytes
  compressedPoint : PublicBytes
  deriving DecidableEq, Repr

structure FullExecutionState where
  publicContext : PublicContext
  kOrg : SecretScalar
  shareOne : RootShare
  shareTwo : RootShare
  shareThree : RootShare
  partialOne : PrfPartial
  partialTwo : PrfPartial
  yServer : PublicBytes
  deriving DecidableEq, Repr

structure OneServerState where
  publicContext : PublicContext
  leftShare : RootShare
  rightShare : RootShare
  yServer : PublicBytes
  deriving DecidableEq, Repr

structure TwoServerParticipantState where
  publicContext : PublicContext
  ownShare : RootShare
  ownPartial : PrfPartial
  deriving DecidableEq, Repr

structure CombinerState where
  publicContext : PublicContext
  leftPartial : PrfPartial
  rightPartial : PrfPartial
  yServer : PublicBytes
  deriving DecidableEq, Repr

structure PublicOutputState where
  publicContext : PublicContext
  yServer : PublicBytes
  deriving DecidableEq, Repr

def CanReconstructKOrgFromShareCount (count : PlaintextShareCount) : Prop :=
  count = .twoOrMore

def shareCountOfOneServerState (_state : OneServerState) : PlaintextShareCount :=
  .twoOrMore

def shareCountOfTwoServerParticipantState
    (_state : TwoServerParticipantState) : PlaintextShareCount :=
  .one

def shareCountOfCombinerState (_state : CombinerState) : PlaintextShareCount :=
  .zero

def shareCountOfPublicOutputState (_state : PublicOutputState) : PlaintextShareCount :=
  .zero

def CombinerStateCarriesPlaintextKOrg (_state : CombinerState) : Prop :=
  False

def CombinerStateCarriesPlaintextRootShares (_state : CombinerState) : Prop :=
  False

def PublicOutputCarriesPlaintextKOrg (_state : PublicOutputState) : Prop :=
  False

def PublicOutputCarriesPlaintextRootShares (_state : PublicOutputState) : Prop :=
  False

theorem oneServerState_has_two_or_more_plaintext_shares
    (state : OneServerState) :
    shareCountOfOneServerState state = .twoOrMore := by
  rfl

theorem twoServerParticipantState_has_one_plaintext_share
    (state : TwoServerParticipantState) :
    shareCountOfTwoServerParticipantState state = .one := by
  rfl

theorem combinerState_has_zero_plaintext_shares
    (state : CombinerState) :
    shareCountOfCombinerState state = .zero := by
  rfl

theorem publicOutputState_has_zero_plaintext_shares
    (state : PublicOutputState) :
    shareCountOfPublicOutputState state = .zero := by
  rfl

end ThresholdPrfPrivacy
