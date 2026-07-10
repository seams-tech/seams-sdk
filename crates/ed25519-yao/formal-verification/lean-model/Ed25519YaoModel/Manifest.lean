namespace Ed25519YaoModel

/-- Model-local mirror of the two current draft-manifest families. -/
inductive CircuitFamily where
  | activation
  | export
  deriving DecidableEq, Repr

/-- Model-local family discriminator for scaffold rehearsal. -/
def familyByte : CircuitFamily → UInt8
  | .activation => 0x01
  | .export => 0x02

/-- Model-local digest-slot count; no production bridge exists in FV1. -/
def manifestDigestSlotCount : Nat := 7

/-- Model-local metric count; no production bridge exists in FV1. -/
def manifestMetricCount : Nat := 12

theorem familyBytesAreDistinct :
    familyByte .activation ≠ familyByte .export := by
  decide

theorem manifestDigestSlotCountIsSeven : manifestDigestSlotCount = 7 := by
  rfl

theorem manifestMetricCountIsTwelve : manifestMetricCount = 12 := by
  rfl

end Ed25519YaoModel
