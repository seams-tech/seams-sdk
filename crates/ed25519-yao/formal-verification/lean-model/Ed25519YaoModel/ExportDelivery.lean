import Ed25519YaoModel.PartyViews

namespace Ed25519YaoModel

inductive ExportAuthorizationState where
  | unconsumed
  | consumed
  deriving DecidableEq, Repr

inductive ExportDeliveryStage where
  | outputCommitted
  | deliveryUncertain
  | released
  deriving DecidableEq, Repr

structure ExportDeliveryIdentity where
  packageSet : Nat
  outputCommittedReceipt : Nat
  releasedReceipt : Nat
  deriving DecidableEq, Repr

def exportAuthorizationState : ExportDeliveryStage → ExportAuthorizationState
  | .outputCommitted => .unconsumed
  | .deliveryUncertain => .unconsumed
  | .released => .consumed

def markDeliveryUncertain
    (identity : ExportDeliveryIdentity) : ExportDeliveryIdentity :=
  identity

def redeliver (identity : ExportDeliveryIdentity) : ExportDeliveryIdentity :=
  identity

def exportRecipientMayObserveSeed : Party → Bool
  | .client => true
  | _ => false

def privateEvaluationWorkForDelivery : ExportDeliveryStage → Nat
  | .outputCommitted => 0
  | .deliveryUncertain => 0
  | .released => 0

theorem outputCommitmentKeepsAuthorizationUnconsumed :
    exportAuthorizationState .outputCommitted = .unconsumed := by
  rfl

theorem uncertaintyKeepsAuthorizationUnconsumed :
    exportAuthorizationState .deliveryUncertain = .unconsumed := by
  rfl

theorem releaseConsumesAuthorization :
    exportAuthorizationState .released = .consumed := by
  rfl

theorem uncertaintyPreservesExactIdentity (identity : ExportDeliveryIdentity) :
    markDeliveryUncertain identity = identity := by
  rfl

theorem redeliveryIsExactIdentitySelfLoop (identity : ExportDeliveryIdentity) :
    redeliver identity = identity := by
  rfl

theorem exportSeedIsClientOnly
    (party : Party) (visible : exportRecipientMayObserveSeed party = true) :
    party = .client := by
  cases party <;> simp_all [exportRecipientMayObserveSeed]

theorem deliveryStagesPerformZeroPrivateEvaluationWork
    (stage : ExportDeliveryStage) :
    privateEvaluationWorkForDelivery stage = 0 := by
  cases stage <;> rfl

end Ed25519YaoModel
