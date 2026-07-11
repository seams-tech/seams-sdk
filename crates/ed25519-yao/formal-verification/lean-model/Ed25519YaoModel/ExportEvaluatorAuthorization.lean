import Ed25519YaoModel.ExportDelivery

/-!
Construction-independent structural model for role-pinned A/B export
authorization acceptance. Signature unforgeability, trusted key distribution,
clock trust, durable replay, and protocol security remain TCB assumptions.
-/

namespace Ed25519YaoModel

inductive ExportAcceptanceRole where
  | deriverA
  | deriverB
  deriving DecidableEq, Repr

structure ExportAcceptanceCommon where
  request : Nat
  authorization : Nat
  transcript : Nat
  provenancePair : Nat
  storeResolution : Nat
  activeStateVersion : Nat
  registeredIdentity : Nat
  oneUseExecution : Nat
  deriving DecidableEq, Repr

structure VerifiedExportAcceptance (role : ExportAcceptanceRole) where
  authority : Nat
  common : ExportAcceptanceCommon
  checkedAt : Nat
  requestExpiry : Nat
  acceptedBeforeExpiry : checkedAt ≤ requestExpiry

structure VerifiedExportAcceptancePair where
  deriverA : VerifiedExportAcceptance .deriverA
  deriverB : VerifiedExportAcceptance .deriverB
  sameCommon : deriverA.common = deriverB.common
  authoritiesDistinct : deriverA.authority ≠ deriverB.authority
  digest : Nat

structure AcceptedExportEvaluation where
  acceptance : VerifiedExportAcceptancePair
  evaluationCount : Nat := 1

structure ExportOutputCommitted where
  evaluation : AcceptedExportEvaluation
  authorizationState : ExportAuthorizationState := .unconsumed
  acceptancePairDigest : Nat := evaluation.acceptance.digest

structure ExportReleased where
  committed : ExportOutputCommitted
  authorizationState : ExportAuthorizationState := .consumed
  acceptancePairDigest : Nat := committed.acceptancePairDigest

def acceptExportEvaluation
    (pair : VerifiedExportAcceptancePair) : AcceptedExportEvaluation :=
  { acceptance := pair }

def commitAcceptedExport
    (evaluation : AcceptedExportEvaluation) : ExportOutputCommitted :=
  { evaluation }

def releaseAcceptedExport (committed : ExportOutputCommitted) : ExportReleased :=
  { committed }

theorem acceptedExportRequiresDeriverA
    (evaluation : AcceptedExportEvaluation) :
    ∃ acceptance : VerifiedExportAcceptance .deriverA,
      acceptance = evaluation.acceptance.deriverA := by
  exact ⟨evaluation.acceptance.deriverA, rfl⟩

theorem acceptedExportRequiresDeriverB
    (evaluation : AcceptedExportEvaluation) :
    ∃ acceptance : VerifiedExportAcceptance .deriverB,
      acceptance = evaluation.acceptance.deriverB := by
  exact ⟨evaluation.acceptance.deriverB, rfl⟩

theorem exportAcceptanceRolesAreDistinct :
    ExportAcceptanceRole.deriverA ≠ ExportAcceptanceRole.deriverB := by
  decide

theorem acceptedPairUsesDistinctAuthorities
    (pair : VerifiedExportAcceptancePair) :
    pair.deriverA.authority ≠ pair.deriverB.authority := by
  exact pair.authoritiesDistinct

theorem acceptedPairBindsOneRequest
    (pair : VerifiedExportAcceptancePair) :
    pair.deriverA.common.request = pair.deriverB.common.request := by
  exact congrArg ExportAcceptanceCommon.request pair.sameCommon

theorem acceptedPairBindsOneAuthorization
    (pair : VerifiedExportAcceptancePair) :
    pair.deriverA.common.authorization = pair.deriverB.common.authorization := by
  exact congrArg ExportAcceptanceCommon.authorization pair.sameCommon

theorem acceptedPairBindsOneTranscript
    (pair : VerifiedExportAcceptancePair) :
    pair.deriverA.common.transcript = pair.deriverB.common.transcript := by
  exact congrArg ExportAcceptanceCommon.transcript pair.sameCommon

theorem acceptedPairBindsOneProvenancePair
    (pair : VerifiedExportAcceptancePair) :
    pair.deriverA.common.provenancePair = pair.deriverB.common.provenancePair := by
  exact congrArg ExportAcceptanceCommon.provenancePair pair.sameCommon

theorem acceptedPairBindsOneStoreStateAndIdentity
    (pair : VerifiedExportAcceptancePair) :
    pair.deriverA.common.storeResolution = pair.deriverB.common.storeResolution ∧
      pair.deriverA.common.activeStateVersion =
        pair.deriverB.common.activeStateVersion ∧
      pair.deriverA.common.registeredIdentity =
        pair.deriverB.common.registeredIdentity := by
  constructor
  · exact congrArg ExportAcceptanceCommon.storeResolution pair.sameCommon
  · constructor
    · exact congrArg ExportAcceptanceCommon.activeStateVersion pair.sameCommon
    · exact congrArg ExportAcceptanceCommon.registeredIdentity pair.sameCommon

theorem acceptedPairBindsOneUseExecution
    (pair : VerifiedExportAcceptancePair) :
    pair.deriverA.common.oneUseExecution =
      pair.deriverB.common.oneUseExecution := by
  exact congrArg ExportAcceptanceCommon.oneUseExecution pair.sameCommon

theorem acceptedExportRunsExactlyOneEvaluation
    (pair : VerifiedExportAcceptancePair) :
    (acceptExportEvaluation pair).evaluationCount = 1 := by
  rfl

theorem commitmentAndReleasePreserveAcceptanceAndConsumeAuthorization
    (evaluation : AcceptedExportEvaluation) :
    let committed := commitAcceptedExport evaluation
    let released := releaseAcceptedExport committed
    committed.authorizationState = .unconsumed ∧
      released.authorizationState = .consumed ∧
      committed.acceptancePairDigest = evaluation.acceptance.digest ∧
      released.acceptancePairDigest = evaluation.acceptance.digest := by
  simp [commitAcceptedExport, releaseAcceptedExport]

end Ed25519YaoModel
