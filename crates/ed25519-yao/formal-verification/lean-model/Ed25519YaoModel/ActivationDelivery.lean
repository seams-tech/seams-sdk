import Ed25519YaoModel.PartyViews

/-!
Host-only structural activation-delivery model. It establishes authorization,
custody, capability, identity, and zero-reevaluation relations without making a
production opener, transport, durability, or P0-P3 security claim.
-/

namespace Ed25519YaoModel

/-- Host-only activation authorization states. -/
inductive ActivationAuthorizationState where
  | notIssued
  | unconsumed
  | consumed
  deriving DecidableEq, Repr

/-- Construction-independent host stages from output commitment through activation. -/
inductive ActivationDeliveryStage where
  | outputCommitted
  | controlAdmitted
  | metadataConsumed
  | deliveryUncertain
  | recipientsReleased
  | redelivered
  | signingWorkerActivated
  deriving DecidableEq, Repr

/-- Exact public identity retained across activation recipient delivery. -/
structure ActivationDeliveryIdentity where
  packageSetDigest : Nat
  outputCommittedReceiptDigest : Nat
  activationTranscriptDigest : Nat
  deriving DecidableEq, Repr

/-- The exact four same-evaluation scalar shares retained by metadata consumption. -/
structure ActivationRetainedShares where
  deriverAClient : Nat
  deriverBClient : Nat
  deriverASigningWorker : Nat
  deriverBSigningWorker : Nat
  deriving DecidableEq, Repr

/-- Metadata-consumed custody before the atomic recipient release. -/
structure HostOnlyActivationMetadataCustody where
  identity : ActivationDeliveryIdentity
  retainedShares : ActivationRetainedShares
  deriving DecidableEq, Repr

/-- Client-only capability produced by atomic release. -/
structure HostOnlyActivationClientReleaseCapability where
  identity : ActivationDeliveryIdentity
  xClientBase : Nat
  deliveryEvidence : Nat
  deriving DecidableEq, Repr

/-- SigningWorker-only authority required by the worker activation transition. -/
structure HostOnlySigningWorkerActivationAuthority where
  identity : ActivationDeliveryIdentity
  retainedShares : ActivationRetainedShares
  deliveryEvidence : Nat
  deriving DecidableEq, Repr

/-- Atomic result containing two statically disjoint recipient capabilities. -/
structure HostOnlyActivationRecipientsReleased where
  client : HostOnlyActivationClientReleaseCapability
  signingWorker : HostOnlySigningWorkerActivationAuthority
  deriving DecidableEq, Repr

inductive ActivationRecipientCapabilityKind where
  | clientScalarRelease
  | signingWorkerActivationAuthority
  deriving DecidableEq, Repr

/-- The worker state produced only from a SigningWorker release authority. -/
structure HostOnlyActivatedSigningWorker where
  identity : ActivationDeliveryIdentity
  xServerBase : Nat
  deriving DecidableEq, Repr

structure ActivationDeliveryPrivateWork where
  yaoEvaluations : Nat
  deriverAInvocations : Nat
  deriverBInvocations : Nat
  contributionDerivations : Nat
  outputShareSamples : Nat
  deriving DecidableEq, Repr

inductive ActivationDeliveryOperation where
  | deliveryUncertainty
  | recipientRelease
  | redelivery
  deriving DecidableEq, Repr

def activationAuthorizationState :
    ActivationDeliveryStage → ActivationAuthorizationState
  | .outputCommitted => .notIssued
  | .controlAdmitted => .unconsumed
  | .metadataConsumed => .consumed
  | .deliveryUncertain => .consumed
  | .recipientsReleased => .consumed
  | .redelivered => .consumed
  | .signingWorkerActivated => .consumed

def markActivationDeliveryUncertain
    (custody : HostOnlyActivationMetadataCustody) :
    HostOnlyActivationMetadataCustody :=
  custody

def releaseActivationRecipients
    (custody : HostOnlyActivationMetadataCustody)
    (clientDeliveryEvidence signingWorkerDeliveryEvidence : Nat) :
    HostOnlyActivationRecipientsReleased :=
  {
    client := {
      identity := custody.identity
      xClientBase := custody.retainedShares.deriverAClient +
        custody.retainedShares.deriverBClient
      deliveryEvidence := clientDeliveryEvidence
    }
    signingWorker := {
      identity := custody.identity
      retainedShares := custody.retainedShares
      deliveryEvidence := signingWorkerDeliveryEvidence
    }
  }

def redeliverActivationRecipients
    (released : HostOnlyActivationRecipientsReleased) :
    HostOnlyActivationRecipientsReleased :=
  released

def clientCapabilityKind
    (_ : HostOnlyActivationClientReleaseCapability) :
    ActivationRecipientCapabilityKind :=
  .clientScalarRelease

def signingWorkerCapabilityKind
    (_ : HostOnlySigningWorkerActivationAuthority) :
    ActivationRecipientCapabilityKind :=
  .signingWorkerActivationAuthority

def activateSigningWorker
    (authority : HostOnlySigningWorkerActivationAuthority) :
    HostOnlyActivatedSigningWorker :=
  {
    identity := authority.identity
    xServerBase := authority.retainedShares.deriverASigningWorker +
      authority.retainedShares.deriverBSigningWorker
  }

def privateWorkForActivationDelivery
    (_ : ActivationDeliveryOperation) : ActivationDeliveryPrivateWork :=
  ⟨0, 0, 0, 0, 0⟩

theorem outputCommitmentHasNoIssuedActivationAuthorization :
    activationAuthorizationState .outputCommitted = .notIssued := by
  rfl

theorem admittedActivationControlHasUnconsumedAuthorization :
    activationAuthorizationState .controlAdmitted = .unconsumed := by
  rfl

theorem metadataConsumptionConsumesActivationAuthorization :
    activationAuthorizationState .metadataConsumed = .consumed := by
  rfl

theorem everyPostConsumptionStageRetainsConsumedAuthorization :
    activationAuthorizationState .deliveryUncertain = .consumed ∧
      activationAuthorizationState .recipientsReleased = .consumed ∧
      activationAuthorizationState .redelivered = .consumed ∧
      activationAuthorizationState .signingWorkerActivated = .consumed := by
  decide

theorem deliveryUncertaintyPreservesExactActivationCustody
    (custody : HostOnlyActivationMetadataCustody) :
    markActivationDeliveryUncertain custody = custody := by
  rfl

theorem activationRedeliveryIsExactReleasedStateSelfLoop
    (released : HostOnlyActivationRecipientsReleased) :
    redeliverActivationRecipients released = released := by
  rfl

theorem atomicReleaseReturnsDistinctRecipientCapabilities
    (custody : HostOnlyActivationMetadataCustody)
    (clientEvidence workerEvidence : Nat) :
    let released := releaseActivationRecipients custody clientEvidence workerEvidence
    clientCapabilityKind released.client = .clientScalarRelease ∧
      signingWorkerCapabilityKind released.signingWorker =
        .signingWorkerActivationAuthority ∧
      clientCapabilityKind released.client ≠
        signingWorkerCapabilityKind released.signingWorker := by
  simp [clientCapabilityKind, signingWorkerCapabilityKind]

theorem atomicReleaseRetainsExactCustodyAndReconstructsClientScalar
    (custody : HostOnlyActivationMetadataCustody)
    (clientEvidence workerEvidence : Nat) :
    let released := releaseActivationRecipients custody clientEvidence workerEvidence
    released.client.identity = custody.identity ∧
      released.signingWorker.identity = custody.identity ∧
      released.signingWorker.retainedShares = custody.retainedShares ∧
      released.client.xClientBase = custody.retainedShares.deriverAClient +
        custody.retainedShares.deriverBClient := by
  simp [releaseActivationRecipients]

theorem typedWorkerActivationPreservesReleasedAuthorityIdentity
    (authority : HostOnlySigningWorkerActivationAuthority) :
    let activated := activateSigningWorker authority
    activated.identity = authority.identity ∧
      activated.xServerBase = authority.retainedShares.deriverASigningWorker +
        authority.retainedShares.deriverBSigningWorker := by
  simp [activateSigningWorker]

theorem uncertaintyReleaseAndRedeliveryPerformZeroPrivateWork :
    privateWorkForActivationDelivery .deliveryUncertainty = ⟨0, 0, 0, 0, 0⟩ ∧
      privateWorkForActivationDelivery .recipientRelease = ⟨0, 0, 0, 0, 0⟩ ∧
      privateWorkForActivationDelivery .redelivery = ⟨0, 0, 0, 0, 0⟩ := by
  decide

end Ed25519YaoModel
