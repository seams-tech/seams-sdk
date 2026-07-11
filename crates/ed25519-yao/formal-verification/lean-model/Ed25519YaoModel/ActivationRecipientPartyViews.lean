import Ed25519YaoModel.ActivationDelivery

/-!
Host-only structural recipient-custody projections after activation release.
This module models no frames, delivery acknowledgement, durable state,
noninterference, or P0-P3 security property.
-/

namespace Ed25519YaoModel

inductive ActivationOrigin where
  | registration
  | recovery
  | refresh
  deriving DecidableEq, Repr

/-- The exact closed stage family owned by this companion. -/
inductive ActivationRecipientPartyViewStage where
  | recipientsReleased
  | signingWorkerActivated
  deriving DecidableEq, Repr

/-- Earlier lifecycle stages used only to state recipient-view emptiness. -/
inductive ActivationRecipientPreReleaseStage where
  | outputCommitted
  | controlAdmitted
  | metadataConsumed
  | deliveryUncertain
  deriving DecidableEq, Repr

structure ActivationRecipientCommonView where
  origin : ActivationOrigin
  identity : ActivationDeliveryIdentity
  stage : ActivationRecipientPartyViewStage
  deriving DecidableEq, Repr

structure ActivationClientScalarCustodyView where
  identity : ActivationDeliveryIdentity
  xClientBase : Nat
  deliveryEvidence : Nat
  deriving DecidableEq, Repr

/-- Opaque worker authority projection; retained A/B shares are absent. -/
structure ActivationSigningWorkerAuthorityCustodyView where
  identity : ActivationDeliveryIdentity
  deliveryEvidence : Nat
  deriving DecidableEq, Repr

/-- Receipt-verified worker projection with no activated-scalar field. -/
structure SealedSigningWorkerActivationCustodyView where
  identity : ActivationDeliveryIdentity
  verifiedReceiptBinding : Nat
  deriving DecidableEq, Repr

inductive ActivationRecipientPrivateExtension where
  | empty
  | clientScalar (view : ActivationClientScalarCustodyView)
  | signingWorkerAuthority (view : ActivationSigningWorkerAuthorityCustodyView)
  | sealedSigningWorkerActivation (view : SealedSigningWorkerActivationCustodyView)
  deriving DecidableEq, Repr

structure ActivationRecipientPartyView where
  common : ActivationRecipientCommonView
  extension : ActivationRecipientPrivateExtension
  deriving DecidableEq, Repr

/-- Canonical activated aggregate retaining the exact released Client capability. -/
structure HostOnlyActivationRecipientActivatedViewState where
  origin : ActivationOrigin
  client : HostOnlyActivationClientReleaseCapability
  signingWorker : HostOnlyActivatedSigningWorker
  verifiedReceiptBinding : Nat
  deriving DecidableEq, Repr

inductive ActivationRecipientPrivateValueClass where
  | clientScalar
  | signingWorkerReleaseAuthority
  | sealedSigningWorkerActivation
  | activatedSigningWorkerScalar
  | deriverAClientShare
  | deriverBClientShare
  | deriverASigningWorkerShare
  | deriverBSigningWorkerShare
  deriving DecidableEq, Repr

def activationRecipientPartyViewStages : List ActivationRecipientPartyViewStage :=
  [.recipientsReleased, .signingWorkerActivated]

def activationRecipientParties : List Party :=
  [.deriverA, .deriverB, .client, .signingWorker, .router, .observer, .diagnostics]

def preReleaseActivationRecipientExtension
    (_ : Party) (_ : ActivationRecipientPreReleaseStage) :
    ActivationRecipientPrivateExtension :=
  .empty

def releasedActivationRecipientExtension
    (released : HostOnlyActivationRecipientsReleased) :
    Party → ActivationRecipientPrivateExtension
  | .client => .clientScalar {
      identity := released.client.identity
      xClientBase := released.client.xClientBase
      deliveryEvidence := released.client.deliveryEvidence
    }
  | .signingWorker => .signingWorkerAuthority {
      identity := released.signingWorker.identity
      deliveryEvidence := released.signingWorker.deliveryEvidence
    }
  | _ => .empty

def releasedActivationRecipientPartyView
    (origin : ActivationOrigin)
    (released : HostOnlyActivationRecipientsReleased)
    (party : Party) : ActivationRecipientPartyView :=
  {
    common := {
      origin
      identity := released.client.identity
      stage := .recipientsReleased
    }
    extension := releasedActivationRecipientExtension released party
  }

def activateReleasedRecipientViewState
    (origin : ActivationOrigin)
    (released : HostOnlyActivationRecipientsReleased)
    (verifiedReceiptBinding : Nat) :
    HostOnlyActivationRecipientActivatedViewState :=
  {
    origin
    client := released.client
    signingWorker := activateSigningWorker released.signingWorker
    verifiedReceiptBinding
  }

def activatedActivationRecipientExtension
    (activated : HostOnlyActivationRecipientActivatedViewState) :
    Party → ActivationRecipientPrivateExtension
  | .client => .clientScalar {
      identity := activated.client.identity
      xClientBase := activated.client.xClientBase
      deliveryEvidence := activated.client.deliveryEvidence
    }
  | .signingWorker => .sealedSigningWorkerActivation {
      identity := activated.signingWorker.identity
      verifiedReceiptBinding := activated.verifiedReceiptBinding
    }
  | _ => .empty

def activatedActivationRecipientPartyView
    (activated : HostOnlyActivationRecipientActivatedViewState)
    (party : Party) : ActivationRecipientPartyView :=
  {
    common := {
      origin := activated.origin
      identity := activated.client.identity
      stage := .signingWorkerActivated
    }
    extension := activatedActivationRecipientExtension activated party
  }

def extensionMayExpose
    (extension : ActivationRecipientPrivateExtension) :
    ActivationRecipientPrivateValueClass → Bool
  | .clientScalar => match extension with
      | .clientScalar _ => true
      | _ => false
  | .signingWorkerReleaseAuthority => match extension with
      | .signingWorkerAuthority _ => true
      | _ => false
  | .sealedSigningWorkerActivation => match extension with
      | .sealedSigningWorkerActivation _ => true
      | _ => false
  | _ => false

theorem activationRecipientStagesAndPartiesAreExactlyClosed :
    activationRecipientPartyViewStages =
      [.recipientsReleased, .signingWorkerActivated] ∧
    activationRecipientParties =
      [.deriverA, .deriverB, .client, .signingWorker, .router, .observer,
        .diagnostics] := by
  simp [activationRecipientPartyViewStages, activationRecipientParties]

theorem everyPreReleaseActivationRecipientExtensionIsEmpty
    (party : Party) (stage : ActivationRecipientPreReleaseStage) :
    preReleaseActivationRecipientExtension party stage = .empty := by
  rfl

theorem releasedClientGetsExactlyScalarCapability
    (released : HostOnlyActivationRecipientsReleased) :
    releasedActivationRecipientExtension released .client = .clientScalar {
      identity := released.client.identity
      xClientBase := released.client.xClientBase
      deliveryEvidence := released.client.deliveryEvidence
    } := by
  rfl

theorem releasedSigningWorkerGetsExactlyOpaqueAuthority
    (released : HostOnlyActivationRecipientsReleased) :
    releasedActivationRecipientExtension released .signingWorker =
      .signingWorkerAuthority {
        identity := released.signingWorker.identity
        deliveryEvidence := released.signingWorker.deliveryEvidence
      } := by
  rfl

theorem releasedDeriverAndInfrastructureExtensionsAreEmpty
    (released : HostOnlyActivationRecipientsReleased) :
    releasedActivationRecipientExtension released .deriverA = .empty ∧
      releasedActivationRecipientExtension released .deriverB = .empty ∧
      releasedActivationRecipientExtension released .router = .empty ∧
      releasedActivationRecipientExtension released .observer = .empty ∧
      releasedActivationRecipientExtension released .diagnostics = .empty := by
  simp [releasedActivationRecipientExtension]

theorem noReleasedPartyGetsBothRecipientCapabilities
    (released : HostOnlyActivationRecipientsReleased) (party : Party) :
    ¬(extensionMayExpose
        (releasedActivationRecipientExtension released party) .clientScalar = true ∧
      extensionMayExpose
        (releasedActivationRecipientExtension released party)
          .signingWorkerReleaseAuthority = true) := by
  cases party <;> simp [releasedActivationRecipientExtension, extensionMayExpose]

theorem activatedClientRetainsExactReleasedCapability
    (origin : ActivationOrigin)
    (released : HostOnlyActivationRecipientsReleased)
    (receiptBinding : Nat) :
    let activated := activateReleasedRecipientViewState origin released receiptBinding
    activatedActivationRecipientExtension activated .client = .clientScalar {
      identity := released.client.identity
      xClientBase := released.client.xClientBase
      deliveryEvidence := released.client.deliveryEvidence
    } := by
  rfl

theorem activatedSigningWorkerProjectionIsSealed
    (origin : ActivationOrigin)
    (released : HostOnlyActivationRecipientsReleased)
    (receiptBinding : Nat) :
    let activated := activateReleasedRecipientViewState origin released receiptBinding
    let extension := activatedActivationRecipientExtension activated .signingWorker
    extension = .sealedSigningWorkerActivation {
      identity := released.signingWorker.identity
      verifiedReceiptBinding := receiptBinding
    } ∧
      extensionMayExpose extension .activatedSigningWorkerScalar = false := by
  simp [activateReleasedRecipientViewState, activateSigningWorker,
    activatedActivationRecipientExtension, extensionMayExpose]

theorem activatedDeriverAndInfrastructureExtensionsAreEmpty
    (activated : HostOnlyActivationRecipientActivatedViewState) :
    activatedActivationRecipientExtension activated .deriverA = .empty ∧
      activatedActivationRecipientExtension activated .deriverB = .empty ∧
      activatedActivationRecipientExtension activated .router = .empty ∧
      activatedActivationRecipientExtension activated .observer = .empty ∧
      activatedActivationRecipientExtension activated .diagnostics = .empty := by
  simp [activatedActivationRecipientExtension]

theorem canonicalReleaseAndActivationViewsShareOneIdentity
    (origin : ActivationOrigin)
    (custody : HostOnlyActivationMetadataCustody)
    (clientEvidence workerEvidence receiptBinding : Nat)
    (party : Party) :
    let released := releaseActivationRecipients custody clientEvidence workerEvidence
    let activated := activateReleasedRecipientViewState origin released receiptBinding
    (releasedActivationRecipientPartyView origin released party).common.identity =
        custody.identity ∧
      (activatedActivationRecipientPartyView activated party).common.identity =
        custody.identity ∧
      released.client.identity = released.signingWorker.identity ∧
      activated.client.identity = activated.signingWorker.identity := by
  simp [releaseActivationRecipients, activateReleasedRecipientViewState,
    activateSigningWorker, releasedActivationRecipientPartyView,
    activatedActivationRecipientPartyView]

theorem redeliveryPreservesEveryReleasedRecipientPartyView
    (origin : ActivationOrigin)
    (released : HostOnlyActivationRecipientsReleased)
    (party : Party) :
    releasedActivationRecipientPartyView origin
        (redeliverActivationRecipients released) party =
      releasedActivationRecipientPartyView origin released party := by
  rfl

theorem recipientPartyViewExtensionsNeverExposeRetainedDeriverShares
    (extension : ActivationRecipientPrivateExtension) :
    extensionMayExpose extension .deriverAClientShare = false ∧
      extensionMayExpose extension .deriverBClientShare = false ∧
      extensionMayExpose extension .deriverASigningWorkerShare = false ∧
      extensionMayExpose extension .deriverBSigningWorkerShare = false := by
  cases extension <;> simp [extensionMayExpose]

end Ed25519YaoModel
