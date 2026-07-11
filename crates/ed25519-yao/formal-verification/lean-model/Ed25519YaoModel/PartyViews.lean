namespace Ed25519YaoModel

inductive Party where
  | client
  | router
  | deriverA
  | deriverB
  | signingWorker
  | observer
  | diagnostics
  deriving DecidableEq, Repr

inductive RequestKind where
  | registration
  | activation
  | recovery
  | refresh
  | export
  deriving DecidableEq, Repr

inductive ValueClass where
  | publicMetadata
  | deriverAClientScalarShare
  | deriverASigningWorkerScalarShare
  | deriverBClientScalarShare
  | deriverBSigningWorkerScalarShare
  | clientScalarOutput
  | signingWorkerScalarOutput
  | deriverAExportSeedShare
  | deriverBExportSeedShare
  | exportClientSeed
  | joinedScalar
  | joinedSeed
  deriving DecidableEq, Repr

inductive Stage where
  | registrationPackagePrepared
  | activationMetadataConsumed
  | recoveryPackagePrepared
  | refreshPackagePrepared
  | exportReleased
  deriving DecidableEq, Repr

def mayObserve : Party → RequestKind → Stage → ValueClass → Bool
  | _, .registration, .registrationPackagePrepared, .publicMetadata => true
  | _, .activation, .activationMetadataConsumed, .publicMetadata => true
  | _, .recovery, .recoveryPackagePrepared, .publicMetadata => true
  | _, .refresh, .refreshPackagePrepared, .publicMetadata => true
  | _, .export, .exportReleased, .publicMetadata => true
  | .deriverA, .registration, .registrationPackagePrepared,
      .deriverAClientScalarShare => true
  | .deriverA, .registration, .registrationPackagePrepared,
      .deriverASigningWorkerScalarShare => true
  | .deriverA, .recovery, .recoveryPackagePrepared,
      .deriverAClientScalarShare => true
  | .deriverA, .recovery, .recoveryPackagePrepared,
      .deriverASigningWorkerScalarShare => true
  | .deriverA, .refresh, .refreshPackagePrepared,
      .deriverAClientScalarShare => true
  | .deriverA, .refresh, .refreshPackagePrepared,
      .deriverASigningWorkerScalarShare => true
  | .deriverB, .registration, .registrationPackagePrepared,
      .deriverBClientScalarShare => true
  | .deriverB, .registration, .registrationPackagePrepared,
      .deriverBSigningWorkerScalarShare => true
  | .deriverB, .recovery, .recoveryPackagePrepared,
      .deriverBClientScalarShare => true
  | .deriverB, .recovery, .recoveryPackagePrepared,
      .deriverBSigningWorkerScalarShare => true
  | .deriverB, .refresh, .refreshPackagePrepared,
      .deriverBClientScalarShare => true
  | .deriverB, .refresh, .refreshPackagePrepared,
      .deriverBSigningWorkerScalarShare => true
  | .deriverA, .export, .exportReleased, .deriverAExportSeedShare => true
  | .deriverB, .export, .exportReleased, .deriverBExportSeedShare => true
  | .client, .export, .exportReleased, .exportClientSeed => true
  | _, _, _, _ => false

/-- Recipient-private outputs created by evaluation and committed for delivery. -/
def newRecipientPrivateOutputs : RequestKind → Stage → List ValueClass
  | .registration, .registrationPackagePrepared =>
      [.clientScalarOutput, .signingWorkerScalarOutput]
  | .recovery, .recoveryPackagePrepared =>
      [.clientScalarOutput, .signingWorkerScalarOutput]
  | .refresh, .refreshPackagePrepared =>
      [.clientScalarOutput, .signingWorkerScalarOutput]
  | .export, .exportReleased => [.exportClientSeed]
  | _, _ => []

def staticallyExposedDerivers : Party → List Party
  | .deriverA => [.deriverA]
  | .deriverB => [.deriverB]
  | _ => []

theorem deriverAExcludesBAndJoinedValues (request : RequestKind) (stage : Stage) :
    mayObserve .deriverA request stage .deriverBClientScalarShare = false ∧
      mayObserve .deriverA request stage .deriverBSigningWorkerScalarShare = false ∧
      mayObserve .deriverA request stage .deriverBExportSeedShare = false ∧
      mayObserve .deriverA request stage .joinedScalar = false ∧
      mayObserve .deriverA request stage .joinedSeed = false := by
  cases request <;> cases stage <;> simp [mayObserve]

theorem deriverBExcludesAAndJoinedValues (request : RequestKind) (stage : Stage) :
    mayObserve .deriverB request stage .deriverAClientScalarShare = false ∧
      mayObserve .deriverB request stage .deriverASigningWorkerScalarShare = false ∧
      mayObserve .deriverB request stage .deriverAExportSeedShare = false ∧
      mayObserve .deriverB request stage .joinedScalar = false ∧
      mayObserve .deriverB request stage .joinedSeed = false := by
  cases request <;> cases stage <;> simp [mayObserve]

theorem routerViewIsPublicOnly
    (request : RequestKind) (stage : Stage) (value : ValueClass)
    (visible : mayObserve .router request stage value = true) :
    value = .publicMetadata := by
  cases request <;> cases stage <;> cases value <;> simp_all [mayObserve]

theorem observerViewIsPublicOnly
    (request : RequestKind) (stage : Stage) (value : ValueClass)
    (visible : mayObserve .observer request stage value = true) :
    value = .publicMetadata := by
  cases request <;> cases stage <;> cases value <;> simp_all [mayObserve]

theorem diagnosticsViewIsPublicOnly
    (request : RequestKind) (stage : Stage) (value : ValueClass)
    (visible : mayObserve .diagnostics request stage value = true) :
    value = .publicMetadata := by
  cases request <;> cases stage <;> cases value <;> simp_all [mayObserve]

theorem seedIsExportClientOnly
    (party : Party) (request : RequestKind) (stage : Stage)
    (visible : mayObserve party request stage .exportClientSeed = true) :
    party = .client ∧ request = .export ∧ stage = .exportReleased := by
  cases party <;> cases request <;> cases stage <;> simp_all [mayObserve]

theorem signingWorkerViewIsPublicOnly
    (request : RequestKind) (stage : Stage) (value : ValueClass)
    (visible : mayObserve .signingWorker request stage value = true) :
    value = .publicMetadata := by
  cases request <;> cases stage <;> cases value <;> simp_all [mayObserve]

theorem activationMetadataConsumptionCreatesNoPrivateOutput
    (party : Party) (value : ValueClass) (nonPublic : value ≠ .publicMetadata) :
    newRecipientPrivateOutputs .activation .activationMetadataConsumed = [] ∧
      mayObserve party .activation .activationMetadataConsumed value = false := by
  cases party <;> cases value <;> simp_all [newRecipientPrivateOutputs, mayObserve]

theorem staticOneDeriverObservationExposesExactlyOneRole :
    staticallyExposedDerivers .deriverA = [.deriverA] ∧
      staticallyExposedDerivers .deriverB = [.deriverB] := by
  simp [staticallyExposedDerivers]

end Ed25519YaoModel
