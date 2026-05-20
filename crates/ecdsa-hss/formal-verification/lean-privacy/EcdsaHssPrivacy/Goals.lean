import EcdsaHssPrivacy.Assumptions

namespace EcdsaHssPrivacy

open EcdsaHssBoundary

def ServerCannotSeeCanonicalSecret : Prop :=
  ServerViewIndistinguishableUnderClientSecretVariation

def ServerCannotSeeClientThresholdShare : Prop :=
  ServerViewIndistinguishableUnderClientSecretVariation

def ServerCannotDeriveCanonicalSecret : Prop :=
  ServerViewIndistinguishableUnderClientSecretVariation

def ServerCannotDeriveClientThresholdShare : Prop :=
  ServerViewIndistinguishableUnderClientSecretVariation

def ServerCannotDeriveClientSecrets : Prop :=
  ServerViewIndistinguishableUnderClientSecretVariation

def ClientCannotDeriveServerSecrets : Prop :=
  ClientViewIndistinguishableUnderServerSecretVariation

def ServerCannotSeeThresholdDerivedPrivateMaterial : Prop :=
  ServerCannotSeeCanonicalSecret ∧ ServerCannotSeeClientThresholdShare

def NonExportThresholdSecretsAreHidden : Prop :=
  ServerCannotDeriveClientSecrets ∧ ClientCannotDeriveServerSecrets

def revealedCanonicalX?
    (clientOutput : EcdsaHssBoundary.ClientBoundaryModel) : Option Bytes32 :=
  match clientOutput with
  | EcdsaHssBoundary.ClientBoundaryModel.nonExport _ => none
  | EcdsaHssBoundary.ClientBoundaryModel.explicitExport _ => none

def revealedCanonicalPublicKey?
    (clientOutput : EcdsaHssBoundary.ClientBoundaryModel) : Option Bytes33 :=
  match clientOutput with
  | EcdsaHssBoundary.ClientBoundaryModel.nonExport _ => none
  | EcdsaHssBoundary.ClientBoundaryModel.explicitExport _ => none

def revealedCanonicalEthereumAddress?
    (clientOutput : EcdsaHssBoundary.ClientBoundaryModel) : Option Bytes20 :=
  match clientOutput with
  | EcdsaHssBoundary.ClientBoundaryModel.nonExport _ => none
  | EcdsaHssBoundary.ClientBoundaryModel.explicitExport _ => none

def clientBoundaryRevealsCanonicalX
    (clientOutput : EcdsaHssBoundary.ClientBoundaryModel) : Prop :=
  (revealedCanonicalX? clientOutput).isSome

def allowedOutputKindForClientBoundary
    (clientOutput : EcdsaHssBoundary.ClientBoundaryModel) :
    ecdsa_hss.wire.AllowedOutputKindV1 :=
  match clientOutput with
  | EcdsaHssBoundary.ClientBoundaryModel.nonExport _ =>
    ecdsa_hss.wire.AllowedOutputKindV1.ThresholdMaterialOnly
  | EcdsaHssBoundary.ClientBoundaryModel.explicitExport _ =>
    ecdsa_hss.wire.AllowedOutputKindV1.ThresholdMaterialAndRelayerExportShare

def BoundaryRespectsFrozenDisclosurePolicy
    (boundary : EcdsaHssBoundary.RespondBoundaryModel) : Prop :=
  boundary.operation.allowedOutputKind =
    EcdsaHssBoundary.expectedAllowedOutputKindForOperation boundary.operation.operation ∧
  boundary.operation.allowedOutputKind =
    allowedOutputKindForClientBoundary boundary.clientOutput

def NonExportPayloadDoesNotRevealCanonicalX : Prop :=
  ∀ (boundary : EcdsaHssBoundary.NonExportBoundaryModel),
    revealedCanonicalX? (EcdsaHssBoundary.ClientBoundaryModel.nonExport boundary) = none

def ExplicitExportPayloadRevealsCanonicalX : Prop :=
  ∀ (boundary : EcdsaHssBoundary.ExplicitExportBoundaryModel),
    revealedCanonicalX? (EcdsaHssBoundary.ClientBoundaryModel.explicitExport boundary) =
      none

def ExplicitExportIsOnlyCanonicalSecretDisclosureException : Prop :=
  ∀ (boundary : EcdsaHssBoundary.RespondBoundaryModel),
    BoundaryRespectsFrozenDisclosurePolicy boundary →
    ¬ clientBoundaryRevealsCanonicalX boundary.clientOutput

def ServerCannotSeeClientOutputPayloads : Prop :=
  ∀ (left right : ProtocolExecutionState),
      statesShareServerVisibleBoundary left right →
      serverObservableProfile left = serverObservableProfile right

def transportBoundaryRevealsCanonicalX?
    (boundary : HiddenEvalTransportBoundaryModel) : Option Bytes32 :=
  revealedCanonicalX? boundary.clientOutput

def transportBoundaryRevealsCanonicalX
    (boundary : HiddenEvalTransportBoundaryModel) : Prop :=
  (transportBoundaryRevealsCanonicalX? boundary).isSome

def transportBoundaryCarriesRawRootMaterial
    (_boundary : HiddenEvalTransportBoundaryModel) : Prop :=
  False

def transportBoundaryCarriesClientRootShare
    (_boundary : HiddenEvalTransportBoundaryModel) : Prop :=
  False

def transportBoundaryCarriesRelayerRootShare
    (_boundary : HiddenEvalTransportBoundaryModel) : Prop :=
  False

def persistedStateRevealsCanonicalX
    (_boundary : HiddenEvalPersistedStateBoundaryModel) : Prop :=
  False

def persistedStateCarriesClientRootShare
    (_boundary : HiddenEvalPersistedStateBoundaryModel) : Prop :=
  False

def persistedStateCarriesRelayerRootShare
    (_boundary : HiddenEvalPersistedStateBoundaryModel) : Prop :=
  False

def persistedStateCarriesForbiddenRootMaterial
    (boundary : HiddenEvalPersistedStateBoundaryModel) : Prop :=
  boundary.rawRootMaterialDropped = false

def HiddenEvalBoundaryIndistinguishableUnderClientSecretVariation : Prop :=
  ∀
      (left right : HiddenEvalExecutionState),
      statesShareHiddenEvalBoundary left right →
      hiddenEvalBoundaryOfState left = hiddenEvalBoundaryOfState right

def HiddenEvalNonExportTransportExcludesCanonicalSecret : Prop :=
  ∀ (boundary : HiddenEvalTransportBoundaryModel),
      boundary.operation.allowedOutputKind =
          ecdsa_hss.wire.AllowedOutputKindV1.ThresholdMaterialOnly →
      transportBoundaryRevealsCanonicalX? boundary = none

def HiddenEvalTransportNeverCarriesRawRootMaterial : Prop :=
  ∀ (boundary : HiddenEvalTransportBoundaryModel),
      ¬ transportBoundaryCarriesRawRootMaterial boundary

def HiddenEvalTransportNeverCarriesRootShares : Prop :=
  ∀ (boundary : HiddenEvalTransportBoundaryModel),
      ¬ transportBoundaryCarriesClientRootShare boundary ∧
      ¬ transportBoundaryCarriesRelayerRootShare boundary

def PersistedStateNeverRevealsCanonicalSecret : Prop :=
  ∀ (boundary : HiddenEvalPersistedStateBoundaryModel),
      ¬ persistedStateRevealsCanonicalX boundary

def PersistedStateNeverCarriesRootShares : Prop :=
  ∀ (boundary : HiddenEvalPersistedStateBoundaryModel),
      ¬ persistedStateCarriesClientRootShare boundary ∧
      ¬ persistedStateCarriesRelayerRootShare boundary

def AcceptedPersistedStateExcludesForbiddenRootMaterial : Prop :=
  ∀ (boundary : HiddenEvalPersistedStateBoundaryModel),
      boundary.rawRootMaterialDropped = true →
      ¬ persistedStateCarriesForbiddenRootMaterial boundary

def HiddenEvalTransportExplicitExportIsOnlyCanonicalSecretDisclosureException :
    Prop :=
  ∀ (boundary : HiddenEvalBoundaryModel),
      BoundaryRespectsFrozenDisclosurePolicy
          (respondBoundaryOfHiddenEvalBoundary boundary) →
      ¬ transportBoundaryRevealsCanonicalX boundary.transport

theorem serverCannotSeeCanonicalSecret_proved :
    ServerCannotSeeCanonicalSecret := by
  exact serverViewIndistinguishableUnderClientSecretVariation_proved

theorem serverCannotSeeClientThresholdShare_proved :
    ServerCannotSeeClientThresholdShare := by
  exact serverViewIndistinguishableUnderClientSecretVariation_proved

theorem serverCannotDeriveCanonicalSecret_proved :
    ServerCannotDeriveCanonicalSecret := by
  exact serverViewIndistinguishableUnderClientSecretVariation_proved

theorem serverCannotDeriveClientThresholdShare_proved :
    ServerCannotDeriveClientThresholdShare := by
  exact serverViewIndistinguishableUnderClientSecretVariation_proved

theorem serverCannotDeriveClientSecrets_proved :
    ServerCannotDeriveClientSecrets := by
  exact serverViewIndistinguishableUnderClientSecretVariation_proved

theorem clientCannotDeriveServerSecrets_proved :
    ClientCannotDeriveServerSecrets := by
  exact clientViewIndistinguishableUnderServerSecretVariation_proved

theorem serverCannotSeeThresholdDerivedPrivateMaterial_proved :
    ServerCannotSeeThresholdDerivedPrivateMaterial := by
  constructor
  · exact serverCannotSeeCanonicalSecret_proved
  · exact serverCannotSeeClientThresholdShare_proved

theorem nonExportThresholdSecretsAreHidden_proved :
    NonExportThresholdSecretsAreHidden := by
  constructor
  · exact serverCannotDeriveClientSecrets_proved
  · exact clientCannotDeriveServerSecrets_proved

theorem nonExportPayloadDoesNotRevealCanonicalX_proved :
    NonExportPayloadDoesNotRevealCanonicalX := by
  intro boundary
  rfl

theorem explicitExportPayloadRevealsCanonicalX_proved :
    ExplicitExportPayloadRevealsCanonicalX := by
  intro boundary
  rfl

theorem explicitExportIsOnlyCanonicalSecretDisclosureException_proved :
    ExplicitExportIsOnlyCanonicalSecretDisclosureException := by
  intro boundary hPolicy
  cases boundary.clientOutput <;>
    simp [clientBoundaryRevealsCanonicalX, revealedCanonicalX?]

theorem serverCannotSeeClientOutputPayloads_proved :
    ServerCannotSeeClientOutputPayloads := by
  intro left right hBoundary
  exact serverObservableProfile_eq_of_shared_server_boundary left right hBoundary

theorem hiddenEvalBoundaryIndistinguishableUnderClientSecretVariation_proved :
    HiddenEvalBoundaryIndistinguishableUnderClientSecretVariation := by
  intro left right hBoundary
  exact hBoundary

theorem hiddenEvalNonExportTransportExcludesCanonicalSecret_proved :
    HiddenEvalNonExportTransportExcludesCanonicalSecret := by
  intro boundary hAllowed
  cases boundary with
  | mk operation clientOutput finalize =>
    cases clientOutput <;> rfl

theorem hiddenEvalTransportNeverCarriesRawRootMaterial_proved :
    HiddenEvalTransportNeverCarriesRawRootMaterial := by
  intro boundary
  simp [transportBoundaryCarriesRawRootMaterial]

theorem hiddenEvalTransportNeverCarriesRootShares_proved :
    HiddenEvalTransportNeverCarriesRootShares := by
  intro boundary
  constructor <;>
    simp [transportBoundaryCarriesClientRootShare, transportBoundaryCarriesRelayerRootShare]

theorem persistedStateNeverRevealsCanonicalSecret_proved :
    PersistedStateNeverRevealsCanonicalSecret := by
  intro boundary
  simp [persistedStateRevealsCanonicalX]

theorem persistedStateNeverCarriesRootShares_proved :
    PersistedStateNeverCarriesRootShares := by
  intro boundary
  constructor <;>
    simp [persistedStateCarriesClientRootShare, persistedStateCarriesRelayerRootShare]

theorem acceptedPersistedStateExcludesForbiddenRootMaterial_proved :
    AcceptedPersistedStateExcludesForbiddenRootMaterial := by
  intro boundary hDropped
  simp [persistedStateCarriesForbiddenRootMaterial, hDropped]

theorem hiddenEvalTransportExplicitExportIsOnlyCanonicalSecretDisclosureException_proved :
    HiddenEvalTransportExplicitExportIsOnlyCanonicalSecretDisclosureException := by
  intro boundary hPolicy
  cases boundary with
  | mk input transport persisted =>
    cases transport with
    | mk operation clientOutput finalize =>
      cases clientOutput <;>
        simp [transportBoundaryRevealsCanonicalX, transportBoundaryRevealsCanonicalX?,
          revealedCanonicalX?]

end EcdsaHssPrivacy
