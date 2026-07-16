import RouterAbEcdsaDerivationBoundary.GeneratedVisibleBoundary
import RouterAbEcdsaDerivationBoundary.GeneratedHiddenEvalBoundary
import RouterAbEcdsaDerivationPrivacy.Goals

namespace RouterAbEcdsaDerivationPrivacy

open RouterAbEcdsaDerivationBoundary

def handwrittenStateOfGeneratedBoundary
    (boundary : GeneratedVisibleRespondBoundary)
    (canonicalX32 : Bytes32)
    (clientSecrets : ClientSecretState)
    (serverSecrets : ServerSecretState) : ProtocolExecutionState :=
  {
    boundary := toHandwrittenRespondBoundary boundary
    canonicalX32 := canonicalX32
    clientSecrets := clientSecrets
    serverSecrets := serverSecrets
  }

def clientVisibleBoundaryOfGeneratedBoundary
    (boundary : GeneratedVisibleRespondBoundary) : ClientVisibleBoundary :=
  clientVisibleBoundaryOfRespondBoundary (toHandwrittenRespondBoundary boundary)

def clientObservableProfileOfGeneratedBoundary
    (boundary : GeneratedVisibleRespondBoundary)
    (canonicalX32 : Bytes32)
    (clientSecrets : ClientSecretState)
    (serverSecrets : ServerSecretState) : ClientObservableProfile :=
  clientObservableProfile
    (handwrittenStateOfGeneratedBoundary boundary canonicalX32 clientSecrets serverSecrets)

def serverVisibleBoundaryOfGeneratedBoundary
    (boundary : GeneratedVisibleRespondBoundary) : ServerVisibleBoundary :=
  serverVisibleBoundaryOfRespondBoundary (toHandwrittenRespondBoundary boundary)

def serverObservableProfileOfGeneratedBoundary
    (boundary : GeneratedVisibleRespondBoundary)
    (canonicalX32 : Bytes32)
    (clientSecrets : ClientSecretState)
    (serverSecrets : ServerSecretState) : ServerObservableProfile :=
  serverObservableProfile
    (handwrittenStateOfGeneratedBoundary boundary canonicalX32 clientSecrets serverSecrets)

def nonExportClientViewOfGeneratedBoundary?
    (boundary : GeneratedVisibleRespondBoundary)
    (canonicalX32 : Bytes32)
    (clientSecrets : ClientSecretState)
    (serverSecrets : ServerSecretState) : Option ClientObservableProfile :=
  nonExportClientView?
    (handwrittenStateOfGeneratedBoundary boundary canonicalX32 clientSecrets serverSecrets)

def explicitExportClientViewOfGeneratedBoundary?
    (boundary : GeneratedVisibleRespondBoundary)
    (canonicalX32 : Bytes32)
    (clientSecrets : ClientSecretState)
    (serverSecrets : ServerSecretState) : Option ClientObservableProfile :=
  explicitExportClientView?
    (handwrittenStateOfGeneratedBoundary boundary canonicalX32 clientSecrets serverSecrets)

def nonExportServerViewOfGeneratedBoundary?
    (boundary : GeneratedVisibleRespondBoundary)
    (canonicalX32 : Bytes32)
    (clientSecrets : ClientSecretState)
    (serverSecrets : ServerSecretState) : Option ServerObservableProfile :=
  nonExportServerView?
    (handwrittenStateOfGeneratedBoundary boundary canonicalX32 clientSecrets serverSecrets)

def explicitExportServerViewOfGeneratedBoundary?
    (boundary : GeneratedVisibleRespondBoundary)
    (canonicalX32 : Bytes32)
    (clientSecrets : ClientSecretState)
    (serverSecrets : ServerSecretState) : Option ServerObservableProfile :=
  explicitExportServerView?
    (handwrittenStateOfGeneratedBoundary boundary canonicalX32 clientSecrets serverSecrets)

theorem clientVisibleBoundaryOfGeneratedBoundary_matches_handwritten_model
    (boundary : GeneratedVisibleRespondBoundary) :
    clientVisibleBoundaryOfGeneratedBoundary boundary =
      clientVisibleBoundaryOfRespondBoundary (toHandwrittenRespondBoundary boundary) := by
  rfl

theorem serverVisibleBoundaryOfGeneratedBoundary_matches_handwritten_model
    (boundary : GeneratedVisibleRespondBoundary) :
    serverVisibleBoundaryOfGeneratedBoundary boundary =
      serverVisibleBoundaryOfRespondBoundary (toHandwrittenRespondBoundary boundary) := by
  rfl

theorem nonExportClientViewOfGeneratedBoundary_matches_handwritten_projection
    (boundary : GeneratedVisibleRespondBoundary)
    (canonicalX32 : Bytes32)
    (clientSecrets : ClientSecretState)
    (serverSecrets : ServerSecretState) :
    nonExportClientViewOfGeneratedBoundary? boundary canonicalX32 clientSecrets serverSecrets =
      nonExportClientView?
        (handwrittenStateOfGeneratedBoundary boundary canonicalX32 clientSecrets serverSecrets) := by
  rfl

theorem explicitExportClientViewOfGeneratedBoundary_matches_handwritten_projection
    (boundary : GeneratedVisibleRespondBoundary)
    (canonicalX32 : Bytes32)
    (clientSecrets : ClientSecretState)
    (serverSecrets : ServerSecretState) :
    explicitExportClientViewOfGeneratedBoundary? boundary canonicalX32 clientSecrets serverSecrets =
      explicitExportClientView?
        (handwrittenStateOfGeneratedBoundary boundary canonicalX32 clientSecrets serverSecrets) := by
  rfl

theorem nonExportServerViewOfGeneratedBoundary_matches_handwritten_projection
    (boundary : GeneratedVisibleRespondBoundary)
    (canonicalX32 : Bytes32)
    (clientSecrets : ClientSecretState)
    (serverSecrets : ServerSecretState) :
    nonExportServerViewOfGeneratedBoundary? boundary canonicalX32 clientSecrets serverSecrets =
      nonExportServerView?
        (handwrittenStateOfGeneratedBoundary boundary canonicalX32 clientSecrets serverSecrets) := by
  rfl

theorem explicitExportServerViewOfGeneratedBoundary_matches_handwritten_projection
    (boundary : GeneratedVisibleRespondBoundary)
    (canonicalX32 : Bytes32)
    (clientSecrets : ClientSecretState)
    (serverSecrets : ServerSecretState) :
    explicitExportServerViewOfGeneratedBoundary? boundary canonicalX32 clientSecrets serverSecrets =
      explicitExportServerView?
        (handwrittenStateOfGeneratedBoundary boundary canonicalX32 clientSecrets serverSecrets) := by
  rfl

theorem generatedBoundary_clientCannotDeriveServerSecrets :
    ∀
      (boundary : GeneratedVisibleRespondBoundary)
      (canonicalX32₁ canonicalX32₂ : Bytes32)
      (clientSecrets₁ clientSecrets₂ : ClientSecretState)
      (serverSecrets₁ serverSecrets₂ : ServerSecretState),
      statesVaryOnlyInServerSecrets
        (handwrittenStateOfGeneratedBoundary boundary canonicalX32₁ clientSecrets₁ serverSecrets₁)
        (handwrittenStateOfGeneratedBoundary boundary canonicalX32₂ clientSecrets₂ serverSecrets₂)
      →
      ClientViewsIndistinguishable
        (clientObservableProfileOfGeneratedBoundary boundary canonicalX32₁ clientSecrets₁ serverSecrets₁)
        (clientObservableProfileOfGeneratedBoundary boundary canonicalX32₂ clientSecrets₂ serverSecrets₂) := by
  intro boundary canonicalX32₁ canonicalX32₂ clientSecrets₁ clientSecrets₂ serverSecrets₁ serverSecrets₂
  intro hVariation
  exact clientViewsIndistinguishable_of_eq
    (clientObservableProfileOfGeneratedBoundary boundary canonicalX32₁ clientSecrets₁ serverSecrets₁)
    (clientObservableProfileOfGeneratedBoundary boundary canonicalX32₂ clientSecrets₂ serverSecrets₂)
    (clientObservableProfile_eq_of_shared_client_boundary
      (handwrittenStateOfGeneratedBoundary boundary canonicalX32₁ clientSecrets₁ serverSecrets₁)
      (handwrittenStateOfGeneratedBoundary boundary canonicalX32₂ clientSecrets₂ serverSecrets₂)
      hVariation)

theorem generatedBoundary_serverCannotDeriveClientSecrets :
    ∀
      (boundary : GeneratedVisibleRespondBoundary)
      (canonicalX32₁ canonicalX32₂ : Bytes32)
      (clientSecrets₁ clientSecrets₂ : ClientSecretState)
      (serverSecrets₁ serverSecrets₂ : ServerSecretState),
      statesVaryOnlyInClientSecrets
        (handwrittenStateOfGeneratedBoundary boundary canonicalX32₁ clientSecrets₁ serverSecrets₁)
        (handwrittenStateOfGeneratedBoundary boundary canonicalX32₂ clientSecrets₂ serverSecrets₂)
      →
      ServerViewsIndistinguishable
        (serverObservableProfileOfGeneratedBoundary boundary canonicalX32₁ clientSecrets₁ serverSecrets₁)
        (serverObservableProfileOfGeneratedBoundary boundary canonicalX32₂ clientSecrets₂ serverSecrets₂) := by
  intro boundary canonicalX32₁ canonicalX32₂ clientSecrets₁ clientSecrets₂ serverSecrets₁ serverSecrets₂
  intro hVariation
  exact serverViewsIndistinguishable_of_eq
    (serverObservableProfileOfGeneratedBoundary boundary canonicalX32₁ clientSecrets₁ serverSecrets₁)
    (serverObservableProfileOfGeneratedBoundary boundary canonicalX32₂ clientSecrets₂ serverSecrets₂)
    (serverObservableProfile_eq_of_shared_server_boundary
      (handwrittenStateOfGeneratedBoundary boundary canonicalX32₁ clientSecrets₁ serverSecrets₁)
      (handwrittenStateOfGeneratedBoundary boundary canonicalX32₂ clientSecrets₂ serverSecrets₂)
      hVariation)

theorem generatedBoundary_serverCannotSeeClientOutputPayloads
    (leftBoundary rightBoundary : GeneratedVisibleRespondBoundary)
    (canonicalX32₁ canonicalX32₂ : Bytes32)
    (clientSecrets₁ clientSecrets₂ : ClientSecretState)
    (serverSecrets₁ serverSecrets₂ : ServerSecretState)
    (hBoundary :
      serverVisibleBoundaryOfGeneratedBoundary leftBoundary =
        serverVisibleBoundaryOfGeneratedBoundary rightBoundary) :
    serverObservableProfileOfGeneratedBoundary leftBoundary canonicalX32₁ clientSecrets₁ serverSecrets₁ =
      serverObservableProfileOfGeneratedBoundary rightBoundary canonicalX32₂ clientSecrets₂ serverSecrets₂ := by
  exact serverObservableProfile_eq_of_shared_server_boundary
    (handwrittenStateOfGeneratedBoundary leftBoundary canonicalX32₁ clientSecrets₁ serverSecrets₁)
    (handwrittenStateOfGeneratedBoundary rightBoundary canonicalX32₂ clientSecrets₂ serverSecrets₂)
    hBoundary

theorem generatedBoundary_explicitExportIsOnlyCanonicalSecretDisclosureException
    (boundary : GeneratedVisibleRespondBoundary) :
    BoundaryRespectsFrozenDisclosurePolicy (toHandwrittenRespondBoundary boundary) →
    ¬ clientBoundaryRevealsCanonicalX
        (toHandwrittenRespondBoundary boundary).clientOutput := by
  intro hPolicy
  exact explicitExportIsOnlyCanonicalSecretDisclosureException_proved
    (toHandwrittenRespondBoundary boundary) hPolicy

def hiddenEvalExecutionStateOfGeneratedBoundary
    (boundary : GeneratedHiddenEvalBoundary)
    (canonicalX32 : Bytes32)
    (clientSecrets : ClientSecretState)
    (serverSecrets : ServerSecretState) : HiddenEvalExecutionState :=
  {
    hiddenEvalBoundary := toHandwrittenHiddenEvalBoundary boundary
    canonicalX32 := canonicalX32
    clientSecrets := clientSecrets
    serverSecrets := serverSecrets
  }

def hiddenEvalBoundaryOfGeneratedBoundary
    (boundary : GeneratedHiddenEvalBoundary) : HiddenEvalBoundaryModel :=
  toHandwrittenHiddenEvalBoundary boundary

def hiddenEvalTransportBoundaryOfGeneratedBoundary
    (boundary : GeneratedHiddenEvalBoundary) : HiddenEvalTransportBoundaryModel :=
  (toHandwrittenHiddenEvalBoundary boundary).transport

def hiddenEvalPersistedStateBoundaryOfGeneratedBoundary
    (boundary : GeneratedHiddenEvalBoundary) :
    HiddenEvalPersistedStateBoundaryModel :=
  (toHandwrittenHiddenEvalBoundary boundary).persisted

theorem hiddenEvalBoundaryOfGeneratedBoundary_matches_handwritten_model
    (boundary : GeneratedHiddenEvalBoundary) :
    hiddenEvalBoundaryOfGeneratedBoundary boundary =
      toHandwrittenHiddenEvalBoundary boundary := by
  rfl

theorem generatedHiddenEvalBoundary_matches_privacy_model
    (boundary : GeneratedHiddenEvalBoundary) :
    hiddenEvalBoundaryOfGeneratedBoundary boundary = toHandwrittenHiddenEvalBoundary boundary := by
  exact hiddenEvalBoundaryOfGeneratedBoundary_matches_handwritten_model boundary

theorem generatedHiddenEvalBoundary_indistinguishable_under_client_secret_variation
    (left right : GeneratedHiddenEvalBoundary)
    (canonicalX32₁ canonicalX32₂ : Bytes32)
    (clientSecrets₁ clientSecrets₂ : ClientSecretState)
    (serverSecrets₁ serverSecrets₂ : ServerSecretState)
    (hBoundary : left = right) :
    hiddenEvalBoundaryOfState
        (hiddenEvalExecutionStateOfGeneratedBoundary left canonicalX32₁ clientSecrets₁ serverSecrets₁)
      =
      hiddenEvalBoundaryOfState
        (hiddenEvalExecutionStateOfGeneratedBoundary right canonicalX32₂ clientSecrets₂ serverSecrets₂) := by
  cases hBoundary
  rfl

theorem generatedHiddenEvalNonExportTransportExcludesCanonicalSecret
    (boundary : GeneratedHiddenEvalBoundary)
    (hAllowed :
      (toHandwrittenHiddenEvalBoundary boundary).transport.operation.allowedOutputKind =
        router_ab_ecdsa_derivation.wire.AllowedOutputKind.ThresholdMaterialOnly) :
    transportBoundaryRevealsCanonicalX?
        (hiddenEvalTransportBoundaryOfGeneratedBoundary boundary) = none := by
  exact hiddenEvalNonExportTransportExcludesCanonicalSecret_proved
    (hiddenEvalTransportBoundaryOfGeneratedBoundary boundary) hAllowed

theorem generatedPersistedStateNeverRevealsCanonicalSecret
    (boundary : GeneratedHiddenEvalBoundary) :
    ¬ persistedStateRevealsCanonicalX
        (hiddenEvalPersistedStateBoundaryOfGeneratedBoundary boundary) := by
  exact persistedStateNeverRevealsCanonicalSecret_proved
    (hiddenEvalPersistedStateBoundaryOfGeneratedBoundary boundary)

theorem generatedAcceptedPersistedStateExcludesForbiddenRootMaterial
    (boundary : GeneratedHiddenEvalBoundary)
    (hDropped :
      (hiddenEvalPersistedStateBoundaryOfGeneratedBoundary boundary).rawRootMaterialDropped = true) :
    ¬ persistedStateCarriesForbiddenRootMaterial
        (hiddenEvalPersistedStateBoundaryOfGeneratedBoundary boundary) := by
  exact acceptedPersistedStateExcludesForbiddenRootMaterial_proved
    (hiddenEvalPersistedStateBoundaryOfGeneratedBoundary boundary) hDropped

theorem generatedHiddenEvalTransportExplicitExportIsOnlyCanonicalSecretDisclosureException
    (boundary : GeneratedHiddenEvalBoundary) :
    BoundaryRespectsFrozenDisclosurePolicy
        (respondBoundaryOfHiddenEvalBoundary (toHandwrittenHiddenEvalBoundary boundary)) →
    ¬ transportBoundaryRevealsCanonicalX
        (hiddenEvalTransportBoundaryOfGeneratedBoundary boundary) := by
  intro hPolicy
  exact hiddenEvalTransportExplicitExportIsOnlyCanonicalSecretDisclosureException_proved
    (toHandwrittenHiddenEvalBoundary boundary) hPolicy

end RouterAbEcdsaDerivationPrivacy
