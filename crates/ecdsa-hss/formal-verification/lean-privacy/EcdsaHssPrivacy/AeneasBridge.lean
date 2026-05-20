import EcdsaHssBoundary.GeneratedVisibleBoundary
import EcdsaHssBoundary.GeneratedHiddenEvalBoundary
import EcdsaHssPrivacy.Goals

namespace EcdsaHssPrivacy

open EcdsaHssBoundary

def handwrittenStateOfGeneratedBoundary
    (boundary : GeneratedVisibleRespondBoundaryV1)
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
    (boundary : GeneratedVisibleRespondBoundaryV1) : ClientVisibleBoundary :=
  clientVisibleBoundaryOfRespondBoundary (toHandwrittenRespondBoundary boundary)

def clientObservableProfileOfGeneratedBoundary
    (boundary : GeneratedVisibleRespondBoundaryV1)
    (canonicalX32 : Bytes32)
    (clientSecrets : ClientSecretState)
    (serverSecrets : ServerSecretState) : ClientObservableProfile :=
  clientObservableProfile
    (handwrittenStateOfGeneratedBoundary boundary canonicalX32 clientSecrets serverSecrets)

def serverVisibleBoundaryOfGeneratedBoundary
    (boundary : GeneratedVisibleRespondBoundaryV1) : ServerVisibleBoundary :=
  serverVisibleBoundaryOfRespondBoundary (toHandwrittenRespondBoundary boundary)

def serverObservableProfileOfGeneratedBoundary
    (boundary : GeneratedVisibleRespondBoundaryV1)
    (canonicalX32 : Bytes32)
    (clientSecrets : ClientSecretState)
    (serverSecrets : ServerSecretState) : ServerObservableProfile :=
  serverObservableProfile
    (handwrittenStateOfGeneratedBoundary boundary canonicalX32 clientSecrets serverSecrets)

def nonExportClientViewOfGeneratedBoundary?
    (boundary : GeneratedVisibleRespondBoundaryV1)
    (canonicalX32 : Bytes32)
    (clientSecrets : ClientSecretState)
    (serverSecrets : ServerSecretState) : Option ClientObservableProfile :=
  nonExportClientView?
    (handwrittenStateOfGeneratedBoundary boundary canonicalX32 clientSecrets serverSecrets)

def explicitExportClientViewOfGeneratedBoundary?
    (boundary : GeneratedVisibleRespondBoundaryV1)
    (canonicalX32 : Bytes32)
    (clientSecrets : ClientSecretState)
    (serverSecrets : ServerSecretState) : Option ClientObservableProfile :=
  explicitExportClientView?
    (handwrittenStateOfGeneratedBoundary boundary canonicalX32 clientSecrets serverSecrets)

def nonExportServerViewOfGeneratedBoundary?
    (boundary : GeneratedVisibleRespondBoundaryV1)
    (canonicalX32 : Bytes32)
    (clientSecrets : ClientSecretState)
    (serverSecrets : ServerSecretState) : Option ServerObservableProfile :=
  nonExportServerView?
    (handwrittenStateOfGeneratedBoundary boundary canonicalX32 clientSecrets serverSecrets)

def explicitExportServerViewOfGeneratedBoundary?
    (boundary : GeneratedVisibleRespondBoundaryV1)
    (canonicalX32 : Bytes32)
    (clientSecrets : ClientSecretState)
    (serverSecrets : ServerSecretState) : Option ServerObservableProfile :=
  explicitExportServerView?
    (handwrittenStateOfGeneratedBoundary boundary canonicalX32 clientSecrets serverSecrets)

theorem clientVisibleBoundaryOfGeneratedBoundary_matches_handwritten_model
    (boundary : GeneratedVisibleRespondBoundaryV1) :
    clientVisibleBoundaryOfGeneratedBoundary boundary =
      clientVisibleBoundaryOfRespondBoundary (toHandwrittenRespondBoundary boundary) := by
  rfl

theorem serverVisibleBoundaryOfGeneratedBoundary_matches_handwritten_model
    (boundary : GeneratedVisibleRespondBoundaryV1) :
    serverVisibleBoundaryOfGeneratedBoundary boundary =
      serverVisibleBoundaryOfRespondBoundary (toHandwrittenRespondBoundary boundary) := by
  rfl

theorem nonExportClientViewOfGeneratedBoundary_matches_handwritten_projection
    (boundary : GeneratedVisibleRespondBoundaryV1)
    (canonicalX32 : Bytes32)
    (clientSecrets : ClientSecretState)
    (serverSecrets : ServerSecretState) :
    nonExportClientViewOfGeneratedBoundary? boundary canonicalX32 clientSecrets serverSecrets =
      nonExportClientView?
        (handwrittenStateOfGeneratedBoundary boundary canonicalX32 clientSecrets serverSecrets) := by
  rfl

theorem explicitExportClientViewOfGeneratedBoundary_matches_handwritten_projection
    (boundary : GeneratedVisibleRespondBoundaryV1)
    (canonicalX32 : Bytes32)
    (clientSecrets : ClientSecretState)
    (serverSecrets : ServerSecretState) :
    explicitExportClientViewOfGeneratedBoundary? boundary canonicalX32 clientSecrets serverSecrets =
      explicitExportClientView?
        (handwrittenStateOfGeneratedBoundary boundary canonicalX32 clientSecrets serverSecrets) := by
  rfl

theorem nonExportServerViewOfGeneratedBoundary_matches_handwritten_projection
    (boundary : GeneratedVisibleRespondBoundaryV1)
    (canonicalX32 : Bytes32)
    (clientSecrets : ClientSecretState)
    (serverSecrets : ServerSecretState) :
    nonExportServerViewOfGeneratedBoundary? boundary canonicalX32 clientSecrets serverSecrets =
      nonExportServerView?
        (handwrittenStateOfGeneratedBoundary boundary canonicalX32 clientSecrets serverSecrets) := by
  rfl

theorem explicitExportServerViewOfGeneratedBoundary_matches_handwritten_projection
    (boundary : GeneratedVisibleRespondBoundaryV1)
    (canonicalX32 : Bytes32)
    (clientSecrets : ClientSecretState)
    (serverSecrets : ServerSecretState) :
    explicitExportServerViewOfGeneratedBoundary? boundary canonicalX32 clientSecrets serverSecrets =
      explicitExportServerView?
        (handwrittenStateOfGeneratedBoundary boundary canonicalX32 clientSecrets serverSecrets) := by
  rfl

theorem generatedBoundary_clientCannotDeriveServerSecrets :
    ∀
      (boundary : GeneratedVisibleRespondBoundaryV1)
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
      (boundary : GeneratedVisibleRespondBoundaryV1)
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
    (leftBoundary rightBoundary : GeneratedVisibleRespondBoundaryV1)
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
    (boundary : GeneratedVisibleRespondBoundaryV1) :
    BoundaryRespectsFrozenDisclosurePolicy (toHandwrittenRespondBoundary boundary) →
    ¬ clientBoundaryRevealsCanonicalX
        (toHandwrittenRespondBoundary boundary).clientOutput := by
  intro hPolicy
  exact explicitExportIsOnlyCanonicalSecretDisclosureException_proved
    (toHandwrittenRespondBoundary boundary) hPolicy

def hiddenEvalExecutionStateOfGeneratedBoundary
    (boundary : GeneratedHiddenEvalBoundaryV1)
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
    (boundary : GeneratedHiddenEvalBoundaryV1) : HiddenEvalBoundaryModel :=
  toHandwrittenHiddenEvalBoundary boundary

def hiddenEvalTransportBoundaryOfGeneratedBoundary
    (boundary : GeneratedHiddenEvalBoundaryV1) : HiddenEvalTransportBoundaryModel :=
  (toHandwrittenHiddenEvalBoundary boundary).transport

def hiddenEvalPersistedStateBoundaryOfGeneratedBoundary
    (boundary : GeneratedHiddenEvalBoundaryV1) :
    HiddenEvalPersistedStateBoundaryModel :=
  (toHandwrittenHiddenEvalBoundary boundary).persisted

theorem hiddenEvalBoundaryOfGeneratedBoundary_matches_handwritten_model
    (boundary : GeneratedHiddenEvalBoundaryV1) :
    hiddenEvalBoundaryOfGeneratedBoundary boundary =
      toHandwrittenHiddenEvalBoundary boundary := by
  rfl

theorem generatedHiddenEvalBoundary_matches_privacy_model
    (boundary : GeneratedHiddenEvalBoundaryV1) :
    hiddenEvalBoundaryOfGeneratedBoundary boundary = toHandwrittenHiddenEvalBoundary boundary := by
  exact hiddenEvalBoundaryOfGeneratedBoundary_matches_handwritten_model boundary

theorem generatedHiddenEvalBoundary_indistinguishable_under_client_secret_variation
    (left right : GeneratedHiddenEvalBoundaryV1)
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
    (boundary : GeneratedHiddenEvalBoundaryV1)
    (hAllowed :
      (toHandwrittenHiddenEvalBoundary boundary).transport.operation.allowedOutputKind =
        ecdsa_hss.wire.AllowedOutputKindV1.ThresholdMaterialOnly) :
    transportBoundaryRevealsCanonicalX?
        (hiddenEvalTransportBoundaryOfGeneratedBoundary boundary) = none := by
  exact hiddenEvalNonExportTransportExcludesCanonicalSecret_proved
    (hiddenEvalTransportBoundaryOfGeneratedBoundary boundary) hAllowed

theorem generatedPersistedStateNeverRevealsCanonicalSecret
    (boundary : GeneratedHiddenEvalBoundaryV1) :
    ¬ persistedStateRevealsCanonicalX
        (hiddenEvalPersistedStateBoundaryOfGeneratedBoundary boundary) := by
  exact persistedStateNeverRevealsCanonicalSecret_proved
    (hiddenEvalPersistedStateBoundaryOfGeneratedBoundary boundary)

theorem generatedAcceptedPersistedStateExcludesForbiddenRootMaterial
    (boundary : GeneratedHiddenEvalBoundaryV1)
    (hDropped :
      (hiddenEvalPersistedStateBoundaryOfGeneratedBoundary boundary).rawRootMaterialDropped = true) :
    ¬ persistedStateCarriesForbiddenRootMaterial
        (hiddenEvalPersistedStateBoundaryOfGeneratedBoundary boundary) := by
  exact acceptedPersistedStateExcludesForbiddenRootMaterial_proved
    (hiddenEvalPersistedStateBoundaryOfGeneratedBoundary boundary) hDropped

theorem generatedHiddenEvalTransportExplicitExportIsOnlyCanonicalSecretDisclosureException
    (boundary : GeneratedHiddenEvalBoundaryV1) :
    BoundaryRespectsFrozenDisclosurePolicy
        (respondBoundaryOfHiddenEvalBoundary (toHandwrittenHiddenEvalBoundary boundary)) →
    ¬ transportBoundaryRevealsCanonicalX
        (hiddenEvalTransportBoundaryOfGeneratedBoundary boundary) := by
  intro hPolicy
  exact hiddenEvalTransportExplicitExportIsOnlyCanonicalSecretDisclosureException_proved
    (toHandwrittenHiddenEvalBoundary boundary) hPolicy

end EcdsaHssPrivacy
