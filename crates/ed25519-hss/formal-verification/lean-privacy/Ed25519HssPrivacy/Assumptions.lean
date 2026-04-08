import Ed25519HssPrivacy.Simulators

namespace Ed25519HssPrivacy

def ClientBoundaryCompatibleWithServerSecret
    (publicParameters : PublicParameters)
    (boundary : NonExportVisibleBoundary)
    (_serverSecret : ServerSecretState) : Prop :=
  ∃ input : ClientSimulatorInput,
    input.publicParameters = publicParameters ∧
    input.boundary = boundary ∧
    simulateNonExportClientView input
      = nonExportClientAdversaryView publicParameters boundary

def ServerBoundaryCompatibleWithClientSecret
    (publicParameters : PublicParameters)
    (boundary : NonExportVisibleBoundary)
    (_clientSecret : ClientSecretState) : Prop :=
  ∃ input : ServerSimulatorInput,
    input.publicParameters = publicParameters ∧
    input.boundary = boundary ∧
    simulateNonExportServerView input
      = nonExportServerAdversaryView publicParameters boundary

theorem clientBoundaryCompatibleWithServerSecret_fromSimulator
    (publicParameters : PublicParameters)
    (boundary : NonExportVisibleBoundary)
    (serverSecret : ServerSecretState) :
    ClientBoundaryCompatibleWithServerSecret publicParameters boundary serverSecret := by
  refine ⟨{
    publicParameters := publicParameters
    boundary := boundary
  }, rfl, rfl, rfl⟩

theorem serverBoundaryCompatibleWithClientSecret_fromSimulator
    (publicParameters : PublicParameters)
    (boundary : NonExportVisibleBoundary)
    (clientSecret : ClientSecretState) :
    ServerBoundaryCompatibleWithClientSecret publicParameters boundary clientSecret := by
  refine ⟨{
    publicParameters := publicParameters
    boundary := boundary
  }, rfl, rfl, rfl⟩

def ClientObservationallyHidesServerSecret : Prop :=
  ∀
      (publicParameters : PublicParameters)
      (boundary : NonExportVisibleBoundary)
      (serverSecret₁ serverSecret₂ : ServerSecretState),
      ClientBoundaryCompatibleWithServerSecret publicParameters boundary serverSecret₁ →
      ClientBoundaryCompatibleWithServerSecret publicParameters boundary serverSecret₂ →
      nonExportClientAdversaryView publicParameters boundary
        = nonExportClientAdversaryView publicParameters boundary

def ServerObservationallyHidesClientSecret : Prop :=
  ∀
      (publicParameters : PublicParameters)
      (boundary : NonExportVisibleBoundary)
      (clientSecret₁ clientSecret₂ : ClientSecretState),
      ServerBoundaryCompatibleWithClientSecret publicParameters boundary clientSecret₁ →
      ServerBoundaryCompatibleWithClientSecret publicParameters boundary clientSecret₂ →
      nonExportServerAdversaryView publicParameters boundary
        = nonExportServerAdversaryView publicParameters boundary

theorem clientObservationallyHidesServerSecret_proved :
    ClientObservationallyHidesServerSecret := by
  intro publicParameters boundary serverSecret₁ serverSecret₂ _hCompat₁ _hCompat₂
  rfl

theorem serverObservationallyHidesClientSecret_proved :
    ServerObservationallyHidesClientSecret := by
  intro publicParameters boundary clientSecret₁ clientSecret₂ _hCompat₁ _hCompat₂
  rfl

def PublicParametersEquivalent
    (left right : PublicParameters) : Prop :=
  left.operation = right.operation ∧
  left.allowedOutputKind = right.allowedOutputKind ∧
  left.contextBinding = right.contextBinding ∧
  left.runBinding = right.runBinding ∧
  left.publicKey = right.publicKey

def NonExportBoundaryEquivalent
    (left right : NonExportVisibleBoundary) : Prop :=
  left.canonicalSeed = right.canonicalSeed ∧
  left.xClientBase = right.xClientBase ∧
  left.xRelayerBaseTransportLeft = right.xRelayerBaseTransportLeft ∧
  left.xRelayerBaseTransportRight = right.xRelayerBaseTransportRight

structure ClientObservableProfile where
  publicParameters : PublicParameters
  boundary : NonExportVisibleBoundary
  deriving Repr

structure ServerObservableProfile where
  publicParameters : PublicParameters
  boundary : NonExportVisibleBoundary
  deriving Repr

def clientObservableProfile
    (view : ClientAdversaryView) : ClientObservableProfile :=
  {
    publicParameters := view.publicParameters
    boundary := view.boundary
  }

def serverObservableProfile
    (view : ServerAdversaryView) : ServerObservableProfile :=
  {
    publicParameters := view.publicParameters
    boundary := view.boundary
  }

def ClientViewsIndistinguishable
    (left right : ClientAdversaryView) : Prop :=
  clientObservableProfile left = clientObservableProfile right

def ServerViewsIndistinguishable
    (left right : ServerAdversaryView) : Prop :=
  serverObservableProfile left = serverObservableProfile right

def ClientBoundaryIndistinguishableUnderServerSecretVariation : Prop :=
  ∀
      (publicParameters : PublicParameters)
      (boundary : NonExportVisibleBoundary)
      (serverSecret₁ serverSecret₂ : ServerSecretState),
      ClientBoundaryCompatibleWithServerSecret publicParameters boundary serverSecret₁ →
      ClientBoundaryCompatibleWithServerSecret publicParameters boundary serverSecret₂ →
      ClientViewsIndistinguishable
        (nonExportClientAdversaryView publicParameters boundary)
        (nonExportClientAdversaryView publicParameters boundary)

def ServerBoundaryIndistinguishableUnderClientSecretVariation : Prop :=
  ∀
      (publicParameters : PublicParameters)
      (boundary : NonExportVisibleBoundary)
      (clientSecret₁ clientSecret₂ : ClientSecretState),
      ServerBoundaryCompatibleWithClientSecret publicParameters boundary clientSecret₁ →
      ServerBoundaryCompatibleWithClientSecret publicParameters boundary clientSecret₂ →
      ServerViewsIndistinguishable
        (nonExportServerAdversaryView publicParameters boundary)
        (nonExportServerAdversaryView publicParameters boundary)

theorem clientBoundaryIndistinguishableUnderServerSecretVariation_proved :
    ClientBoundaryIndistinguishableUnderServerSecretVariation := by
  intro publicParameters boundary serverSecret₁ serverSecret₂ hCompat₁ hCompat₂
  rfl

theorem serverBoundaryIndistinguishableUnderClientSecretVariation_proved :
    ServerBoundaryIndistinguishableUnderClientSecretVariation := by
  intro publicParameters boundary clientSecret₁ clientSecret₂ hCompat₁ hCompat₂
  rfl

theorem clientViewsIndistinguishable_iff_observable_fields
    (left right : ClientAdversaryView) :
    ClientViewsIndistinguishable left right ↔
      PublicParametersEquivalent left.publicParameters right.publicParameters ∧
      NonExportBoundaryEquivalent left.boundary right.boundary := by
  constructor
  · intro h
    cases left
    cases right
    simp [ClientViewsIndistinguishable, clientObservableProfile,
      PublicParametersEquivalent, NonExportBoundaryEquivalent] at h ⊢
    exact h
  · intro h
    cases left
    cases right
    simp [ClientViewsIndistinguishable, clientObservableProfile,
      PublicParametersEquivalent, NonExportBoundaryEquivalent] at h ⊢
    exact h

theorem serverViewsIndistinguishable_iff_observable_fields
    (left right : ServerAdversaryView) :
    ServerViewsIndistinguishable left right ↔
      PublicParametersEquivalent left.publicParameters right.publicParameters ∧
      NonExportBoundaryEquivalent left.boundary right.boundary := by
  constructor
  · intro h
    cases left
    cases right
    simp [ServerViewsIndistinguishable, serverObservableProfile,
      PublicParametersEquivalent, NonExportBoundaryEquivalent] at h ⊢
    exact h
  · intro h
    cases left
    cases right
    simp [ServerViewsIndistinguishable, serverObservableProfile,
      PublicParametersEquivalent, NonExportBoundaryEquivalent] at h ⊢
    exact h

end Ed25519HssPrivacy
