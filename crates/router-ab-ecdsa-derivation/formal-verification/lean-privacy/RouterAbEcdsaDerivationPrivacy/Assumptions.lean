import RouterAbEcdsaDerivationPrivacy.Simulators

namespace RouterAbEcdsaDerivationPrivacy

def ClientViewCompatibleWithSimulator : Prop :=
  ∀ (state : ProtocolExecutionState),
      simulateNonExportClientView
          {
            visibleBoundary := clientVisibleBoundaryOfState state
          }
        =
        nonExportClientView? state

def ExplicitExportClientViewCompatibleWithSimulator : Prop :=
  ∀ (state : ProtocolExecutionState),
      simulateExplicitExportClientView
          {
            visibleBoundary := clientVisibleBoundaryOfState state
          }
        =
        explicitExportClientView? state

def ServerViewCompatibleWithSimulator : Prop :=
  ∀ (state : ProtocolExecutionState),
      simulateNonExportServerView
          {
            visibleBoundary := serverVisibleBoundaryOfState state
          }
        =
        nonExportServerView? state

def ExplicitExportServerViewCompatibleWithSimulator : Prop :=
  ∀ (state : ProtocolExecutionState),
      simulateExplicitExportServerView
          {
            visibleBoundary := serverVisibleBoundaryOfState state
          }
        =
        explicitExportServerView? state

def ClientVisibleBoundaryEquivalent
    (left right : ClientVisibleBoundary) : Prop :=
  left.operation = right.operation ∧
  left.allowedOutputKind = right.allowedOutputKind ∧
  left.clientOutput = right.clientOutput

def ServerVisibleBoundaryEquivalent
    (left right : ServerVisibleBoundary) : Prop :=
  left.operation = right.operation ∧
  left.allowedOutputKind = right.allowedOutputKind ∧
  left.finalizeOperation = right.finalizeOperation ∧
  left.rawRootMaterialDropped = right.rawRootMaterialDropped ∧
  left.relayerKeyId = right.relayerKeyId ∧
  left.clientPublicKey33 = right.clientPublicKey33 ∧
  left.relayerPublicKey33 = right.relayerPublicKey33 ∧
  left.thresholdPublicKey33 = right.thresholdPublicKey33 ∧
  left.thresholdEthereumAddress20 = right.thresholdEthereumAddress20 ∧
  left.clientShareRetryCounter = right.clientShareRetryCounter ∧
  left.relayerShareRetryCounter = right.relayerShareRetryCounter ∧
  left.retainedRelayerKeyId = right.retainedRelayerKeyId ∧
  left.relayerShare32 = right.relayerShare32 ∧
  left.retainedClientPublicKey33 = right.retainedClientPublicKey33 ∧
  left.retainedRelayerPublicKey33 = right.retainedRelayerPublicKey33 ∧
  left.retainedThresholdPublicKey33 = right.retainedThresholdPublicKey33 ∧
  left.retainedThresholdEthereumAddress20 = right.retainedThresholdEthereumAddress20 ∧
  left.retainedClientShareRetryCounter = right.retainedClientShareRetryCounter ∧
  left.retainedRelayerShareRetryCounter = right.retainedRelayerShareRetryCounter

def ClientObservableProfilesEquivalent
    (left right : ClientObservableProfile) : Prop :=
  ClientVisibleBoundaryEquivalent left.boundary right.boundary

def ServerObservableProfilesEquivalent
    (left right : ServerObservableProfile) : Prop :=
  ServerVisibleBoundaryEquivalent left.boundary right.boundary

def ClientViewsIndistinguishable
    (left right : ClientObservableProfile) : Prop :=
  ClientObservableProfilesEquivalent left right

def ServerViewsIndistinguishable
    (left right : ServerObservableProfile) : Prop :=
  ServerObservableProfilesEquivalent left right

def ClientViewIndistinguishableUnderServerSecretVariation : Prop :=
  ∀
      (left right : ProtocolExecutionState),
      statesVaryOnlyInServerSecrets left right →
      ClientViewCompatibleWithSimulator →
      ClientViewsIndistinguishable
        (clientObservableProfile left)
        (clientObservableProfile right)

def ServerViewIndistinguishableUnderClientSecretVariation : Prop :=
  ∀
      (left right : ProtocolExecutionState),
      statesVaryOnlyInClientSecrets left right →
      ServerViewCompatibleWithSimulator →
      ServerViewsIndistinguishable
        (serverObservableProfile left)
        (serverObservableProfile right)

theorem clientViewCompatibleWithSimulator_proved :
    ClientViewCompatibleWithSimulator := by
  intro state
  exact simulateNonExportClientView_matches_state_projection state

theorem explicitExportClientViewCompatibleWithSimulator_proved :
    ExplicitExportClientViewCompatibleWithSimulator := by
  intro state
  exact simulateExplicitExportClientView_matches_state_projection state

theorem serverViewCompatibleWithSimulator_proved :
    ServerViewCompatibleWithSimulator := by
  intro state
  exact simulateNonExportServerView_matches_state_projection state

theorem explicitExportServerViewCompatibleWithSimulator_proved :
    ExplicitExportServerViewCompatibleWithSimulator := by
  intro state
  exact simulateExplicitExportServerView_matches_state_projection state

theorem clientObservableProfilesEquivalent_of_eq
    (left right : ClientObservableProfile)
    (h : left = right) :
    ClientObservableProfilesEquivalent left right := by
  cases h
  simp [ClientObservableProfilesEquivalent, ClientVisibleBoundaryEquivalent]

theorem serverObservableProfilesEquivalent_of_eq
    (left right : ServerObservableProfile)
    (h : left = right) :
    ServerObservableProfilesEquivalent left right := by
  cases h
  simp [ServerObservableProfilesEquivalent, ServerVisibleBoundaryEquivalent]

theorem clientViewsIndistinguishable_of_eq
    (left right : ClientObservableProfile)
    (h : left = right) :
    ClientViewsIndistinguishable left right := by
  exact clientObservableProfilesEquivalent_of_eq left right h

theorem serverViewsIndistinguishable_of_eq
    (left right : ServerObservableProfile)
    (h : left = right) :
    ServerViewsIndistinguishable left right := by
  exact serverObservableProfilesEquivalent_of_eq left right h

theorem clientViewIndistinguishableUnderServerSecretVariation_proved :
    ClientViewIndistinguishableUnderServerSecretVariation := by
  intro left right hVariation _hCompat
  exact clientViewsIndistinguishable_of_eq
    (clientObservableProfile left)
    (clientObservableProfile right)
    (clientObservableProfile_eq_of_shared_client_boundary left right hVariation)

theorem serverViewIndistinguishableUnderClientSecretVariation_proved :
    ServerViewIndistinguishableUnderClientSecretVariation := by
  intro left right hVariation _hCompat
  exact serverViewsIndistinguishable_of_eq
    (serverObservableProfile left)
    (serverObservableProfile right)
    (serverObservableProfile_eq_of_shared_server_boundary left right hVariation)

end RouterAbEcdsaDerivationPrivacy
