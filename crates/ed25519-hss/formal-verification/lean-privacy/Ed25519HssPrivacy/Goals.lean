import Ed25519HssPrivacy.Assumptions

namespace Ed25519HssPrivacy

abbrev ClientDeriver := ClientAdversaryView → Bytes32

abbrev ServerDeriver := ServerAdversaryView → ClientSecretState

def ClientCannotDeriveYRelayer : Prop :=
  ClientBoundaryIndistinguishableUnderServerSecretVariation

def ClientCannotDeriveTauRelayer : Prop :=
  ClientBoundaryIndistinguishableUnderServerSecretVariation

def ServerCannotDeriveClientSecrets : Prop :=
  ServerBoundaryIndistinguishableUnderClientSecretVariation

def NonExportHiddenSeedIsHidden : Prop :=
  ClientBoundaryIndistinguishableUnderServerSecretVariation ∧
  ServerBoundaryIndistinguishableUnderClientSecretVariation

def ExplicitExportIsOnlyDisclosureException : Prop :=
  ∀ (operation : Operation) (boundary : VisibleBoundary),
    boundary.allowedOutputKind = allowedOutputKindForOperation operation →
    (boundary.seedOutput? ≠ none) ↔ operation = .explicitKeyExport

theorem nonExportHiddenSeedIsHidden_proved : NonExportHiddenSeedIsHidden := by
  constructor
  · exact clientBoundaryIndistinguishableUnderServerSecretVariation_proved
  · exact serverBoundaryIndistinguishableUnderClientSecretVariation_proved

theorem explicitExportIsOnlyDisclosureException_proved :
    ExplicitExportIsOnlyDisclosureException := by
  intro operation boundary hAllowed
  cases boundary <;> cases operation <;> simp [VisibleBoundary.allowedOutputKind,
    VisibleBoundary.seedOutput?, allowedOutputKindForOperation] at hAllowed ⊢

theorem clientCannotDeriveYRelayer_proved : ClientCannotDeriveYRelayer := by
  exact clientBoundaryIndistinguishableUnderServerSecretVariation_proved

theorem clientCannotDeriveTauRelayer_proved : ClientCannotDeriveTauRelayer := by
  exact clientBoundaryIndistinguishableUnderServerSecretVariation_proved

theorem serverCannotDeriveClientSecrets_proved : ServerCannotDeriveClientSecrets := by
  exact serverBoundaryIndistinguishableUnderClientSecretVariation_proved

end Ed25519HssPrivacy
