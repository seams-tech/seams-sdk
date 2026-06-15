import Ed25519HssPrivacy.Assumptions

namespace Ed25519HssPrivacy

abbrev ClientDeriver := ClientAdversaryView → Bytes32

abbrev ServerDeriver := ServerAdversaryView → ClientSecretState

def ClientCannotDeriveYServer : Prop :=
  ClientBoundaryIndistinguishableUnderServerSecretVariation

def ClientCannotDeriveTauServer : Prop :=
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

theorem clientCannotDeriveYServer_proved : ClientCannotDeriveYServer := by
  exact clientBoundaryIndistinguishableUnderServerSecretVariation_proved

theorem clientCannotDeriveTauServer_proved : ClientCannotDeriveTauServer := by
  exact clientBoundaryIndistinguishableUnderServerSecretVariation_proved

theorem serverCannotDeriveClientSecrets_proved : ServerCannotDeriveClientSecrets := by
  exact serverBoundaryIndistinguishableUnderClientSecretVariation_proved

end Ed25519HssPrivacy
