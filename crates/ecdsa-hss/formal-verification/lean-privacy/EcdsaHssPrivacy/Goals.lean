import EcdsaHssPrivacy.Assumptions

namespace EcdsaHssPrivacy

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
  | EcdsaHssBoundary.ClientBoundaryModel.explicitExport boundary =>
    some boundary.canonicalX32

def revealedCanonicalPublicKey?
    (clientOutput : EcdsaHssBoundary.ClientBoundaryModel) : Option Bytes33 :=
  match clientOutput with
  | EcdsaHssBoundary.ClientBoundaryModel.nonExport _ => none
  | EcdsaHssBoundary.ClientBoundaryModel.explicitExport boundary =>
    some boundary.canonicalPublicKey33

def revealedCanonicalEthereumAddress?
    (clientOutput : EcdsaHssBoundary.ClientBoundaryModel) : Option Bytes20 :=
  match clientOutput with
  | EcdsaHssBoundary.ClientBoundaryModel.nonExport _ => none
  | EcdsaHssBoundary.ClientBoundaryModel.explicitExport boundary =>
    some boundary.canonicalEthereumAddress20

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
    ecdsa_hss.wire.AllowedOutputKindV1.ThresholdMaterialAndCanonicalSecret

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
      some boundary.canonicalX32

def ExplicitExportIsOnlyCanonicalSecretDisclosureException : Prop :=
  ∀ (boundary : EcdsaHssBoundary.RespondBoundaryModel),
    BoundaryRespectsFrozenDisclosurePolicy boundary →
    clientBoundaryRevealsCanonicalX boundary.clientOutput
      ↔ boundary.operation.operation = ecdsa_hss.wire.ServerEvalOperationV1.ExplicitKeyExport

def ServerCannotSeeClientOutputPayloads : Prop :=
  ∀ (left right : ProtocolExecutionState),
      statesShareServerVisibleBoundary left right →
      serverObservableProfile left = serverObservableProfile right

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
  rcases hPolicy with ⟨hOperation, hClientOutput⟩
  cases boundary.operation.operation <;> cases boundary.clientOutput <;>
    simp [BoundaryRespectsFrozenDisclosurePolicy,
      clientBoundaryRevealsCanonicalX,
      revealedCanonicalX?,
      allowedOutputKindForClientBoundary,
      EcdsaHssBoundary.expectedAllowedOutputKindForOperation] at hOperation hClientOutput ⊢
  all_goals contradiction

theorem serverCannotSeeClientOutputPayloads_proved :
    ServerCannotSeeClientOutputPayloads := by
  intro left right hBoundary
  exact serverObservableProfile_eq_of_shared_server_boundary left right hBoundary

end EcdsaHssPrivacy
