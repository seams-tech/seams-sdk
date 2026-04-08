import Ed25519HssPrivacy.AeneasBridge
import Ed25519HssPrivacy.Goals

namespace Ed25519HssPrivacy

open Ed25519HssBoundary

def GeneratedClientBoundaryIndistinguishableUnderServerSecretVariation : Prop :=
  ∀
      (publicParameters : PublicParameters)
      (boundary : GeneratedVisibleBoundary)
      (serverSecret₁ serverSecret₂ : ServerSecretState),
      ClientBoundaryCompatibleWithServerSecret
        publicParameters
        (nonExportBoundaryOfGeneratedVisibleBoundary boundary)
        serverSecret₁ →
      ClientBoundaryCompatibleWithServerSecret
        publicParameters
        (nonExportBoundaryOfGeneratedVisibleBoundary boundary)
        serverSecret₂ →
      ClientViewsIndistinguishable
        (nonExportClientAdversaryView
          publicParameters
          (nonExportBoundaryOfGeneratedVisibleBoundary boundary))
        (nonExportClientAdversaryView
          publicParameters
          (nonExportBoundaryOfGeneratedVisibleBoundary boundary))

def GeneratedServerBoundaryIndistinguishableUnderClientSecretVariation : Prop :=
  ∀
      (publicParameters : PublicParameters)
      (boundary : GeneratedVisibleBoundary)
      (clientSecret₁ clientSecret₂ : ClientSecretState),
      ServerBoundaryCompatibleWithClientSecret
        publicParameters
        (nonExportBoundaryOfGeneratedVisibleBoundary boundary)
        clientSecret₁ →
      ServerBoundaryCompatibleWithClientSecret
        publicParameters
        (nonExportBoundaryOfGeneratedVisibleBoundary boundary)
        clientSecret₂ →
      ServerViewsIndistinguishable
        (nonExportServerAdversaryView
          publicParameters
          (nonExportBoundaryOfGeneratedVisibleBoundary boundary))
        (nonExportServerAdversaryView
          publicParameters
          (nonExportBoundaryOfGeneratedVisibleBoundary boundary))

def GeneratedClientCannotDeriveYRelayer : Prop :=
  GeneratedClientBoundaryIndistinguishableUnderServerSecretVariation

def GeneratedClientCannotDeriveTauRelayer : Prop :=
  GeneratedClientBoundaryIndistinguishableUnderServerSecretVariation

def GeneratedServerCannotDeriveClientSecrets : Prop :=
  GeneratedServerBoundaryIndistinguishableUnderClientSecretVariation

def GeneratedNonExportHiddenSeedIsHidden : Prop :=
  GeneratedClientBoundaryIndistinguishableUnderServerSecretVariation ∧
  GeneratedServerBoundaryIndistinguishableUnderClientSecretVariation

theorem generatedClientBoundaryIndistinguishableUnderServerSecretVariation_proved :
    GeneratedClientBoundaryIndistinguishableUnderServerSecretVariation := by
  intro publicParameters boundary serverSecret₁ serverSecret₂ hCompat₁ hCompat₂
  exact clientBoundaryIndistinguishableUnderServerSecretVariation_proved
    publicParameters
    (nonExportBoundaryOfGeneratedVisibleBoundary boundary)
    serverSecret₁
    serverSecret₂
    hCompat₁
    hCompat₂

theorem generatedServerBoundaryIndistinguishableUnderClientSecretVariation_proved :
    GeneratedServerBoundaryIndistinguishableUnderClientSecretVariation := by
  intro publicParameters boundary clientSecret₁ clientSecret₂ hCompat₁ hCompat₂
  exact serverBoundaryIndistinguishableUnderClientSecretVariation_proved
    publicParameters
    (nonExportBoundaryOfGeneratedVisibleBoundary boundary)
    clientSecret₁
    clientSecret₂
    hCompat₁
    hCompat₂

theorem generatedClientCannotDeriveYRelayer_proved :
    GeneratedClientCannotDeriveYRelayer := by
  exact generatedClientBoundaryIndistinguishableUnderServerSecretVariation_proved

theorem generatedClientCannotDeriveTauRelayer_proved :
    GeneratedClientCannotDeriveTauRelayer := by
  exact generatedClientBoundaryIndistinguishableUnderServerSecretVariation_proved

theorem generatedServerCannotDeriveClientSecrets_proved :
    GeneratedServerCannotDeriveClientSecrets := by
  exact generatedServerBoundaryIndistinguishableUnderClientSecretVariation_proved

theorem generatedNonExportHiddenSeedIsHidden_proved :
    GeneratedNonExportHiddenSeedIsHidden := by
  constructor
  · exact generatedClientBoundaryIndistinguishableUnderServerSecretVariation_proved
  · exact generatedServerBoundaryIndistinguishableUnderClientSecretVariation_proved

theorem generatedVisibleBoundary_is_nonExport
    (boundary : GeneratedVisibleBoundary) :
    visibleBoundaryOfGeneratedVisibleBoundary boundary =
      .nonExport (nonExportBoundaryOfGeneratedVisibleBoundary boundary) := by
  rfl

theorem generatedVisibleBoundary_has_no_seed_output
    (boundary : GeneratedVisibleBoundary) :
    (visibleBoundaryOfGeneratedVisibleBoundary boundary).seedOutput? = none := by
  rfl

end Ed25519HssPrivacy
