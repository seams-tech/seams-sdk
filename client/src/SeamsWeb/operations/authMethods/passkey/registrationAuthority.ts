import type { RegistrationHooksOptions } from '@/core/types/sdkSentEvents';
import type { WebAuthnRegistrationCredential } from '@/core/types/webauthn';
import type { ConfirmationConfig } from '@/core/types/signer-worker';
import type { RegistrationConfirmationDiagnostics } from '@/core/signingEngine/stepUpConfirmation/types';
import type { WebAuthnRegistrationConfirmationSurface } from '@/SeamsWeb/signingSurface/types';
import {
  redactedPasskeyRegistrationCredential,
  requirePasskeyPrfFirstB64u,
} from '@/SeamsWeb/operations/authMethods/passkey/ecdsaBootstrap';

export type PasskeyRegistrationAuthorityMaterial = {
  kind: 'passkey';
  credential: WebAuthnRegistrationCredential;
  webauthnRegistration: WebAuthnRegistrationCredential;
  prfFirstB64u: string;
  diagnostics: PasskeyRegistrationAuthorityDiagnostics;
};

export type PasskeyRegistrationAuthorityDiagnostics = {
  kind: 'passkey_registration_authority_diagnostics_v1';
  requestConfirmationMs: number;
  prfExtractionMs: number;
  credentialRedactionMs: number;
  confirmationWorkerReadyMs: number;
  confirmationWorkerRequestRoundTripMs: number;
  confirmationWorkerResponseValidationMs: number;
  confirmationRequestSetupMs: number;
  confirmationPromptUserMs: number;
  confirmationPromptElementDefineMs: number;
  confirmationPromptMountMs: number;
  confirmationPromptHostFirstUpdateMs: number;
  confirmationPromptHostInteractiveMs: number;
  confirmationPromptConfirmEventMs: number;
  confirmationPromptDecisionWaitMs: number;
  confirmationCredentialCreateStartMs: number;
  confirmationCredentialCreateMs: number;
  confirmationCredentialSerializeMs: number;
  confirmationDuplicateRetryCount: number;
  confirmationMainThreadTotalMs: number;
};

function roundDurationMs(startedAt: number): number {
  return Math.max(0, Math.round(performance.now() - startedAt));
}

function zeroRegistrationConfirmationDiagnostics(): RegistrationConfirmationDiagnostics {
  return {
    kind: 'registration_confirmation_diagnostics_v1',
    workerReadyMs: 0,
    workerRequestRoundTripMs: 0,
    workerResponseValidationMs: 0,
    requestSetupMs: 0,
    promptUserMs: 0,
    promptElementDefineMs: 0,
    promptMountMs: 0,
    promptHostFirstUpdateMs: 0,
    promptHostInteractiveMs: 0,
    promptConfirmEventMs: 0,
    promptDecisionWaitMs: 0,
    credentialCreateStartMs: 0,
    credentialCreateMs: 0,
    credentialSerializeMs: 0,
    duplicateRetryCount: 0,
    mainThreadTotalMs: 0,
  };
}

export async function collectPasskeyRegistrationAuthority(args: {
  context: { signingEngine: WebAuthnRegistrationConfirmationSurface };
  walletId: string;
  signerSlot: number;
  registrationIntentDigestB64u: string;
  options: RegistrationHooksOptions;
  confirmationConfigOverride: Partial<ConfirmationConfig>;
}): Promise<PasskeyRegistrationAuthorityMaterial> {
  const requestConfirmationStartedAt = performance.now();
  const registrationSession =
    await args.context.signingEngine.requestRegistrationCredentialConfirmation({
      nearAccountId: args.walletId,
      signerSlot: args.signerSlot,
      confirmerText: args.options.confirmerText,
      confirmationConfigOverride: args.confirmationConfigOverride,
      challengeB64u: args.registrationIntentDigestB64u,
    });
  const requestConfirmationMs = roundDurationMs(requestConfirmationStartedAt);
  const confirmationDiagnostics =
    registrationSession.registrationDiagnostics ?? zeroRegistrationConfirmationDiagnostics();

  const credential = registrationSession.credential;
  const prfExtractionStartedAt = performance.now();
  const prfFirstB64u = requirePasskeyPrfFirstB64u(credential, 'Passkey registration authority');
  const prfExtractionMs = roundDurationMs(prfExtractionStartedAt);

  const credentialRedactionStartedAt = performance.now();
  const webauthnRegistration = redactedPasskeyRegistrationCredential(credential);
  const credentialRedactionMs = roundDurationMs(credentialRedactionStartedAt);

  return {
    kind: 'passkey',
    credential,
    webauthnRegistration,
    prfFirstB64u,
    diagnostics: {
      kind: 'passkey_registration_authority_diagnostics_v1',
      requestConfirmationMs,
      prfExtractionMs,
      credentialRedactionMs,
      confirmationWorkerReadyMs: confirmationDiagnostics.workerReadyMs,
      confirmationWorkerRequestRoundTripMs: confirmationDiagnostics.workerRequestRoundTripMs,
      confirmationWorkerResponseValidationMs: confirmationDiagnostics.workerResponseValidationMs,
      confirmationRequestSetupMs: confirmationDiagnostics.requestSetupMs,
      confirmationPromptUserMs: confirmationDiagnostics.promptUserMs,
      confirmationPromptElementDefineMs: confirmationDiagnostics.promptElementDefineMs,
      confirmationPromptMountMs: confirmationDiagnostics.promptMountMs,
      confirmationPromptHostFirstUpdateMs: confirmationDiagnostics.promptHostFirstUpdateMs,
      confirmationPromptHostInteractiveMs: confirmationDiagnostics.promptHostInteractiveMs,
      confirmationPromptConfirmEventMs: confirmationDiagnostics.promptConfirmEventMs,
      confirmationPromptDecisionWaitMs: confirmationDiagnostics.promptDecisionWaitMs,
      confirmationCredentialCreateStartMs: confirmationDiagnostics.credentialCreateStartMs,
      confirmationCredentialCreateMs: confirmationDiagnostics.credentialCreateMs,
      confirmationCredentialSerializeMs: confirmationDiagnostics.credentialSerializeMs,
      confirmationDuplicateRetryCount: confirmationDiagnostics.duplicateRetryCount,
      confirmationMainThreadTotalMs: confirmationDiagnostics.mainThreadTotalMs,
    },
  };
}
