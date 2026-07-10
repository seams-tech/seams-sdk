import type { RegistrationHooksOptions } from '@/core/types/sdkSentEvents';
import type { WebAuthnRegistrationCredential } from '@/core/types/webauthn';
import type { ConfirmationConfig } from '@/core/types/signer-worker';
import type { RegistrationActivationProof } from '@/core/signingEngine/stepUpConfirmation/channel/confirmTypes';
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

function buildPasskeyRegistrationAuthorityMaterial(args: {
  credential: WebAuthnRegistrationCredential;
  diagnostics: RegistrationConfirmationDiagnostics;
  requestConfirmationMs: number;
}): PasskeyRegistrationAuthorityMaterial {
  const prfExtractionStartedAt = performance.now();
  const prfFirstB64u = requirePasskeyPrfFirstB64u(
    args.credential,
    'Passkey registration authority',
  );
  const prfExtractionMs = roundDurationMs(prfExtractionStartedAt);
  const credentialRedactionStartedAt = performance.now();
  const webauthnRegistration = redactedPasskeyRegistrationCredential(args.credential);
  const credentialRedactionMs = roundDurationMs(credentialRedactionStartedAt);
  return {
    kind: 'passkey',
    credential: args.credential,
    webauthnRegistration,
    prfFirstB64u,
    diagnostics: {
      kind: 'passkey_registration_authority_diagnostics_v1',
      requestConfirmationMs: args.requestConfirmationMs,
      prfExtractionMs,
      credentialRedactionMs,
      confirmationWorkerReadyMs: args.diagnostics.workerReadyMs,
      confirmationWorkerRequestRoundTripMs: args.diagnostics.workerRequestRoundTripMs,
      confirmationWorkerResponseValidationMs: args.diagnostics.workerResponseValidationMs,
      confirmationRequestSetupMs: args.diagnostics.requestSetupMs,
      confirmationPromptUserMs: args.diagnostics.promptUserMs,
      confirmationPromptElementDefineMs: args.diagnostics.promptElementDefineMs,
      confirmationPromptMountMs: args.diagnostics.promptMountMs,
      confirmationPromptHostFirstUpdateMs: args.diagnostics.promptHostFirstUpdateMs,
      confirmationPromptHostInteractiveMs: args.diagnostics.promptHostInteractiveMs,
      confirmationPromptConfirmEventMs: args.diagnostics.promptConfirmEventMs,
      confirmationPromptDecisionWaitMs: args.diagnostics.promptDecisionWaitMs,
      confirmationCredentialCreateStartMs: args.diagnostics.credentialCreateStartMs,
      confirmationCredentialCreateMs: args.diagnostics.credentialCreateMs,
      confirmationCredentialSerializeMs: args.diagnostics.credentialSerializeMs,
      confirmationDuplicateRetryCount: args.diagnostics.duplicateRetryCount,
      confirmationMainThreadTotalMs: args.diagnostics.mainThreadTotalMs,
    },
  };
}

export async function collectPasskeyRegistrationAuthorityFromCredential(
  credentialPromise: Promise<WebAuthnRegistrationCredential>,
): Promise<PasskeyRegistrationAuthorityMaterial> {
  const startedAt = performance.now();
  const credential = await credentialPromise;
  return buildPasskeyRegistrationAuthorityMaterial({
    credential,
    diagnostics: zeroRegistrationConfirmationDiagnostics(),
    requestConfirmationMs: roundDurationMs(startedAt),
  });
}

export async function collectPasskeyRegistrationAuthority(args: {
  context: { signingEngine: WebAuthnRegistrationConfirmationSurface };
  walletId: string;
  signerSlot: number;
  registrationIntentDigestB64u: string;
  options: RegistrationHooksOptions;
  confirmationConfigOverride: Partial<ConfirmationConfig>;
  walletIframeActivation?: RegistrationActivationProof;
}): Promise<PasskeyRegistrationAuthorityMaterial> {
  const requestConfirmationStartedAt = performance.now();
  const registrationSession =
    await args.context.signingEngine.requestRegistrationCredentialConfirmation({
      walletId: args.walletId,
      signerSlot: args.signerSlot,
      confirmerText: args.options.confirmerText,
      confirmationConfigOverride: args.confirmationConfigOverride,
      challengeB64u: args.registrationIntentDigestB64u,
      walletIframeActivation: args.walletIframeActivation,
    });
  const requestConfirmationMs = roundDurationMs(requestConfirmationStartedAt);
  const confirmationDiagnostics =
    registrationSession.registrationDiagnostics ?? zeroRegistrationConfirmationDiagnostics();

  return buildPasskeyRegistrationAuthorityMaterial({
    credential: registrationSession.credential,
    diagnostics: confirmationDiagnostics,
    requestConfirmationMs,
  });
}
