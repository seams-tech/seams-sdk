import type { ConfirmationConfig } from '@/core/types/signer-worker';
import type { WebAuthnAuthenticationCredential } from '@/core/types';
import type { RegistrationCredentialConfirmationPayload } from '../../workerManager/validation';
import type { WebAuthnAllowCredential } from '../../webauthnAuth/credentials/collectAuthenticationCredentialForChallengeB64u';
import type { RegistrationSessionDeps } from '../../interfaces/operationDeps';

export async function requestRegistrationSessionCredentialConfirmation(
  deps: RegistrationSessionDeps,
  params: {
    walletId: string;
    nearAccountId?: string;
    signerSlot: number;
    confirmerText?: { title?: string; body?: string };
    confirmationConfigOverride?: Partial<ConfirmationConfig>;
    challengeB64u?: string;
    walletIframeActivation?: Parameters<
      RegistrationSessionDeps['touchConfirm']['requestRegistrationCredentialConfirmation']
    >[0]['walletIframeActivation'];
  },
): Promise<RegistrationCredentialConfirmationPayload> {
  return await deps.touchConfirm.requestRegistrationCredentialConfirmation({
    walletId: params.walletId,
    nearAccountId: params.nearAccountId,
    signerSlot: params.signerSlot,
    confirmerText: params.confirmerText,
    confirmationConfigOverride: params.confirmationConfigOverride,
    challengeB64u: params.challengeB64u,
    walletIframeActivation: params.walletIframeActivation,
  });
}

export async function getAuthenticationCredentialsSerialized(
  deps: RegistrationSessionDeps,
  params: {
    subjectId: string;
    challengeB64u: string;
    allowCredentials: WebAuthnAllowCredential[];
    includeSecondPrfOutput?: boolean;
  },
): Promise<WebAuthnAuthenticationCredential> {
  return await deps.touchIdPrompt.getAuthenticationCredentialsSerializedForChallengeB64u({
    subjectId: params.subjectId,
    challengeB64u: params.challengeB64u,
    allowCredentials: params.allowCredentials,
    includeSecondPrfOutput: params.includeSecondPrfOutput ?? false,
  });
}

function toAllowCredentials(credentialIds: string[]): WebAuthnAllowCredential[] {
  return credentialIds.map((id) => ({
    id: id,
    type: 'public-key',
    transports: ['internal', 'hybrid', 'usb', 'ble'],
  }));
}

export async function getAuthenticationCredentialsSerializedDualPrf(
  deps: RegistrationSessionDeps,
  params: {
    subjectId: string;
    challengeB64u: string;
    credentialIds: string[];
  },
): Promise<WebAuthnAuthenticationCredential> {
  return await deps.touchIdPrompt.getAuthenticationCredentialsSerializedForChallengeB64u({
    subjectId: params.subjectId,
    challengeB64u: params.challengeB64u,
    allowCredentials: toAllowCredentials(params.credentialIds),
    includeSecondPrfOutput: true,
  });
}
