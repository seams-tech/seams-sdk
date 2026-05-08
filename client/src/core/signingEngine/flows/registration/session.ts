import type { AccountId } from '@/core/types/accountIds';
import type { ConfirmationConfig } from '@/core/types/signer-worker';
import type { WebAuthnAuthenticationCredential } from '@/core/types';
import type { RegistrationCredentialConfirmationPayload } from '../../workerManager/validation';
import type { WebAuthnAllowCredential } from '../../walletAuth/webauthn/credentials/collectAuthenticationCredentialForChallengeB64u';
import type { RegistrationSessionDeps } from '../../interfaces/operationDeps';

export async function requestRegistrationSessionCredentialConfirmation(
  deps: RegistrationSessionDeps,
  params: {
    nearAccountId: string;
    signerSlot: number;
    confirmerText?: { title?: string; body?: string };
    confirmationConfigOverride?: Partial<ConfirmationConfig>;
  },
): Promise<RegistrationCredentialConfirmationPayload> {
  return await deps.touchConfirm.requestRegistrationCredentialConfirmation({
    nearAccountId: params.nearAccountId,
    signerSlot: params.signerSlot,
    confirmerText: params.confirmerText,
    confirmationConfigOverride: params.confirmationConfigOverride,
    nearRpcUrl: deps.nearRpcUrl,
  });
}

export async function getAuthenticationCredentialsSerialized(
  deps: RegistrationSessionDeps,
  params: {
    nearAccountId: AccountId;
    challengeB64u: string;
    allowCredentials: WebAuthnAllowCredential[];
    includeSecondPrfOutput?: boolean;
  },
): Promise<WebAuthnAuthenticationCredential> {
  return await deps.touchIdPrompt.getAuthenticationCredentialsSerializedForChallengeB64u({
    nearAccountId: params.nearAccountId,
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
    nearAccountId: AccountId;
    challengeB64u: string;
    credentialIds: string[];
  },
): Promise<WebAuthnAuthenticationCredential> {
  return await deps.touchIdPrompt.getAuthenticationCredentialsSerializedForChallengeB64u({
    nearAccountId: params.nearAccountId,
    challengeB64u: params.challengeB64u,
    allowCredentials: toAllowCredentials(params.credentialIds),
    includeSecondPrfOutput: true,
  });
}
