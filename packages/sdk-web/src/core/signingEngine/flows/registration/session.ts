import type { ConfirmationConfig } from '@/core/types/signer-worker';
import type { WebAuthnAuthenticationCredential } from '@/core/types';
import type { RegistrationCredentialConfirmationPayload } from '../../workerManager/validation';
import type { WebAuthnAllowCredential } from '../../webauthnAuth/credentials/collectAuthenticationCredentialForChallengeB64u';
import type { RegistrationSessionDeps } from '../../interfaces/operationDeps';
import type { WalletAddAuthMethodRegistrationOptions } from '@/core/rpcClients/relayer/walletRegistration';

export async function requestRegistrationSessionCredentialConfirmation(
  deps: RegistrationSessionDeps,
  params: {
    walletId: string;
    nearAccountId?: string;
    signerSlot: number;
    confirmerText?: { title?: string; body?: string };
    confirmationConfigOverride?: Partial<ConfirmationConfig>;
    challengeB64u?: string;
    registrationOptions?: WalletAddAuthMethodRegistrationOptions;
  },
): Promise<RegistrationCredentialConfirmationPayload> {
  return await deps.touchConfirm.requestRegistrationCredentialConfirmation({
    walletId: params.walletId,
    nearAccountId: params.nearAccountId,
    signerSlot: params.signerSlot,
    confirmerText: params.confirmerText,
    confirmationConfigOverride: params.confirmationConfigOverride,
    challengeB64u: params.challengeB64u,
    registrationOptions: params.registrationOptions,
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
