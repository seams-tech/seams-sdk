import type { ConfirmationConfig } from '@/core/types/signer-worker';
import { secureRandomId } from '@shared/utils/secureRandomId';
import {
  UserConfirmationType,
  type RegistrationSummary,
  type UserConfirmRequest,
} from '@/core/signingEngine/stepUpConfirmation/channel/confirmTypes';
import {
  parseAndValidateRegistrationCredentialConfirmationPayload,
  type RegistrationCredentialConfirmationPayload,
} from '@/core/signingEngine/workerManager/validation';
import type { UiConfirmSecureConfirmationPort } from '../../types';

export async function requestRegistrationCredentialConfirmation({
  touchConfirm,
  nearAccountId,
  signerSlot,
  confirmerText,
  confirmationConfig,
  challengeB64u,
}: {
  touchConfirm: Pick<UiConfirmSecureConfirmationPort, 'requestUserConfirmation'>;
  nearAccountId: string;
  signerSlot: number;
  confirmerText?: { title?: string; body?: string };
  confirmationConfig?: Partial<ConfirmationConfig>;
  challengeB64u?: string;
}): Promise<RegistrationCredentialConfirmationPayload> {
  if (typeof touchConfirm.requestUserConfirmation !== 'function') {
    throw new Error('UserConfirm manager request bridge is unavailable');
  }

  const requestId = secureRandomId('register', 32, 'registration credential confirmation IDs');

  const title = confirmerText?.title;
  const body = confirmerText?.body;
  const request: UserConfirmRequest<
    {
      nearAccountId: string;
      signerSlot: number;
    },
    RegistrationSummary
  > = {
    requestId,
    type: UserConfirmationType.REGISTER_ACCOUNT,
    summary: {
      nearAccountId,
      signerSlot,
      ...(title != null ? { title } : {}),
      ...(body != null ? { body } : {}),
    },
    payload: {
      nearAccountId,
      signerSlot,
      ...(challengeB64u
        ? {
            webauthnChallenge: {
              kind: 'intent_digest',
              challengeB64u,
            },
          }
        : {}),
    },
    confirmationConfig,
    intentDigest: `register:${nearAccountId}:${signerSlot}`,
  };

  const decision = await touchConfirm.requestUserConfirmation(request);

  if (!decision.confirmed) {
    throw new Error(decision.error || 'User rejected registration request');
  }
  if (!decision.credential) {
    throw new Error('Missing credential from registration confirmation');
  }

  return parseAndValidateRegistrationCredentialConfirmationPayload({
    confirmed: decision.confirmed,
    requestId,
    intentDigest: decision.intentDigest || '',
    credential: decision.credential,
    transactionContext: decision.transactionContext,
    error: decision.error,
  });
}
