import type { ConfirmationConfig } from '@/core/types/signer-worker';
import type { TouchConfirmContext } from '../../';
import {
  UserConfirmationType,
  type RegistrationSummary,
  type UserConfirmRequest,
} from '../../shared/confirmTypes';
import {
  parseAndValidateRegistrationCredentialConfirmationPayload,
  type RegistrationCredentialConfirmationPayload,
} from '@/core/signingEngine/workerManager/validation';

function resolveRequestUserConfirmation(ctx: TouchConfirmContext) {
  if (typeof ctx.requestUserConfirmation === 'function') {
    return ctx.requestUserConfirmation;
  }
  const manager = (ctx as TouchConfirmContext & {
    touchConfirmManager?: { requestUserConfirmation?: TouchConfirmContext['requestUserConfirmation'] };
  }).touchConfirmManager;
  if (manager && typeof manager.requestUserConfirmation === 'function') {
    return manager.requestUserConfirmation.bind(manager);
  }
  return null;
}

export async function requestRegistrationCredentialConfirmation({
  ctx,
  nearAccountId,
  deviceNumber,
  confirmerText,
  nearRpcUrl,
  confirmationConfig,
}: {
  ctx: TouchConfirmContext,
  nearAccountId: string,
  deviceNumber: number,
  confirmerText?: { title?: string; body?: string };
  nearRpcUrl: string,
  confirmationConfig?: Partial<ConfirmationConfig>,
}): Promise<RegistrationCredentialConfirmationPayload> {
  const requestUserConfirmation = resolveRequestUserConfirmation(ctx);
  if (typeof requestUserConfirmation !== 'function') {
    throw new Error('UserConfirm request bridge is unavailable (worker handshake path only)');
  }

  if (!nearRpcUrl) {
    throw new Error('nearRpcUrl is required for registration confirmation');
  }

  const requestId = (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function')
    ? crypto.randomUUID()
    : `register-${Date.now()}-${Math.random().toString(16).slice(2)}`;

  const title = confirmerText?.title;
  const body = confirmerText?.body;
  const request: UserConfirmRequest<{
    nearAccountId: string;
    deviceNumber: number;
    rpcCall: { nearRpcUrl: string; nearAccountId: string };
  }, RegistrationSummary> = {
    requestId,
    type: UserConfirmationType.REGISTER_ACCOUNT,
    summary: {
      nearAccountId,
      deviceNumber,
      ...(title != null ? { title } : {}),
      ...(body != null ? { body } : {}),
    },
    payload: {
      nearAccountId,
      deviceNumber,
      rpcCall: {
        nearRpcUrl,
        nearAccountId,
      },
    },
    confirmationConfig,
    intentDigest: `register:${nearAccountId}:${deviceNumber}`,
  };

  const decision = await requestUserConfirmation(request);

  if (!decision.confirmed) {
    throw new Error(decision.error || 'User rejected registration request');
  }
  if (!decision.credential) {
    throw new Error('Missing credential from registration confirmation');
  }
  if (!decision.transactionContext) {
    throw new Error('Missing transactionContext from registration confirmation');
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
