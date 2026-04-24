import {
  SigningSessionIds,
  type SigningOperationId,
} from '../../session/signingSessionTypes';

export type EvmFamilySigningOperationIds = {
  planningOperationId: SigningOperationId;
  confirmationOperationId?: SigningOperationId;
};

function createEvmFamilySigningOperationId(): SigningOperationId {
  const cryptoObj = globalThis as { crypto?: { randomUUID?: () => string } };
  const randomId =
    typeof cryptoObj.crypto?.randomUUID === 'function'
      ? cryptoObj.crypto.randomUUID()
      : `${Date.now().toString(36)}-${Math.random().toString(36).slice(2)}`;
  return SigningSessionIds.signingOperation(`evm-family-sign:${randomId}`);
}

export function createEvmFamilySigningOperationIds(
  providedOperationId?: SigningOperationId,
): EvmFamilySigningOperationIds {
  if (providedOperationId) {
    return {
      planningOperationId: providedOperationId,
      confirmationOperationId: providedOperationId,
    };
  }
  return {
    planningOperationId: createEvmFamilySigningOperationId(),
  };
}

export function ensureEvmFamilyConfirmationOperationId(
  operationIds: EvmFamilySigningOperationIds,
): SigningOperationId {
  operationIds.confirmationOperationId =
    operationIds.confirmationOperationId || createEvmFamilySigningOperationId();
  return operationIds.confirmationOperationId;
}
