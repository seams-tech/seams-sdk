import {
  SigningSessionIds,
  type SigningOperationFingerprint,
  type SigningOperationId,
} from '../../session/signingSession/types';
import type { SigningOperationIdFingerprintBinder } from '../../session/planning/operationIdBinding';

export type EvmFamilySigningOperationIds = {
  planningOperationId: SigningOperationId;
  confirmationOperationId?: SigningOperationId;
  callerProvided: boolean;
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
      callerProvided: true,
    };
  }
  return {
    planningOperationId: createEvmFamilySigningOperationId(),
    callerProvided: false,
  };
}

export function ensureEvmFamilyConfirmationOperationId(
  operationIds: EvmFamilySigningOperationIds,
): SigningOperationId {
  operationIds.confirmationOperationId =
    operationIds.confirmationOperationId || createEvmFamilySigningOperationId();
  return operationIds.confirmationOperationId;
}

export function bindEvmFamilyCallerProvidedOperationIdToFingerprint(
  operationIds: EvmFamilySigningOperationIds,
  operationFingerprint: SigningOperationFingerprint,
  binder: SigningOperationIdFingerprintBinder,
): void {
  if (!operationIds.callerProvided) return;
  binder.bindCallerProvidedOperationIdToFingerprint({
    operationId: operationIds.planningOperationId,
    operationFingerprint,
  });
}
