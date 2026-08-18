import {
  SigningSessionIds,
  type SigningOperationFingerprint,
  type SigningOperationId,
} from '../../session/operationState/types';
import { secureRandomBase64Url } from '@shared/utils/secureRandomId';
import type { SigningOperationIdFingerprintBinder } from '../../session/planning/operationIdBinding';

export type EvmFamilySigningOperationIds = {
  planningOperationId: SigningOperationId;
  confirmationOperationId?: SigningOperationId;
  callerProvided: boolean;
};

function createEvmFamilySigningOperationId(): SigningOperationId {
  const randomId = secureRandomBase64Url(32, 'EVM family signing operation IDs');
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
