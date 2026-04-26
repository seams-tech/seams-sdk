import type { SigningOperationFingerprint, SigningOperationId } from './signingSessionTypes';

const MAX_BOUND_CALLER_OPERATION_IDS = 1024;
const callerProvidedOperationFingerprintsById = new Map<string, string>();

export function bindCallerProvidedSigningOperationIdToFingerprint(args: {
  operationId: SigningOperationId;
  operationFingerprint: SigningOperationFingerprint;
}): void {
  const operationId = String(args.operationId || '').trim();
  const fingerprint = String(args.operationFingerprint || '').trim();
  if (!operationId) throw new Error('[SigningEngine] signingOperationId is required');
  if (!fingerprint) throw new Error('[SigningEngine] operation fingerprint is required');

  const existingFingerprint = callerProvidedOperationFingerprintsById.get(operationId);
  if (existingFingerprint && existingFingerprint !== fingerprint) {
    throw new Error(
      `[SigningEngine] caller-provided signingOperationId reused for a different operation: ${operationId}`,
    );
  }

  callerProvidedOperationFingerprintsById.set(operationId, fingerprint);
  trimOldestBoundCallerOperationIds();
}

function trimOldestBoundCallerOperationIds(): void {
  while (callerProvidedOperationFingerprintsById.size > MAX_BOUND_CALLER_OPERATION_IDS) {
    const oldest = callerProvidedOperationFingerprintsById.keys().next().value;
    if (!oldest) return;
    callerProvidedOperationFingerprintsById.delete(oldest);
  }
}
