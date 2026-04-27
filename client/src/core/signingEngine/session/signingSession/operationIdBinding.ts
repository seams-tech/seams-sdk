import type { SigningOperationFingerprint, SigningOperationId } from './types';

const MAX_BOUND_CALLER_OPERATION_IDS = 1024;

export type SigningOperationIdBindingState = {
  callerProvidedOperationFingerprintsById: Map<string, string>;
};

export type SigningOperationIdFingerprintBinder = {
  bindCallerProvidedOperationIdToFingerprint(args: {
    operationId: SigningOperationId;
    operationFingerprint: SigningOperationFingerprint;
  }): void;
};

export function bindCallerProvidedSigningOperationIdToFingerprint(args: {
  state: SigningOperationIdBindingState;
  operationId: SigningOperationId;
  operationFingerprint: SigningOperationFingerprint;
}): void {
  const operationId = String(args.operationId || '').trim();
  const fingerprint = String(args.operationFingerprint || '').trim();
  if (!operationId) throw new Error('[SigningEngine] signingOperationId is required');
  if (!fingerprint) throw new Error('[SigningEngine] operation fingerprint is required');

  const bindings = args.state.callerProvidedOperationFingerprintsById;
  const existingFingerprint = bindings.get(operationId);
  if (existingFingerprint && existingFingerprint !== fingerprint) {
    throw new Error(
      `[SigningEngine] caller-provided signingOperationId reused for a different operation: ${operationId}`,
    );
  }

  bindings.set(operationId, fingerprint);
  trimOldestBoundCallerOperationIds(bindings);
}

function trimOldestBoundCallerOperationIds(bindings: Map<string, string>): void {
  while (bindings.size > MAX_BOUND_CALLER_OPERATION_IDS) {
    const oldest = bindings.keys().next().value;
    if (!oldest) return;
    bindings.delete(oldest);
  }
}
