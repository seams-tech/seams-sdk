import type {
  SigningOperationFingerprint,
  SigningOperationId,
} from '../operationState/types';

const MAX_BOUND_CALLER_OPERATION_IDS = 1024;

export type SigningOperationIdFingerprintBinder = {
  bindCallerProvidedOperationIdToFingerprint(args: {
    operationId: SigningOperationId;
    operationFingerprint: SigningOperationFingerprint;
  }): void;
};

type SigningOperationIdBindingRegistryState = {
  callerProvidedOperationFingerprintsById: Map<string, string>;
};

function bindCallerProvidedSigningOperationIdToFingerprint(args: {
  state: SigningOperationIdBindingRegistryState;
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

export class SigningOperationIdBindingRegistry
  implements SigningOperationIdFingerprintBinder
{
  private readonly state: SigningOperationIdBindingRegistryState = {
    callerProvidedOperationFingerprintsById: new Map(),
  };

  bindCallerProvidedOperationIdToFingerprint(args: {
    operationId: SigningOperationId;
    operationFingerprint: SigningOperationFingerprint;
  }): void {
    bindCallerProvidedSigningOperationIdToFingerprint({
      state: this.state,
      operationId: args.operationId,
      operationFingerprint: args.operationFingerprint,
    });
  }
}

function trimOldestBoundCallerOperationIds(bindings: Map<string, string>): void {
  while (bindings.size > MAX_BOUND_CALLER_OPERATION_IDS) {
    const oldest = bindings.keys().next().value;
    if (!oldest) return;
    bindings.delete(oldest);
  }
}
