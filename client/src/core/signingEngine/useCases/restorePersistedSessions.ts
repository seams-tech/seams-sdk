import {
  useCaseFailure,
  type NonEmptyReadonlyArray,
  type ReadyEcdsaLane,
  type ReadyEd25519Lane,
  type ReauthRequiredLane,
  type RestorePersistedSessionCleanup,
  type RestorePersistedSessionsFailureCode,
  type RestorePersistedSessionsInput,
  type RestorePersistedSessionsLifecycleState,
  type RestorePersistedSessionsResult,
  type RestorePersistedSessionsSuccess,
  type UseCaseFailure,
  type UseCaseWalletSessionReadiness,
} from './lifecycle';

export type RestorePersistedSessionsFailure = UseCaseFailure<RestorePersistedSessionsFailureCode>;

export type RestorePersistedSessionMaterial =
  | ReadyEd25519Lane
  | ReadyEcdsaLane
  | ReauthRequiredLane;

export type RestorePersistedSessionsReadResult =
  | {
      ok: true;
      material: readonly RestorePersistedSessionMaterial[];
      cleanup: readonly RestorePersistedSessionCleanup[];
      code?: never;
      message?: never;
      retryable?: never;
    }
  | UseCaseFailure<
      Extract<
        RestorePersistedSessionsFailureCode,
        'stale_persistence' | 'unavailable_storage' | 'malformed_record' | 'incompatible_record'
      >
    >;

export type RestorePersistedSessionsClassificationResult =
  | {
      ok: true;
      readiness: UseCaseWalletSessionReadiness;
      restored: readonly (ReadyEd25519Lane | ReadyEcdsaLane)[];
      reauthRequired: readonly ReauthRequiredLane[];
      cleanup: readonly RestorePersistedSessionCleanup[];
      code?: never;
      message?: never;
      retryable?: never;
    }
  | UseCaseFailure<
      Extract<
        RestorePersistedSessionsFailureCode,
        'seal_failed' | 'incompatible_record' | 'malformed_record' | 'invalid_state'
      >
    >;

export type RestorePersistedSessionsCleanupResult =
  | { ok: true; code?: never; message?: never; retryable?: never }
  | UseCaseFailure<Extract<RestorePersistedSessionsFailureCode, 'cleanup_failed'>>;

export type RestorePersistedSessionsDeps = {
  reader: {
    read(input: RestorePersistedSessionsInput): Promise<RestorePersistedSessionsReadResult>;
  };
  classifier: {
    classify(input: {
      input: RestorePersistedSessionsInput;
      material: readonly RestorePersistedSessionMaterial[];
      cleanup: readonly RestorePersistedSessionCleanup[];
    }): Promise<RestorePersistedSessionsClassificationResult>;
  };
  cleanup: {
    clean(
      input: NonEmptyReadonlyArray<RestorePersistedSessionCleanup>,
    ): Promise<RestorePersistedSessionsCleanupResult>;
  };
  lifecycle?: {
    transition(state: RestorePersistedSessionsLifecycleState): void | Promise<void>;
  };
};

export type RestorePersistedSessionsUseCase = {
  restore(input: RestorePersistedSessionsInput): Promise<RestorePersistedSessionsResult>;
};

export function createRestorePersistedSessionsUseCase(
  deps: RestorePersistedSessionsDeps,
): RestorePersistedSessionsUseCase {
  return {
    restore: (input) => restorePersistedSessions(deps, input),
  };
}

function toNonEmptyReadonlyArray<T>(items: readonly T[]): NonEmptyReadonlyArray<T> | null {
  const first = items[0];
  if (first === undefined) return null;
  return [first, ...items.slice(1)];
}

async function emit(
  deps: RestorePersistedSessionsDeps,
  state: RestorePersistedSessionsLifecycleState,
): Promise<void> {
  await deps.lifecycle?.transition(state);
}

async function emitFailure(
  deps: RestorePersistedSessionsDeps,
  result: RestorePersistedSessionsFailure,
): Promise<RestorePersistedSessionsFailure> {
  await emit(deps, {
    kind: 'failed',
    ok: false,
    code: result.code,
    source: result.source,
    message: result.message,
    retryable: result.retryable,
    ...(result.cause === undefined ? {} : { cause: result.cause }),
  });
  return result;
}

function invalidState(message: string): RestorePersistedSessionsFailure {
  return useCaseFailure({
    code: 'invalid_state',
    source: 'domain',
    message,
    retryable: false,
  });
}

export async function restorePersistedSessions(
  deps: RestorePersistedSessionsDeps,
  input: RestorePersistedSessionsInput,
): Promise<RestorePersistedSessionsResult> {
  await emit(deps, { kind: 'received_input', ...input });

  await emit(deps, { kind: 'reading_persistence', input });
  const read = await deps.reader.read(input);
  if (!read.ok) return emitFailure(deps, read);

  await emit(deps, {
    kind: 'classifying_material',
    input,
    material: read.material,
  });
  const classified = await deps.classifier.classify({
    input,
    material: read.material,
    cleanup: read.cleanup,
  });
  if (!classified.ok) return emitFailure(deps, classified);

  const cleanup = toNonEmptyReadonlyArray(classified.cleanup);
  if (cleanup) {
    await emit(deps, {
      kind: 'cleaning_stale_records',
      input,
      cleanup,
    });
    const cleaned = await deps.cleanup.clean(cleanup);
    if (!cleaned.ok) return emitFailure(deps, cleaned);
  }

  if (String(classified.readiness.walletId) !== String(input.walletId)) {
    return emitFailure(
      deps,
      invalidState('Restore classifier returned readiness for a different wallet'),
    );
  }

  const success: RestorePersistedSessionsSuccess = {
    ok: true,
    walletId: input.walletId,
    readiness: classified.readiness,
    restored: classified.restored,
    reauthRequired: classified.reauthRequired,
    cleanup: classified.cleanup,
  };
  await emit(deps, { kind: 'ready', result: success });
  return success;
}
