import type {
  CreatePrfSessionSealServiceOptions,
  PrfSessionSealConsumePolicy,
  PrfSessionSealConsumeUseResult,
  PrfSessionSealIdempotencyOptions,
  PrfSessionSealIdempotencyStore,
  PrfSessionSealOperation,
  PrfSessionSealRouteResult,
  PrfSessionSealService,
  PrfSessionSealThresholdSessionRecord,
} from './types';

const PRF_SEAL_LOG_LABEL = '[threshold-ecdsa-prf-seal]';

function toMessage(input: unknown, fallback: string): string {
  const value = String(input || '').trim();
  return value || fallback;
}

function toCode(input: unknown, fallback: string): string {
  const value = String(input || '').trim();
  return value || fallback;
}

function toNonNegativeInt(value: unknown): number | undefined {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return undefined;
  return Math.max(0, Math.floor(parsed));
}

function toPositiveInt(value: unknown, fallback: number): number {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) return fallback;
  return Math.max(1, Math.floor(parsed));
}

function toOptionalTrimmedString(value: unknown): string | undefined {
  const out = String(value || '').trim();
  return out || undefined;
}

function sleepMs(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, Math.max(0, Math.floor(ms)));
  });
}

function isExpired(session: PrfSessionSealThresholdSessionRecord, nowMs: number): boolean {
  return !Number.isFinite(session.expiresAtMs) || session.expiresAtMs <= nowMs;
}

function shouldConsume(
  policy: PrfSessionSealConsumePolicy,
  operation: PrfSessionSealOperation,
): boolean {
  if (policy === 'always') return true;
  if (policy === 'apply-only') return operation === 'apply-server-seal';
  if (policy === 'remove-only') return operation === 'remove-server-seal';
  return false;
}

function mapConsumeFailure(input: PrfSessionSealConsumeUseResult & { ok: false }): {
  code: string;
  message: string;
} {
  const code = toCode(input.code, 'unauthorized');
  const message = toMessage(input.message, 'Threshold session rejected');
  const lowered = message.toLowerCase();

  if (code === 'expired' || lowered.includes('expired')) {
    return { code: 'expired', message };
  }
  if (code === 'exhausted' || lowered.includes('exhaust')) {
    return { code: 'exhausted', message };
  }
  return { code, message };
}

async function emitAudit(input: {
  options: CreatePrfSessionSealServiceOptions;
  operation: PrfSessionSealOperation;
  thresholdSessionId: string;
  userId: string;
  result: PrfSessionSealRouteResult;
  startedAtMs: number;
  nowMs: () => number;
}): Promise<void> {
  if (!input.options.audit) return;
  try {
    await input.options.audit({
      operation: input.operation,
      thresholdSessionId: input.thresholdSessionId,
      userId: input.userId,
      ok: input.result.ok,
      ...(input.result.ok ? {} : { code: input.result.code }),
      durationMs: Math.max(0, input.nowMs() - input.startedAtMs),
    });
  } catch {}
}

function emitOperationRequestLog(input: {
  options: CreatePrfSessionSealServiceOptions;
  operation: PrfSessionSealOperation;
  thresholdSessionId: string;
  userId: string;
  keyVersion?: string;
  metadata?: Record<string, unknown>;
}): void {
  const logger = input.options.logger;
  if (!logger) return;
  const metadataKeys = input.metadata ? Object.keys(input.metadata) : [];
  logger.info(`${PRF_SEAL_LOG_LABEL} ${input.operation} request`, {
    operation: input.operation,
    thresholdSessionId: input.thresholdSessionId,
    userId: input.userId,
    ...(input.keyVersion ? { keyVersion: input.keyVersion } : {}),
    metadataKeys,
  });
}

function emitOperationResultLog(input: {
  options: CreatePrfSessionSealServiceOptions;
  operation: PrfSessionSealOperation;
  thresholdSessionId: string;
  userId: string;
  result: PrfSessionSealRouteResult;
  durationMs: number;
}): void {
  const logger = input.options.logger;
  if (!logger) return;
  const payload = {
    operation: input.operation,
    thresholdSessionId: input.thresholdSessionId,
    userId: input.userId,
    durationMs: input.durationMs,
    ...(input.result.ok
      ? {
          keyVersion: input.result.keyVersion,
          expiresAtMs: input.result.expiresAtMs,
          remainingUses: input.result.remainingUses,
        }
      : {
          code: input.result.code,
          message: input.result.message,
        }),
  };
  if (input.result.ok) {
    logger.info(`${PRF_SEAL_LOG_LABEL} ${input.operation} success`, payload);
    return;
  }
  logger.warn(`${PRF_SEAL_LOG_LABEL} ${input.operation} failure`, payload);
}

type PrfSessionSealRequestInput = {
  thresholdSessionId: string;
  ciphertext: string;
  keyVersion?: string;
  metadata?: Record<string, unknown>;
};

type PrfSessionSealAuthInput = {
  userId: string;
  claims: Record<string, unknown>;
};

function makeSingleFlightKey(args: {
  operation: PrfSessionSealOperation;
  request: PrfSessionSealRequestInput;
  auth: PrfSessionSealAuthInput;
}): string {
  const thresholdSessionId = String(args.request.thresholdSessionId || '').trim();
  const userId = String(args.auth.userId || '').trim();
  const ciphertext = String(args.request.ciphertext || '').trim();
  if (!thresholdSessionId || !userId || !ciphertext) return '';
  const keyVersion = String(args.request.keyVersion || '').trim();
  return [args.operation, userId, thresholdSessionId, keyVersion, ciphertext].join('|');
}

async function runSealOperation(input: {
  options: CreatePrfSessionSealServiceOptions;
  operation: PrfSessionSealOperation;
  request: {
    thresholdSessionId: string;
    ciphertext: string;
    keyVersion?: string;
    metadata?: Record<string, unknown>;
  };
  auth: { userId: string; claims: Record<string, unknown> };
}): Promise<PrfSessionSealRouteResult> {
  const nowMs = input.options.nowMs || Date.now;
  const startedAtMs = nowMs();
  let result: PrfSessionSealRouteResult = {
    ok: false,
    code: 'internal',
    message: 'Internal error',
  };

  try {
    const requiredRequestKeyVersion = toOptionalTrimmedString(input.options.requiredRequestKeyVersion);
    if (requiredRequestKeyVersion) {
      const requestKeyVersion = toOptionalTrimmedString(input.request.keyVersion);
      if (!requestKeyVersion) {
        result = {
          ok: false,
          code: 'invalid_args',
          message: 'keyVersion is required',
        };
        return result;
      }
      if (requestKeyVersion !== requiredRequestKeyVersion) {
        result = {
          ok: false,
          code: 'conflict',
          message: `keyVersion mismatch: expected "${requiredRequestKeyVersion}"`,
        };
        return result;
      }
    }

    const requiredRequestShamirPrimeB64u = toOptionalTrimmedString(
      input.options.requiredRequestShamirPrimeB64u,
    );
    if (requiredRequestShamirPrimeB64u) {
      const requestShamirPrimeB64u = toOptionalTrimmedString(
        (input.request.metadata as { clientShamirPrimeB64u?: unknown } | undefined)
          ?.clientShamirPrimeB64u,
      );
      if (!requestShamirPrimeB64u) {
        result = {
          ok: false,
          code: 'invalid_args',
          message: 'metadata.clientShamirPrimeB64u is required',
        };
        return result;
      }
      if (requestShamirPrimeB64u !== requiredRequestShamirPrimeB64u) {
        result = {
          ok: false,
          code: 'conflict',
          message: 'shamirPrimeB64u mismatch',
        };
        return result;
      }
    }

    emitOperationRequestLog({
      options: input.options,
      operation: input.operation,
      thresholdSessionId: input.request.thresholdSessionId,
      userId: input.auth.userId,
      keyVersion: input.request.keyVersion,
      metadata: input.request.metadata,
    });

    const session = await input.options.sessionPolicy.getSession(input.request.thresholdSessionId);
    if (!session) {
      result = {
        ok: false,
        code: 'not_found',
        message: 'Unknown or expired threshold session',
      };
      return result;
    }

    if (session.userId !== input.auth.userId) {
      result = {
        ok: false,
        code: 'forbidden',
        message: 'thresholdSessionId does not belong to authenticated user',
      };
      return result;
    }

    if (isExpired(session, nowMs())) {
      result = {
        ok: false,
        code: 'expired',
        message: 'threshold session expired',
      };
      return result;
    }

    if (input.options.guard) {
      const guard = await input.options.guard({
        operation: input.operation,
        thresholdSessionId: input.request.thresholdSessionId,
        auth: input.auth,
      });
      if (!guard.ok) {
        result = {
          ok: false,
          code: toCode(guard.code, 'forbidden'),
          message: toMessage(guard.message, 'Request rejected'),
        };
        return result;
      }
    }

    let remainingUses = toNonNegativeInt(session.remainingUses);
    const consumePolicy = input.options.consumePolicy || 'never';
    if (shouldConsume(consumePolicy, input.operation)) {
      if (!input.options.sessionPolicy.consumeUseCount) {
        result = {
          ok: false,
          code: 'not_implemented',
          message: 'consumeUseCount is required for selected consumePolicy',
        };
        return result;
      }
      const consumed = await input.options.sessionPolicy.consumeUseCount(
        input.request.thresholdSessionId,
      );
      if (!consumed.ok) {
        const mapped = mapConsumeFailure(consumed);
        result = { ok: false, code: mapped.code, message: mapped.message };
        return result;
      }
      remainingUses = toNonNegativeInt(consumed.remainingUses);
    }

    const sealed = await input.options.cipher.run({
      operation: input.operation,
      thresholdSessionId: input.request.thresholdSessionId,
      ciphertext: input.request.ciphertext,
      keyVersion: input.request.keyVersion,
      metadata: input.request.metadata,
      auth: input.auth,
    });
    if (!sealed.ok) {
      result = {
        ok: false,
        code: toCode(sealed.code, 'internal'),
        message: toMessage(sealed.message, 'PRF session seal operation failed'),
      };
      return result;
    }

    result = {
      ok: true,
      ciphertext: sealed.ciphertext,
      keyVersion: sealed.keyVersion || input.request.keyVersion,
      expiresAtMs: session.expiresAtMs,
      ...(remainingUses !== undefined ? { remainingUses } : {}),
    };
    return result;
  } catch (error: unknown) {
    result = {
      ok: false,
      code: 'internal',
      message: toMessage(error instanceof Error ? error.message : error, 'Internal error'),
    };
    return result;
  } finally {
    const durationMs = Math.max(0, nowMs() - startedAtMs);
    emitOperationResultLog({
      options: input.options,
      operation: input.operation,
      thresholdSessionId: input.request.thresholdSessionId,
      userId: input.auth.userId,
      result,
      durationMs,
    });
    await emitAudit({
      options: input.options,
      operation: input.operation,
      thresholdSessionId: input.request.thresholdSessionId,
      userId: input.auth.userId,
      result,
      startedAtMs,
      nowMs,
    });
  }
}

async function waitForIdempotencyResult(input: {
  store: PrfSessionSealIdempotencyStore;
  key: string;
  nowMs: () => number;
  waitForPendingMs: number;
  pollIntervalMs: number;
}): Promise<PrfSessionSealRouteResult | null> {
  const deadlineMs = input.nowMs() + Math.max(0, Math.floor(input.waitForPendingMs));
  while (input.nowMs() < deadlineMs) {
    const result = await input.store.getResult({
      key: input.key,
      nowMs: input.nowMs(),
    });
    if (result) return result;
    await sleepMs(input.pollIntervalMs);
  }
  return null;
}

export function createPrfSessionSealService(
  options: CreatePrfSessionSealServiceOptions,
): PrfSessionSealService {
  const singleFlight = new Map<string, Promise<PrfSessionSealRouteResult>>();
  const idempotency: PrfSessionSealIdempotencyOptions | undefined = options.idempotency;

  const runWithSingleFlight = async (
    operation: PrfSessionSealOperation,
    request: PrfSessionSealRequestInput,
    auth: PrfSessionSealAuthInput,
  ): Promise<PrfSessionSealRouteResult> => {
    const singleFlightKey = makeSingleFlightKey({ operation, request, auth });
    if (!singleFlightKey) {
      return await runSealOperation({
        options,
        operation,
        request,
        auth,
      });
    }

    const inFlight = singleFlight.get(singleFlightKey);
    if (inFlight) {
      options.logger?.info(`${PRF_SEAL_LOG_LABEL} single_flight_hit`, {
        operation,
        thresholdSessionId: request.thresholdSessionId,
        userId: auth.userId,
      });
      return await inFlight;
    }

    const runTask = async (): Promise<PrfSessionSealRouteResult> =>
      await runSealOperation({
        options,
        operation,
        request,
        auth,
      });
    const guardedTask = (async (): Promise<PrfSessionSealRouteResult> => {
      if (!idempotency) {
        return await runTask();
      }

      const pendingTtlMs = toPositiveInt(idempotency.pendingTtlMs, 5_000);
      const resultTtlMs = toPositiveInt(idempotency.resultTtlMs, 60_000);
      const waitForPendingMs = toPositiveInt(idempotency.waitForPendingMs, 2_000);
      const pollIntervalMs = toPositiveInt(idempotency.pollIntervalMs, 50);

      const begin = await idempotency.store.begin({
        key: singleFlightKey,
        nowMs: (options.nowMs || Date.now)(),
        pendingTtlMs,
      });
      if (!begin.acquired) {
        if (begin.result) {
          options.logger?.info(`${PRF_SEAL_LOG_LABEL} idempotency_hit`, {
            operation,
            thresholdSessionId: request.thresholdSessionId,
            userId: auth.userId,
          });
          return begin.result;
        }
        if (begin.pending) {
          const waited = await waitForIdempotencyResult({
            store: idempotency.store,
            key: singleFlightKey,
            nowMs: options.nowMs || Date.now,
            waitForPendingMs,
            pollIntervalMs,
          });
          if (waited) {
            options.logger?.info(`${PRF_SEAL_LOG_LABEL} idempotency_wait_hit`, {
              operation,
              thresholdSessionId: request.thresholdSessionId,
              userId: auth.userId,
            });
            return waited;
          }

          const retryBegin = await idempotency.store.begin({
            key: singleFlightKey,
            nowMs: (options.nowMs || Date.now)(),
            pendingTtlMs,
          });
          if (!retryBegin.acquired) {
            if (retryBegin.result) return retryBegin.result;
            return {
              ok: false,
              code: 'conflict',
              message: 'Equivalent PRF seal request is already in progress',
            };
          }
        }
      }

      const result = await runTask();
      await idempotency.store
        .complete({
          key: singleFlightKey,
          nowMs: (options.nowMs || Date.now)(),
          resultTtlMs,
          result,
        })
        .catch(() => undefined);
      return result;
    })().finally(() => {
      singleFlight.delete(singleFlightKey);
    });
    singleFlight.set(singleFlightKey, guardedTask);
    return await guardedTask;
  };

  return {
    applyServerSeal: async (request, auth) =>
      await runWithSingleFlight('apply-server-seal', request, auth),
    removeServerSeal: async (request, auth) =>
      await runWithSingleFlight('remove-server-seal', request, auth),
  };
}
