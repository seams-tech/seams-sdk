import { base64UrlEncode } from '@shared/utils/encoders';
import { sha256BytesUtf8 } from '@shared/utils/digests';
import type {
  CreatePrfSessionSealServiceOptions,
  PrfSessionSealConsumePolicy,
  PrfSessionSealConsumeUseResult,
  PrfSessionSealOperation,
  PrfSessionSealRouteResult,
  PrfSessionSealService,
  PrfSessionSealThresholdSessionRecord,
} from './types';

const PRF_SEAL_LOG_LABEL = '[threshold-ecdsa-prf-seal]';
const PRF_SEAL_IDEMPOTENCY_TTL_MS_DEFAULT = 90_000;
const PRF_SEAL_REPLAYABLE_ERROR_CODES = new Set([
  'expired',
  'exhausted',
  'forbidden',
  'not_found',
  'invalid_ciphertext',
  'invalid_key_version',
]);

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
  return Math.floor(parsed);
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

function fnv1aHex(input: string): string {
  let hash = 2166136261;
  for (let i = 0; i < input.length; i += 1) {
    hash ^= input.charCodeAt(i);
    hash = Math.imul(hash, 16777619);
  }
  return (hash >>> 0).toString(16).padStart(8, '0');
}

async function hashCiphertextForIdempotency(ciphertext: string): Promise<string> {
  const normalized = String(ciphertext || '').trim();
  if (!normalized) return '';
  try {
    const digest32 = await sha256BytesUtf8(normalized);
    return `sha256:${base64UrlEncode(digest32)}`;
  } catch {
    return `fnv1a:${fnv1aHex(normalized)}`;
  }
}

async function makeOperationRequestKey(args: {
  operation: PrfSessionSealOperation;
  request: PrfSessionSealRequestInput;
  auth: PrfSessionSealAuthInput;
}): Promise<string> {
  const thresholdSessionId = String(args.request.thresholdSessionId || '').trim();
  const userId = String(args.auth.userId || '').trim();
  const ciphertext = String(args.request.ciphertext || '').trim();
  if (!thresholdSessionId || !userId || !ciphertext) return '';
  const keyVersion = String(args.request.keyVersion || '').trim();
  const operation = args.operation === 'apply-server-seal' ? 'apply' : 'remove';
  const ciphertextHash = await hashCiphertextForIdempotency(ciphertext);
  if (!ciphertextHash) return '';
  return [
    'prfseal',
    operation,
    userId,
    thresholdSessionId,
    keyVersion || '_',
    ciphertextHash,
  ].join(':');
}

function shouldPersistIdempotentResult(result: PrfSessionSealRouteResult): boolean {
  if (result.ok) return true;
  return PRF_SEAL_REPLAYABLE_ERROR_CODES.has(String(result.code || '').trim());
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

export function createPrfSessionSealService(
  options: CreatePrfSessionSealServiceOptions,
): PrfSessionSealService {
  const singleFlight = new Map<string, Promise<PrfSessionSealRouteResult>>();
  const nowMs = options.nowMs || Date.now;
  const idempotencyStore = options.idempotency?.store;
  const idempotencyTtlMs = toPositiveInt(
    options.idempotency?.ttlMs,
    PRF_SEAL_IDEMPOTENCY_TTL_MS_DEFAULT,
  );

  const tryReplayIdempotentResult = async (
    operation: PrfSessionSealOperation,
    thresholdSessionId: string,
    userId: string,
    idempotencyKey: string,
  ): Promise<PrfSessionSealRouteResult | null> => {
    if (!idempotencyStore || !idempotencyKey) return null;
    try {
      const replay = await idempotencyStore.get({
        key: idempotencyKey,
        nowMs: nowMs(),
      });
      if (!replay) return null;
      options.logger?.info(`${PRF_SEAL_LOG_LABEL} idempotency_replay_hit`, {
        operation,
        thresholdSessionId,
        userId,
      });
      return replay;
    } catch (error: unknown) {
      options.logger?.warn(`${PRF_SEAL_LOG_LABEL} idempotency_replay_error`, {
        operation,
        thresholdSessionId,
        userId,
        message: toMessage(error instanceof Error ? error.message : error, 'Unknown error'),
      });
      return null;
    }
  };

  const tryPersistIdempotentResult = async (
    operation: PrfSessionSealOperation,
    thresholdSessionId: string,
    userId: string,
    idempotencyKey: string,
    result: PrfSessionSealRouteResult,
  ): Promise<void> => {
    if (!idempotencyStore || !idempotencyKey) return;
    try {
      await idempotencyStore.set({
        key: idempotencyKey,
        result,
        expiresAtMs: nowMs() + idempotencyTtlMs,
      });
    } catch (error: unknown) {
      options.logger?.warn(`${PRF_SEAL_LOG_LABEL} idempotency_persist_error`, {
        operation,
        thresholdSessionId,
        userId,
        message: toMessage(error instanceof Error ? error.message : error, 'Unknown error'),
      });
    }
  };

  const runWithSingleFlight = async (
    operation: PrfSessionSealOperation,
    request: PrfSessionSealRequestInput,
    auth: PrfSessionSealAuthInput,
  ): Promise<PrfSessionSealRouteResult> => {
    const operationKey = await makeOperationRequestKey({ operation, request, auth });
    const idempotentReplay = await tryReplayIdempotentResult(
      operation,
      request.thresholdSessionId,
      auth.userId,
      operationKey,
    );
    if (idempotentReplay) return idempotentReplay;

    const runAndPersist = async (): Promise<PrfSessionSealRouteResult> => {
      const result = await runSealOperation({
        options,
        operation,
        request,
        auth,
      });
      if (shouldPersistIdempotentResult(result)) {
        await tryPersistIdempotentResult(
          operation,
          request.thresholdSessionId,
          auth.userId,
          operationKey,
          result,
        );
      }
      return result;
    };

    if (!operationKey) {
      return await runAndPersist();
    }

    const inFlight = singleFlight.get(operationKey);
    if (inFlight) {
      options.logger?.info(`${PRF_SEAL_LOG_LABEL} single_flight_hit`, {
        operation,
        thresholdSessionId: request.thresholdSessionId,
        userId: auth.userId,
      });
      return await inFlight;
    }

    const task = runAndPersist().finally(() => {
      singleFlight.delete(operationKey);
    });
    singleFlight.set(operationKey, task);
    return await task;
  };

  return {
    applyServerSeal: async (request, auth) =>
      await runWithSingleFlight('apply-server-seal', request, auth),
    removeServerSeal: async (request, auth) =>
      await runWithSingleFlight('remove-server-seal', request, auth),
  };
}
