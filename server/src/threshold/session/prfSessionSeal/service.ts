import type {
  CreatePrfSessionSealServiceOptions,
  PrfSessionSealConsumePolicy,
  PrfSessionSealConsumeUseResult,
  PrfSessionSealOperation,
  PrfSessionSealRouteResult,
  PrfSessionSealService,
  PrfSessionSealThresholdSessionRecord,
} from './types';

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
  return {
    applyServerSeal: async (request, auth) =>
      await runSealOperation({
        options,
        operation: 'apply-server-seal',
        request,
        auth,
      }),
    removeServerSeal: async (request, auth) =>
      await runSealOperation({
        options,
        operation: 'remove-server-seal',
        request,
        auth,
      }),
  };
}
