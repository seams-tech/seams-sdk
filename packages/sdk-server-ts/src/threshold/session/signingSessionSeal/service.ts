import { base64UrlEncode } from '@shared/utils/encoders';
import { sha256BytesUtf8 } from '@shared/utils/digests';
import {
  parseRouterAbEcdsaHssWalletSessionClaims,
  parseRouterAbEd25519WalletSessionClaims,
} from '../../../core/ThresholdService/validation';
import type {
  CreateSigningSessionSealServiceOptions,
  SigningSessionSealCurve,
  SigningSessionSealConsumePolicy,
  SigningSessionSealConsumeUseResult,
  SigningSessionSealOperation,
  SigningSessionSealRouteResult,
  SigningSessionSealService,
  SigningSessionSealThresholdSessionRecord,
} from './signingSessionSeal.types';

const SIGNING_SESSION_SEAL_LOG_LABEL = '[threshold-signing-session-seal]';
const SIGNING_SESSION_SEAL_IDEMPOTENCY_TTL_MS_DEFAULT = 90_000;
const SIGNING_SESSION_SEAL_REPLAYABLE_ERROR_CODES = new Set([
  'expired',
  'exhausted',
  'forbidden',
  'not_found',
  'invalid_ciphertext',
  'invalid_key_version',
]);

function toMessage(input: unknown, defaultMessage: string): string {
  const value = String(input || '').trim();
  return value || defaultMessage;
}

function toCode(input: unknown, defaultCode: string): string {
  const value = String(input || '').trim();
  return value || defaultCode;
}

function toNonNegativeInt(value: unknown): number | undefined {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return undefined;
  return Math.max(0, Math.floor(parsed));
}

function toPositiveInt(value: unknown, defaultValue: number): number {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) return defaultValue;
  return Math.floor(parsed);
}

function isExpired(session: SigningSessionSealThresholdSessionRecord, nowMs: number): boolean {
  return !Number.isFinite(session.expiresAtMs) || session.expiresAtMs <= nowMs;
}

function shouldConsume(
  policy: SigningSessionSealConsumePolicy,
  operation: SigningSessionSealOperation,
): boolean {
  if (policy === 'always') return true;
  if (policy === 'apply-only') return operation === 'apply-server-seal';
  if (policy === 'remove-only') return operation === 'remove-server-seal';
  return false;
}

function mapConsumeFailure(input: SigningSessionSealConsumeUseResult & { ok: false }): {
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
  options: CreateSigningSessionSealServiceOptions;
  operation: SigningSessionSealOperation;
  thresholdSessionId: string;
  userId: string;
  result: SigningSessionSealRouteResult;
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
  options: CreateSigningSessionSealServiceOptions;
  operation: SigningSessionSealOperation;
  thresholdSessionId: string;
  userId: string;
  keyVersion?: string;
  metadata?: Record<string, unknown>;
}): void {
  const logger = input.options.logger;
  if (!logger) return;
  const metadataKeys = input.metadata ? Object.keys(input.metadata) : [];
  logger.info(`${SIGNING_SESSION_SEAL_LOG_LABEL} ${input.operation} request`, {
    operation: input.operation,
    thresholdSessionId: input.thresholdSessionId,
    userId: input.userId,
    ...(input.keyVersion ? { keyVersion: input.keyVersion } : {}),
    metadataKeys,
  });
}

function emitOperationResultLog(input: {
  options: CreateSigningSessionSealServiceOptions;
  operation: SigningSessionSealOperation;
  thresholdSessionId: string;
  userId: string;
  result: SigningSessionSealRouteResult;
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
    logger.info(`${SIGNING_SESSION_SEAL_LOG_LABEL} ${input.operation} success`, payload);
    return;
  }
  logger.warn(`${SIGNING_SESSION_SEAL_LOG_LABEL} ${input.operation} failure`, payload);
}

type SigningSessionSealRequestInput = {
  thresholdSessionId: string;
  ciphertext: string;
  keyVersion?: string;
  metadata?: Record<string, unknown>;
};

type SigningSessionSealAuthInput = {
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
  operation: SigningSessionSealOperation;
  request: SigningSessionSealRequestInput;
  auth: SigningSessionSealAuthInput;
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
    'signing-session-seal',
    operation,
    userId,
    thresholdSessionId,
    keyVersion || '_',
    ciphertextHash,
  ].join(':');
}

function shouldPersistIdempotentResult(result: SigningSessionSealRouteResult): boolean {
  if (result.ok) return true;
  return SIGNING_SESSION_SEAL_REPLAYABLE_ERROR_CODES.has(String(result.code || '').trim());
}

function hasSigningGrantBudgetClaim(auth: { claims: Record<string, unknown> }): boolean {
  return Boolean(String(auth.claims.signingGrantId || '').trim());
}

function parseCurveBoundWalletBudgetLookup(
  claims: Record<string, unknown>,
):
  | { curve: 'ecdsa'; signingGrantId: string; thresholdSessionId: string }
  | { curve: 'ed25519'; signingGrantId: string; thresholdSessionId: string }
  | null {
  const ecdsaClaims = parseRouterAbEcdsaHssWalletSessionClaims(claims);
  if (ecdsaClaims) {
    return {
      curve: 'ecdsa',
      signingGrantId: ecdsaClaims.signingGrantId,
      thresholdSessionId: ecdsaClaims.thresholdSessionId,
    };
  }
  const ed25519Claims = parseRouterAbEd25519WalletSessionClaims(claims);
  if (ed25519Claims) {
    return {
      curve: 'ed25519',
      signingGrantId: ed25519Claims.signingGrantId,
      thresholdSessionId: ed25519Claims.thresholdSessionId,
    };
  }
  return null;
}

function parseCurveBoundThresholdLookup(args: {
  claims: Record<string, unknown>;
  thresholdSessionId: string;
}): { curve: SigningSessionSealCurve; thresholdSessionId: string } | null {
  const requestedThresholdSessionId = String(args.thresholdSessionId || '').trim();
  if (!requestedThresholdSessionId) return null;
  const ecdsaClaims = parseRouterAbEcdsaHssWalletSessionClaims(args.claims);
  if (ecdsaClaims) {
    return ecdsaClaims.thresholdSessionId === requestedThresholdSessionId
      ? {
          curve: 'ecdsa',
          thresholdSessionId: requestedThresholdSessionId,
        }
      : null;
  }
  const ed25519Claims = parseRouterAbEd25519WalletSessionClaims(args.claims);
  if (ed25519Claims) {
    return ed25519Claims.thresholdSessionId === requestedThresholdSessionId
      ? {
          curve: 'ed25519',
          thresholdSessionId: requestedThresholdSessionId,
        }
      : null;
  }
  return null;
}

async function resolveBudgetStatusForSealOperation(input: {
  options: CreateSigningSessionSealServiceOptions;
  auth: { userId: string; claims: Record<string, unknown> };
  fallbackSession: SigningSessionSealThresholdSessionRecord;
  nowMs: number;
}): Promise<
  | { ok: true; remainingUses?: number; expiresAtMs: number }
  | { ok: false; code: string; message: string }
> {
  const walletBudgetLookup = parseCurveBoundWalletBudgetLookup(input.auth.claims);
  if (!walletBudgetLookup) {
    return {
      ok: true,
      remainingUses: toNonNegativeInt(input.fallbackSession.remainingUses),
      expiresAtMs: input.fallbackSession.expiresAtMs,
    };
  }
  if (!input.options.sessionPolicy.getWalletBudgetStatus) {
    return {
      ok: false,
      code: 'not_configured',
      message: 'wallet signing-session status is not configured',
    };
  }
  const walletStatus = await input.options.sessionPolicy.getWalletBudgetStatus(walletBudgetLookup);
  if (!walletStatus) {
    return {
      ok: false,
      code: 'not_found',
      message: 'wallet signing session not found',
    };
  }
  if (walletStatus.userId !== input.auth.userId) {
    return {
      ok: false,
      code: 'forbidden',
      message: 'wallet signing session does not belong to authenticated user',
    };
  }
  if (isExpired(walletStatus, input.nowMs)) {
    return {
      ok: false,
      code: 'expired',
      message: 'wallet signing session expired',
    };
  }
  const remainingUses = toNonNegativeInt(walletStatus.remainingUses) ?? 0;
  if (remainingUses <= 0) {
    return {
      ok: false,
      code: 'exhausted',
      message: 'wallet signing session exhausted',
    };
  }
  return {
    ok: true,
    remainingUses,
    expiresAtMs: Math.min(input.fallbackSession.expiresAtMs, walletStatus.expiresAtMs),
  };
}

async function runSealOperation(input: {
  options: CreateSigningSessionSealServiceOptions;
  operation: SigningSessionSealOperation;
  request: {
    thresholdSessionId: string;
    ciphertext: string;
    keyVersion?: string;
    metadata?: Record<string, unknown>;
  };
  auth: { userId: string; claims: Record<string, unknown> };
}): Promise<SigningSessionSealRouteResult> {
  const nowMs = input.options.nowMs || Date.now;
  const startedAtMs = nowMs();
  let result: SigningSessionSealRouteResult = {
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

    const thresholdLookup = parseCurveBoundThresholdLookup({
      claims: input.auth.claims,
      thresholdSessionId: input.request.thresholdSessionId,
    });
    if (!thresholdLookup) {
      result = {
        ok: false,
        code: 'forbidden',
        message: 'Wallet Session does not match requested thresholdSessionId',
      };
      return result;
    }

    const session = await input.options.sessionPolicy.getThresholdSession(thresholdLookup);
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

    const budgetStatus = await resolveBudgetStatusForSealOperation({
      options: input.options,
      auth: input.auth,
      fallbackSession: session,
      nowMs: nowMs(),
    });
    if (!budgetStatus.ok) {
      result = budgetStatus;
      return result;
    }

    let remainingUses = budgetStatus.remainingUses;
    let expiresAtMs = budgetStatus.expiresAtMs;
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
      const consumed = await input.options.sessionPolicy.consumeUseCount(thresholdLookup);
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
        message: toMessage(sealed.message, 'Signing-session seal operation failed'),
      };
      return result;
    }

    result = {
      ok: true,
      ciphertext: sealed.ciphertext,
      keyVersion: sealed.keyVersion || input.request.keyVersion,
      expiresAtMs,
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

export function createSigningSessionSealService(
  options: CreateSigningSessionSealServiceOptions,
): SigningSessionSealService {
  const singleFlight = new Map<string, Promise<SigningSessionSealRouteResult>>();
  const nowMs = options.nowMs || Date.now;
  const idempotencyStore = options.idempotency?.store;
  const idempotencyTtlMs = toPositiveInt(
    options.idempotency?.ttlMs,
    SIGNING_SESSION_SEAL_IDEMPOTENCY_TTL_MS_DEFAULT,
  );

  const tryReplayIdempotentResult = async (
    operation: SigningSessionSealOperation,
    thresholdSessionId: string,
    userId: string,
    idempotencyKey: string,
  ): Promise<SigningSessionSealRouteResult | null> => {
    if (!idempotencyStore || !idempotencyKey) return null;
    try {
      const replay = await idempotencyStore.get({
        key: idempotencyKey,
        nowMs: nowMs(),
      });
      if (!replay) return null;
      options.logger?.info(`${SIGNING_SESSION_SEAL_LOG_LABEL} idempotency_replay_hit`, {
        operation,
        thresholdSessionId,
        userId,
      });
      return replay;
    } catch (error: unknown) {
      options.logger?.warn(`${SIGNING_SESSION_SEAL_LOG_LABEL} idempotency_replay_error`, {
        operation,
        thresholdSessionId,
        userId,
        message: toMessage(error instanceof Error ? error.message : error, 'Unknown error'),
      });
      return null;
    }
  };

  const tryPersistIdempotentResult = async (
    operation: SigningSessionSealOperation,
    thresholdSessionId: string,
    userId: string,
    idempotencyKey: string,
    result: SigningSessionSealRouteResult,
  ): Promise<void> => {
    if (!idempotencyStore || !idempotencyKey) return;
    try {
      await idempotencyStore.set({
        key: idempotencyKey,
        result,
        expiresAtMs: nowMs() + idempotencyTtlMs,
      });
    } catch (error: unknown) {
      options.logger?.warn(`${SIGNING_SESSION_SEAL_LOG_LABEL} idempotency_persist_error`, {
        operation,
        thresholdSessionId,
        userId,
        message: toMessage(error instanceof Error ? error.message : error, 'Unknown error'),
      });
    }
  };

  const runWithSingleFlight = async (
    operation: SigningSessionSealOperation,
    request: SigningSessionSealRequestInput,
    auth: SigningSessionSealAuthInput,
  ): Promise<SigningSessionSealRouteResult> => {
    const operationKey = await makeOperationRequestKey({ operation, request, auth });
    const allowPersistentReplay = !hasSigningGrantBudgetClaim(auth);
    if (allowPersistentReplay) {
      const idempotentReplay = await tryReplayIdempotentResult(
        operation,
        request.thresholdSessionId,
        auth.userId,
        operationKey,
      );
      if (idempotentReplay) return idempotentReplay;
    }

    const runAndPersist = async (): Promise<SigningSessionSealRouteResult> => {
      const result = await runSealOperation({
        options,
        operation,
        request,
        auth,
      });
      if (allowPersistentReplay && shouldPersistIdempotentResult(result)) {
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
      options.logger?.info(`${SIGNING_SESSION_SEAL_LOG_LABEL} single_flight_hit`, {
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
