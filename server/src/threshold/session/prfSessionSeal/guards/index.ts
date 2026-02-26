import type {
  PrfSessionSealGuard,
  PrfSessionSealGuardInput,
  PrfSessionSealGuardResult,
} from '../types';

export function composePrfSessionSealGuards(
  ...guards: Array<PrfSessionSealGuard | null | undefined>
): PrfSessionSealGuard {
  const list = guards.filter(Boolean) as PrfSessionSealGuard[];
  if (list.length === 0) {
    return async (): Promise<PrfSessionSealGuardResult> => ({ ok: true });
  }
  if (list.length === 1) {
    const [single] = list;
    return async (input: PrfSessionSealGuardInput): Promise<PrfSessionSealGuardResult> =>
      await single(input);
  }

  return async (input: PrfSessionSealGuardInput): Promise<PrfSessionSealGuardResult> => {
    for (const guard of list) {
      const result = await guard(input);
      if (!result.ok) return result;
    }
    return { ok: true };
  };
}

export interface PrfSessionSealRateLimitConsumeInput {
  key: string;
  limit: number;
  windowMs: number;
  nowMs: number;
}

export type PrfSessionSealRateLimitConsumeResult =
  | { ok: true; remaining: number; resetAtMs: number }
  | {
      ok: false;
      code?: string;
      message?: string;
      remaining?: number;
      resetAtMs?: number;
      retryAfterMs?: number;
    };

export interface PrfSessionSealRateLimiter {
  consume(
    input: PrfSessionSealRateLimitConsumeInput,
  ): Promise<PrfSessionSealRateLimitConsumeResult> | PrfSessionSealRateLimitConsumeResult;
}

export interface InMemoryPrfSessionSealRateLimiterOptions {
  maxEntries?: number;
}

type Bucket = { count: number; resetAtMs: number };

class InMemoryPrfSessionSealRateLimiter implements PrfSessionSealRateLimiter {
  private readonly maxEntries: number;
  private readonly buckets = new Map<string, Bucket>();

  constructor(options: InMemoryPrfSessionSealRateLimiterOptions = {}) {
    const configuredMaxEntries = Number(options.maxEntries);
    this.maxEntries = Number.isFinite(configuredMaxEntries) && configuredMaxEntries > 0
      ? Math.floor(configuredMaxEntries)
      : 10_000;
  }

  private trim(nowMs: number): void {
    if (this.buckets.size <= this.maxEntries) return;
    for (const [key, bucket] of this.buckets) {
      if (bucket.resetAtMs <= nowMs) {
        this.buckets.delete(key);
      }
      if (this.buckets.size <= this.maxEntries) return;
    }
    while (this.buckets.size > this.maxEntries) {
      const oldestKey = this.buckets.keys().next().value;
      if (oldestKey === undefined) return;
      this.buckets.delete(oldestKey);
    }
  }

  consume(input: PrfSessionSealRateLimitConsumeInput): PrfSessionSealRateLimitConsumeResult {
    const nowMs = Math.floor(Number(input.nowMs) || 0);
    const limit = Math.max(1, Math.floor(Number(input.limit) || 0));
    const windowMs = Math.max(1, Math.floor(Number(input.windowMs) || 0));
    const key = String(input.key || '').trim();
    if (!key) {
      return { ok: false, code: 'invalid_rate_limit_key', message: 'Rate-limit key is required' };
    }

    const existing = this.buckets.get(key);
    const bucket = !existing || existing.resetAtMs <= nowMs
      ? { count: 0, resetAtMs: nowMs + windowMs }
      : existing;
    bucket.count += 1;
    this.buckets.set(key, bucket);

    this.trim(nowMs);

    const remaining = Math.max(0, limit - bucket.count);
    if (bucket.count > limit) {
      const retryAfterMs = Math.max(0, bucket.resetAtMs - nowMs);
      return {
        ok: false,
        code: 'rate_limited',
        message: 'Rate limit exceeded',
        remaining: 0,
        resetAtMs: bucket.resetAtMs,
        retryAfterMs,
      };
    }

    return { ok: true, remaining, resetAtMs: bucket.resetAtMs };
  }
}

export interface PrfSessionSealRateLimitRejectedEvent {
  input: PrfSessionSealGuardInput;
  key: string;
  limit: number;
  windowMs: number;
  retryAfterMs?: number;
  resetAtMs?: number;
}

export interface CreatePrfSessionSealRateLimitGuardOptions {
  limiter: PrfSessionSealRateLimiter;
  limit: number;
  windowMs: number;
  keyPrefix?: string;
  keyBy?: (input: PrfSessionSealGuardInput) => string;
  nowMs?: () => number;
  onRejected?: (
    event: PrfSessionSealRateLimitRejectedEvent,
  ) => Promise<void> | void;
}

function coercePositiveInt(value: unknown, fallback: number): number {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) return fallback;
  return Math.floor(parsed);
}

function defaultKey(input: PrfSessionSealGuardInput): string {
  return `${input.auth.userId}:${input.thresholdSessionId}:${input.operation}`;
}

export function createInMemoryPrfSessionSealRateLimiter(
  options: InMemoryPrfSessionSealRateLimiterOptions = {},
): PrfSessionSealRateLimiter {
  return new InMemoryPrfSessionSealRateLimiter(options);
}

export function createPrfSessionSealRateLimitGuard(
  options: CreatePrfSessionSealRateLimitGuardOptions,
): PrfSessionSealGuard {
  const limit = coercePositiveInt(options.limit, 0);
  const windowMs = coercePositiveInt(options.windowMs, 0);
  if (limit <= 0) {
    throw new Error('createPrfSessionSealRateLimitGuard requires limit > 0');
  }
  if (windowMs <= 0) {
    throw new Error('createPrfSessionSealRateLimitGuard requires windowMs > 0');
  }
  const keyPrefix = String(options.keyPrefix || 'prf-seal').trim();
  const keyBy = options.keyBy || defaultKey;
  const nowMs = options.nowMs || Date.now;

  return async (input): Promise<PrfSessionSealGuardResult> => {
    const scopedKey = String(keyBy(input) || '').trim();
    const key = keyPrefix ? `${keyPrefix}:${scopedKey}` : scopedKey;
    const consumed = await options.limiter.consume({
      key,
      limit,
      windowMs,
      nowMs: nowMs(),
    });
    if (consumed.ok) return { ok: true };

    if (options.onRejected) {
      try {
        await options.onRejected({
          input,
          key,
          limit,
          windowMs,
          retryAfterMs: consumed.retryAfterMs,
          resetAtMs: consumed.resetAtMs,
        });
      } catch {}
    }

    return {
      ok: false,
      code: String(consumed.code || 'rate_limited'),
      message: String(consumed.message || 'Too many requests'),
    };
  };
}
