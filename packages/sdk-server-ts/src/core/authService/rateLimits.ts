import { toOptionalTrimmedString } from '@shared/utils/validation';
import {
  resolveSigningSessionSealRateLimitFromEnv,
  type SigningSessionSealRateLimiter,
} from '../../threshold/session/signingSessionSeal';
import type { AuthServiceConfigSource } from './configValues';
import { readAuthServiceConfigValue } from './configValues';
import type {
  AuthRateLimitPolicy,
  EmailOtpRateLimitPolicies,
  EmailOtpRateLimitScope,
} from './emailOtpConfig';

export type RateLimitResult =
  | { ok: true }
  | {
      ok: false;
      code: 'rate_limited';
      message: string;
      retryAfterMs?: number;
      resetAtMs?: number;
    };

type SigningSessionSealRateLimiterKind = 'in-memory' | 'upstash-redis-rest' | 'redis-tcp';

function readRateLimitConfigValue(input: {
  thresholdStore: AuthServiceConfigSource;
  name: string;
}): string {
  return readAuthServiceConfigValue({
    thresholdStore: input.thresholdStore,
    name: input.name,
  });
}

function parseRateLimiterKind(input: {
  raw: string;
  name: string;
}): SigningSessionSealRateLimiterKind | null {
  const value = toOptionalTrimmedString(input.raw).toLowerCase();
  if (!value) return null;
  switch (value) {
    case 'in-memory':
    case 'upstash-redis-rest':
    case 'redis-tcp':
      return value;
  }
  throw new Error(`${input.name} must be one of in-memory, upstash-redis-rest, or redis-tcp`);
}

export function createRegistrationPrepareRateLimiter(input: {
  thresholdStore: AuthServiceConfigSource;
}): SigningSessionSealRateLimiter {
  const thresholdStore = input.thresholdStore;
  return resolveSigningSessionSealRateLimitFromEnv({
    limiterKind: parseRateLimiterKind({
      raw: readRateLimitConfigValue({
        thresholdStore,
        name: 'REGISTRATION_PREPARE_RATE_LIMITER_KIND',
      }),
      name: 'REGISTRATION_PREPARE_RATE_LIMITER_KIND',
    }),
    upstashUrl:
      readRateLimitConfigValue({
        thresholdStore,
        name: 'REGISTRATION_PREPARE_RATE_LIMIT_UPSTASH_URL',
      }) || null,
    upstashToken:
      readRateLimitConfigValue({
        thresholdStore,
        name: 'REGISTRATION_PREPARE_RATE_LIMIT_UPSTASH_TOKEN',
      }) || null,
    redisUrl:
      readRateLimitConfigValue({
        thresholdStore,
        name: 'REGISTRATION_PREPARE_RATE_LIMIT_REDIS_URL',
      }) || null,
    keyPrefix:
      readRateLimitConfigValue({
        thresholdStore,
        name: 'REGISTRATION_PREPARE_RATE_LIMIT_KEY_PREFIX',
      }) || 'registration-prepare:v1:',
    limit: 1,
    windowMs: 1,
  }).limiter;
}

export function createEmailOtpRateLimiter(input: {
  thresholdStore: AuthServiceConfigSource;
}): SigningSessionSealRateLimiter {
  const thresholdStore = input.thresholdStore;
  return resolveSigningSessionSealRateLimitFromEnv({
    limiterKind: parseRateLimiterKind({
      raw: readRateLimitConfigValue({
        thresholdStore,
        name: 'EMAIL_OTP_RATE_LIMITER_KIND',
      }),
      name: 'EMAIL_OTP_RATE_LIMITER_KIND',
    }),
    upstashUrl:
      readRateLimitConfigValue({
        thresholdStore,
        name: 'EMAIL_OTP_RATE_LIMIT_UPSTASH_URL',
      }) || null,
    upstashToken:
      readRateLimitConfigValue({
        thresholdStore,
        name: 'EMAIL_OTP_RATE_LIMIT_UPSTASH_TOKEN',
      }) || null,
    redisUrl:
      readRateLimitConfigValue({
        thresholdStore,
        name: 'EMAIL_OTP_RATE_LIMIT_REDIS_URL',
      }) || null,
    keyPrefix:
      readRateLimitConfigValue({
        thresholdStore,
        name: 'EMAIL_OTP_RATE_LIMIT_KEY_PREFIX',
      }) || 'email-otp:v2:',
    limit: 1,
    windowMs: 1,
  }).limiter;
}

function consumedRateLimitError(
  message: string,
  consumed: { retryAfterMs?: number; resetAtMs?: number },
): RateLimitResult {
  const result: {
    ok: false;
    code: 'rate_limited';
    message: string;
    retryAfterMs?: number;
    resetAtMs?: number;
  } = {
    ok: false,
    code: 'rate_limited',
    message,
  };
  if (typeof consumed.retryAfterMs === 'number') result.retryAfterMs = consumed.retryAfterMs;
  if (typeof consumed.resetAtMs === 'number') result.resetAtMs = consumed.resetAtMs;
  return result;
}

export async function consumeEmailOtpRateLimit(input: {
  limiter: SigningSessionSealRateLimiter;
  policies: EmailOtpRateLimitPolicies;
  scope: EmailOtpRateLimitScope;
  action?: string;
  userId?: string;
  walletId?: string;
  providerSubject?: string;
  orgId?: string;
  clientIp?: string;
}): Promise<RateLimitResult> {
  const policy = input.policies[input.scope];
  const keySuffix = `scope=${input.scope}:action=${input.action || 'default'}:limit=${policy.limit}:windowMs=${policy.windowMs}`;
  const keys = [
    input.clientIp ? `${keySuffix}:ip:${input.clientIp}` : '',
    input.userId ? `${keySuffix}:user:${input.userId}` : '',
    input.walletId ? `${keySuffix}:wallet:${input.walletId}` : '',
    input.providerSubject ? `${keySuffix}:providerSubject:${input.providerSubject}` : '',
    input.orgId ? `${keySuffix}:org:${input.orgId}` : '',
  ].filter(Boolean);
  for (const key of keys) {
    const consumed = await input.limiter.consume({
      key,
      limit: policy.limit,
      windowMs: policy.windowMs,
      nowMs: Date.now(),
    });
    if (!consumed.ok) return consumedRateLimitError('Email OTP rate limit exceeded', consumed);
  }
  return { ok: true };
}
