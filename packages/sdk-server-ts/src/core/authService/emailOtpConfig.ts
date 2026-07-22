import type { AuthServiceConfigSource } from './configValues';
import { readAuthServiceConfigValue } from './configValues';

export type EmailOtpDeliveryMode = 'email_provider' | 'log' | 'memory';

export const EMAIL_OTP_CODE_LENGTH = 6 as const;

export type EmailOtpConfig = {
  deliveryMode: EmailOtpDeliveryMode;
  challengeTtlMs: number;
  grantTtlMs: number;
  maxAttempts: number;
  lockoutTtlMs: number;
  codeLength: typeof EMAIL_OTP_CODE_LENGTH;
  devOutboxEnabled: boolean;
  maxActiveChallengesPerContext: number;
};

export type AuthRateLimitPolicy = {
  limit: number;
  windowMs: number;
};

export type EmailOtpRateLimitScope =
  | 'challenge'
  | 'verify'
  | 'grant'
  | 'recoveryKeyAttempt'
  | 'googleRegistrationAttempt';

export type EmailOtpRateLimitPolicies = Record<EmailOtpRateLimitScope, AuthRateLimitPolicy>;

export type EmailOtpConfigInput = {
  thresholdStore: AuthServiceConfigSource;
  production: boolean;
};

function readEmailOtpConfigValue(input: EmailOtpConfigInput, name: string): string {
  return readAuthServiceConfigValue({ thresholdStore: input.thresholdStore, name });
}

export function parseConfiguredInteger(input: {
  name: string;
  raw: string;
  defaultValue: number;
  min: number;
  max: number;
}): number {
  const normalized = String(input.raw || '').trim();
  if (!normalized) return input.defaultValue;
  const n = Number(normalized);
  if (!Number.isFinite(n)) {
    throw new Error(`${input.name} must be a finite number`);
  }
  if (n < input.min || n > input.max) {
    throw new Error(`${input.name} must be between ${input.min} and ${input.max}`);
  }
  return Math.floor(n);
}

function parseEmailOtpDeliveryMode(raw: string): EmailOtpDeliveryMode {
  const deliveryModeRaw = raw.toLowerCase();
  if (!deliveryModeRaw) return 'memory';
  if (
    deliveryModeRaw === 'email_provider' ||
    deliveryModeRaw === 'log' ||
    deliveryModeRaw === 'memory'
  ) {
    return deliveryModeRaw;
  }
  throw new Error('EMAIL_OTP_DELIVERY_MODE must be one of email_provider, log, or memory');
}

function readBooleanFlag(input: EmailOtpConfigInput, name: string): string {
  const raw = readEmailOtpConfigValue(input, name);
  if (
    raw &&
    !['1', 'true', 'yes', 'on', '0', 'false', 'no', 'off'].includes(raw.toLowerCase())
  ) {
    throw new Error(`${name} must be a boolean flag when provided`);
  }
  return raw;
}

function isTruthyBooleanFlag(raw: string): boolean {
  return ['1', 'true', 'yes', 'on'].includes(raw.toLowerCase());
}

export function resolveRegistrationPrepareRateLimitPolicy(
  input: EmailOtpConfigInput,
): AuthRateLimitPolicy {
  const defaults = input.production
    ? { limit: 1, windowMs: 5_000 }
    : { limit: 100, windowMs: 60_000 };
  return {
    limit: parseConfiguredInteger({
      name: 'REGISTRATION_PREPARE_RATE_LIMIT_MAX',
      raw: readAuthServiceConfigValue({
        thresholdStore: input.thresholdStore,
        name: 'REGISTRATION_PREPARE_RATE_LIMIT_MAX',
      }),
      defaultValue: defaults.limit,
      min: 1,
      max: 10_000,
    }),
    windowMs: parseConfiguredInteger({
      name: 'REGISTRATION_PREPARE_RATE_LIMIT_WINDOW_MS',
      raw: readAuthServiceConfigValue({
        thresholdStore: input.thresholdStore,
        name: 'REGISTRATION_PREPARE_RATE_LIMIT_WINDOW_MS',
      }),
      defaultValue: defaults.windowMs,
      min: 1_000,
      max: 24 * 60 * 60_000,
    }),
  };
}

export function resolveEmailOtpRateLimitPolicies(
  input: EmailOtpConfigInput,
): EmailOtpRateLimitPolicies {
  const challengeDefault = input.production
    ? { limit: 30, windowMs: 60_000 }
    : { limit: 100, windowMs: 60_000 };
  const verifyDefault = input.production
    ? { limit: 30, windowMs: 60_000 }
    : { limit: 100, windowMs: 60_000 };
  const grantDefault = input.production
    ? { limit: 30, windowMs: 60_000 }
    : { limit: 100, windowMs: 60_000 };
  const recoveryKeyAttemptDefault = input.production
    ? { limit: 10, windowMs: 5 * 60_000 }
    : { limit: 100, windowMs: 60_000 };
  const googleRegistrationAttemptDefault = input.production
    ? { limit: 12, windowMs: 10 * 60_000 }
    : { limit: 200, windowMs: 60_000 };
  return {
    challenge: {
      limit: parseConfiguredInteger({
        name: 'EMAIL_OTP_CHALLENGE_RATE_LIMIT_MAX',
        raw: readEmailOtpConfigValue(input, 'EMAIL_OTP_CHALLENGE_RATE_LIMIT_MAX'),
        defaultValue: challengeDefault.limit,
        min: 1,
        max: 500,
      }),
      windowMs: parseConfiguredInteger({
        name: 'EMAIL_OTP_CHALLENGE_RATE_LIMIT_WINDOW_MS',
        raw: readEmailOtpConfigValue(input, 'EMAIL_OTP_CHALLENGE_RATE_LIMIT_WINDOW_MS'),
        defaultValue: challengeDefault.windowMs,
        min: 1_000,
        max: 24 * 60 * 60_000,
      }),
    },
    verify: {
      limit: parseConfiguredInteger({
        name: 'EMAIL_OTP_VERIFY_RATE_LIMIT_MAX',
        raw: readEmailOtpConfigValue(input, 'EMAIL_OTP_VERIFY_RATE_LIMIT_MAX'),
        defaultValue: verifyDefault.limit,
        min: 1,
        max: 1000,
      }),
      windowMs: parseConfiguredInteger({
        name: 'EMAIL_OTP_VERIFY_RATE_LIMIT_WINDOW_MS',
        raw: readEmailOtpConfigValue(input, 'EMAIL_OTP_VERIFY_RATE_LIMIT_WINDOW_MS'),
        defaultValue: verifyDefault.windowMs,
        min: 1_000,
        max: 24 * 60 * 60_000,
      }),
    },
    grant: {
      limit: parseConfiguredInteger({
        name: 'EMAIL_OTP_GRANT_RATE_LIMIT_MAX',
        raw: readEmailOtpConfigValue(input, 'EMAIL_OTP_GRANT_RATE_LIMIT_MAX'),
        defaultValue: grantDefault.limit,
        min: 1,
        max: 1000,
      }),
      windowMs: parseConfiguredInteger({
        name: 'EMAIL_OTP_GRANT_RATE_LIMIT_WINDOW_MS',
        raw: readEmailOtpConfigValue(input, 'EMAIL_OTP_GRANT_RATE_LIMIT_WINDOW_MS'),
        defaultValue: grantDefault.windowMs,
        min: 1_000,
        max: 24 * 60 * 60_000,
      }),
    },
    recoveryKeyAttempt: {
      limit: parseConfiguredInteger({
        name: 'EMAIL_OTP_RECOVERY_KEY_ATTEMPT_RATE_LIMIT_MAX',
        raw: readEmailOtpConfigValue(input, 'EMAIL_OTP_RECOVERY_KEY_ATTEMPT_RATE_LIMIT_MAX'),
        defaultValue: recoveryKeyAttemptDefault.limit,
        min: 1,
        max: 1000,
      }),
      windowMs: parseConfiguredInteger({
        name: 'EMAIL_OTP_RECOVERY_KEY_ATTEMPT_RATE_LIMIT_WINDOW_MS',
        raw: readEmailOtpConfigValue(input, 'EMAIL_OTP_RECOVERY_KEY_ATTEMPT_RATE_LIMIT_WINDOW_MS'),
        defaultValue: recoveryKeyAttemptDefault.windowMs,
        min: 1_000,
        max: 24 * 60 * 60_000,
      }),
    },
    googleRegistrationAttempt: {
      limit: parseConfiguredInteger({
        name: 'EMAIL_OTP_GOOGLE_REGISTRATION_ATTEMPT_RATE_LIMIT_MAX',
        raw: readEmailOtpConfigValue(input, 'EMAIL_OTP_GOOGLE_REGISTRATION_ATTEMPT_RATE_LIMIT_MAX'),
        defaultValue: googleRegistrationAttemptDefault.limit,
        min: 1,
        max: 1000,
      }),
      windowMs: parseConfiguredInteger({
        name: 'EMAIL_OTP_GOOGLE_REGISTRATION_ATTEMPT_RATE_LIMIT_WINDOW_MS',
        raw: readEmailOtpConfigValue(
          input,
          'EMAIL_OTP_GOOGLE_REGISTRATION_ATTEMPT_RATE_LIMIT_WINDOW_MS',
        ),
        defaultValue: googleRegistrationAttemptDefault.windowMs,
        min: 1_000,
        max: 24 * 60 * 60_000,
      }),
    },
  };
}

export function resolveEmailOtpConfig(input: EmailOtpConfigInput): EmailOtpConfig {
  const deliveryMode = parseEmailOtpDeliveryMode(
    readEmailOtpConfigValue(input, 'EMAIL_OTP_DELIVERY_MODE'),
  );
  const devOutboxEnabledRaw = readBooleanFlag(input, 'EMAIL_OTP_DEV_OUTBOX_ENABLED');
  const devOutboxEnabled =
    deliveryMode === 'memory' &&
    !input.production &&
    (devOutboxEnabledRaw ? isTruthyBooleanFlag(devOutboxEnabledRaw) : true);
  return {
    deliveryMode,
    challengeTtlMs: parseConfiguredInteger({
      name: 'EMAIL_OTP_CHALLENGE_TTL_MS',
      raw: readEmailOtpConfigValue(input, 'EMAIL_OTP_CHALLENGE_TTL_MS'),
      defaultValue: 5 * 60_000,
      min: 30_000,
      max: 15 * 60_000,
    }),
    grantTtlMs: parseConfiguredInteger({
      name: 'EMAIL_OTP_GRANT_TTL_MS',
      raw: readEmailOtpConfigValue(input, 'EMAIL_OTP_GRANT_TTL_MS'),
      defaultValue: 30_000,
      min: 10_000,
      max: 5 * 60_000,
    }),
    maxAttempts: parseConfiguredInteger({
      name: 'EMAIL_OTP_MAX_ATTEMPTS',
      raw: readEmailOtpConfigValue(input, 'EMAIL_OTP_MAX_ATTEMPTS'),
      defaultValue: 5,
      min: 1,
      max: 10,
    }),
    lockoutTtlMs: parseConfiguredInteger({
      name: 'EMAIL_OTP_LOCKOUT_TTL_MS',
      raw: readEmailOtpConfigValue(input, 'EMAIL_OTP_LOCKOUT_TTL_MS'),
      defaultValue: 5 * 60_000,
      min: 60_000,
      max: 24 * 60 * 60_000,
    }),
    codeLength: parseEmailOtpCodeLength(
      readEmailOtpConfigValue(input, 'EMAIL_OTP_CODE_LENGTH'),
    ),
    devOutboxEnabled,
    maxActiveChallengesPerContext: parseConfiguredInteger({
      name: 'EMAIL_OTP_MAX_ACTIVE_CHALLENGES_PER_CONTEXT',
      raw: readEmailOtpConfigValue(input, 'EMAIL_OTP_MAX_ACTIVE_CHALLENGES_PER_CONTEXT'),
      defaultValue: 5,
      min: 1,
      max: 20,
    }),
  };
}

function parseEmailOtpCodeLength(raw: string): typeof EMAIL_OTP_CODE_LENGTH {
  const codeLength = parseConfiguredInteger({
    name: 'EMAIL_OTP_CODE_LENGTH',
    raw,
    defaultValue: EMAIL_OTP_CODE_LENGTH,
    min: EMAIL_OTP_CODE_LENGTH,
    max: 8,
  });
  if (codeLength !== EMAIL_OTP_CODE_LENGTH) {
    throw new Error(`EMAIL_OTP_CODE_LENGTH must be ${EMAIL_OTP_CODE_LENGTH}`);
  }
  return EMAIL_OTP_CODE_LENGTH;
}

export function maskEmailAddress(email: string): string {
  const trimmed = String(email || '').trim().toLowerCase();
  const atIndex = trimmed.indexOf('@');
  if (atIndex <= 0 || atIndex === trimmed.length - 1) return 'hidden';
  const local = trimmed.slice(0, atIndex);
  const domain = trimmed.slice(atIndex + 1);
  const maskedLocal =
    local.length <= 2 ? `${local[0] || '*'}*` : `${local[0]}***${local.slice(-1)}`;
  const domainParts = domain.split('.');
  const domainName = domainParts[0] || '';
  const maskedDomainName =
    domainName.length <= 2
      ? `${domainName[0] || '*'}*`
      : `${domainName[0]}***${domainName.slice(-1)}`;
  return `${maskedLocal}@${[maskedDomainName, ...domainParts.slice(1)].join('.')}`;
}
