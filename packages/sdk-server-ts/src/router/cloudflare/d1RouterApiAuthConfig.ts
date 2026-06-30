import { toOptionalTrimmedString } from '@shared/utils/validation';
import type { WalletEmailOtpChannel } from '@shared/utils/emailOtpDomain';
import type {
  EmailOtpChallengeAction,
  EmailOtpChallengeOperation,
} from '../../core/EmailOtpStores';
import type { ThresholdStoreConfigInput } from '../../core/types';
import type { ThresholdSigningService } from '../../core/ThresholdService/ThresholdSigningService';
import {
  formatSigningSessionSealKeyVersionForWire,
  formatSigningSessionSealShamirPrimeB64uForWire,
  parseSigningSessionSealKeyVersion,
  parseSigningSessionSealShamirPrimeB64u,
} from '../../core/keyMaterialBrands';
import type { D1DatabaseLike } from '../../storage/tenantRoute';
import {
  normalizeOidcExchangeConfig,
  type CloudflareD1OidcExchangeConfig,
  type NormalizedCloudflareD1OidcExchangeConfig,
} from './d1OidcBoundary';

export type CloudflareD1EmailOtpDeliveryProviderInput = {
  readonly challengeId: string;
  readonly walletId: string;
  readonly userId: string;
  readonly orgId?: string;
  readonly email: string;
  readonly emailHint: string;
  readonly otpCode: string;
  readonly otpChannel: WalletEmailOtpChannel;
  readonly action: EmailOtpChallengeAction;
  readonly operation: EmailOtpChallengeOperation;
  readonly expiresAtMs: number;
};

export type CloudflareD1EmailOtpDeliveryProviderResult =
  | { readonly ok: true; readonly providerMessageId?: string }
  | { readonly ok: false; readonly code: string; readonly message: string };

export interface CloudflareD1EmailOtpDeliveryProvider {
  deliver(
    input: CloudflareD1EmailOtpDeliveryProviderInput,
  ): Promise<CloudflareD1EmailOtpDeliveryProviderResult>;
}

export type CloudflareD1EmailOtpServerSealConfig = {
  readonly keyVersion: string;
  readonly shamirPrimeB64u: string;
  readonly serverEncryptExponentB64u: string;
  readonly serverDecryptExponentB64u: string;
};

export interface CloudflareD1RouterApiAuthServiceOptions {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
  readonly relayerAccount?: string;
  readonly relayerPublicKey?: string;
  readonly relayerPrivateKey?: string;
  readonly nearRpcUrl?: string;
  readonly accountInitialBalance?: string;
  readonly implicitNearAccountTestFundingEnabled?: boolean | string;
  readonly googleOidcClientId?: string;
  readonly oidcExchange?: CloudflareD1OidcExchangeConfig;
  readonly accountIdDerivationSecret?: string;
  readonly emailOtpServerSeal?: CloudflareD1EmailOtpServerSealConfig;
  readonly emailOtpDeliveryMode?: string;
  readonly emailOtpDeliveryProvider?: CloudflareD1EmailOtpDeliveryProvider;
  readonly emailOtpDevOutboxEnabled?: boolean | string;
  readonly emailOtpProduction?: boolean | string;
  readonly emailOtpChallengeTtlMs?: number | string;
  readonly emailOtpGrantTtlMs?: number | string;
  readonly emailOtpMaxAttempts?: number | string;
  readonly emailOtpLockoutTtlMs?: number | string;
  readonly emailOtpCodeLength?: number | string;
  readonly emailOtpMaxActiveChallengesPerContext?: number | string;
  readonly emailOtpChallengeRateLimitMax?: number | string;
  readonly emailOtpChallengeRateLimitWindowMs?: number | string;
  readonly emailOtpVerifyRateLimitMax?: number | string;
  readonly emailOtpVerifyRateLimitWindowMs?: number | string;
  readonly emailOtpGrantRateLimitMax?: number | string;
  readonly emailOtpGrantRateLimitWindowMs?: number | string;
  readonly emailOtpRecoveryKeyAttemptRateLimitMax?: number | string;
  readonly emailOtpRecoveryKeyAttemptRateLimitWindowMs?: number | string;
  readonly emailOtpGoogleRegistrationAttemptRateLimitMax?: number | string;
  readonly emailOtpGoogleRegistrationAttemptRateLimitWindowMs?: number | string;
  readonly thresholdStore?: ThresholdStoreConfigInput | null;
  readonly thresholdSigningService?: ThresholdSigningService | null;
}

export type EmailOtpDeliveryMode = 'email_provider' | 'log' | 'dev_d1_outbox';

export type EmailOtpRuntimeConfig = {
  readonly deliveryMode: EmailOtpDeliveryMode;
  readonly deliveryProvider?: CloudflareD1EmailOtpDeliveryProvider;
  readonly devOutboxEnabled: boolean;
  readonly production: boolean;
  readonly challengeTtlMs: number;
  readonly grantTtlMs: number;
  readonly maxAttempts: number;
  readonly lockoutTtlMs: number;
  readonly codeLength: number;
  readonly maxActiveChallengesPerContext: number;
  readonly rateLimits: {
    readonly challenge: EmailOtpRateLimitPolicy;
    readonly verify: EmailOtpRateLimitPolicy;
    readonly grant: EmailOtpRateLimitPolicy;
    readonly recoveryKeyAttempt: EmailOtpRateLimitPolicy;
    readonly googleRegistrationAttempt: EmailOtpRateLimitPolicy;
  };
};

export type EmailOtpRateLimitPolicy = {
  readonly limit: number;
  readonly windowMs: number;
};

export type EmailOtpServerSealRuntimeConfig =
  | {
      readonly configured: true;
      readonly keyVersion: string;
      readonly shamirPrimeB64u: string;
      readonly serverEncryptExponentB64u: string;
      readonly serverDecryptExponentB64u: string;
    }
  | {
      readonly configured: false;
      readonly message: string;
    };

export type NormalizedCloudflareD1RouterApiAuthServiceOptions = Omit<
  CloudflareD1RouterApiAuthServiceOptions,
  | 'relayerAccount'
  | 'relayerPublicKey'
  | 'relayerPrivateKey'
  | 'nearRpcUrl'
  | 'accountInitialBalance'
  | 'implicitNearAccountTestFundingEnabled'
  | 'googleOidcClientId'
  | 'oidcExchange'
  | 'accountIdDerivationSecret'
  | 'emailOtpServerSeal'
  | 'emailOtpDeliveryMode'
  | 'emailOtpDeliveryProvider'
  | 'emailOtpDevOutboxEnabled'
  | 'emailOtpProduction'
  | 'emailOtpChallengeTtlMs'
  | 'emailOtpGrantTtlMs'
  | 'emailOtpMaxAttempts'
  | 'emailOtpLockoutTtlMs'
  | 'emailOtpCodeLength'
  | 'emailOtpMaxActiveChallengesPerContext'
  | 'emailOtpChallengeRateLimitMax'
  | 'emailOtpChallengeRateLimitWindowMs'
  | 'emailOtpVerifyRateLimitMax'
  | 'emailOtpVerifyRateLimitWindowMs'
  | 'emailOtpGrantRateLimitMax'
  | 'emailOtpGrantRateLimitWindowMs'
  | 'emailOtpRecoveryKeyAttemptRateLimitMax'
  | 'emailOtpRecoveryKeyAttemptRateLimitWindowMs'
  | 'emailOtpGoogleRegistrationAttemptRateLimitMax'
  | 'emailOtpGoogleRegistrationAttemptRateLimitWindowMs'
  | 'thresholdStore'
  | 'thresholdSigningService'
> & {
  readonly relayerAccount?: string;
  readonly relayerPublicKey?: string;
  readonly relayerPrivateKey?: string;
  readonly nearRpcUrl?: string;
  readonly accountInitialBalance?: string;
  readonly implicitNearAccountTestFundingEnabled: boolean;
  readonly googleOidcClientId?: string;
  readonly oidcExchange?: NormalizedCloudflareD1OidcExchangeConfig;
  readonly accountIdDerivationSecret?: string;
  readonly emailOtp: EmailOtpRuntimeConfig;
  readonly emailOtpServerSeal: EmailOtpServerSealRuntimeConfig;
  readonly thresholdStore?: ThresholdStoreConfigInput | null;
  readonly thresholdSigningService?: ThresholdSigningService | null;
};

export function requireD1RouterApiAuthScopeString(input: unknown, field: string): string {
  const value = toOptionalTrimmedString(input);
  if (!value) throw new Error(`${field} is required for Cloudflare D1 Router API auth service`);
  return value;
}

export function parseBooleanFlag(input: unknown, fallback: boolean, field: string): boolean {
  if (input == null || input === '') return fallback;
  if (typeof input === 'boolean') return input;
  const value = toOptionalTrimmedString(input)?.toLowerCase();
  switch (value) {
    case '1':
    case 'true':
    case 'yes':
    case 'on':
      return true;
    case '0':
    case 'false':
    case 'no':
    case 'off':
      return false;
    default:
      throw new Error(`${field} must be a boolean flag`);
  }
}

export function normalizeD1RouterApiAuthOptions(
  input: CloudflareD1RouterApiAuthServiceOptions,
): NormalizedCloudflareD1RouterApiAuthServiceOptions {
  return {
    database: input.database,
    namespace: requireD1RouterApiAuthScopeString(input.namespace, 'namespace'),
    orgId: requireD1RouterApiAuthScopeString(input.orgId, 'orgId'),
    projectId: requireD1RouterApiAuthScopeString(input.projectId, 'projectId'),
    envId: requireD1RouterApiAuthScopeString(input.envId, 'envId'),
    relayerAccount: toOptionalTrimmedString(input.relayerAccount),
    relayerPublicKey: toOptionalTrimmedString(input.relayerPublicKey),
    relayerPrivateKey: toOptionalTrimmedString(input.relayerPrivateKey),
    nearRpcUrl: toOptionalTrimmedString(input.nearRpcUrl),
    accountInitialBalance: toOptionalTrimmedString(input.accountInitialBalance),
    implicitNearAccountTestFundingEnabled: parseBooleanFlag(
      input.implicitNearAccountTestFundingEnabled,
      false,
      'implicitNearAccountTestFundingEnabled',
    ),
    googleOidcClientId: toOptionalTrimmedString(input.googleOidcClientId),
    oidcExchange: normalizeOidcExchangeConfig(input),
    accountIdDerivationSecret: toOptionalTrimmedString(input.accountIdDerivationSecret),
    emailOtp: normalizeEmailOtpConfig(input),
    emailOtpServerSeal: normalizeEmailOtpServerSealConfig(input),
    thresholdStore: input.thresholdStore,
    thresholdSigningService: input.thresholdSigningService,
  };
}

function configuredInteger(input: {
  readonly field: string;
  readonly raw: unknown;
  readonly fallback: number;
  readonly min: number;
  readonly max: number;
}): number {
  if (input.raw == null || input.raw === '') return input.fallback;
  const value = typeof input.raw === 'number' ? input.raw : Number(input.raw);
  if (!Number.isFinite(value)) throw new Error(`${input.field} must be a finite number`);
  if (value < input.min || value > input.max) {
    throw new Error(`${input.field} must be between ${input.min} and ${input.max}`);
  }
  return Math.floor(value);
}

function normalizeEmailOtpDeliveryMode(input: unknown): EmailOtpDeliveryMode {
  const value = toOptionalTrimmedString(input)?.toLowerCase() || 'email_provider';
  switch (value) {
    case 'email_provider':
    case 'log':
    case 'dev_d1_outbox':
      return value;
    default:
      throw new Error('emailOtpDeliveryMode must be one of email_provider, log, or dev_d1_outbox');
  }
}

function emailOtpRateLimitPolicy(input: {
  readonly limitField: string;
  readonly limitRaw: unknown;
  readonly limitFallback: number;
  readonly limitMax: number;
  readonly windowField: string;
  readonly windowRaw: unknown;
  readonly windowFallback: number;
}): EmailOtpRateLimitPolicy {
  return {
    limit: configuredInteger({
      field: input.limitField,
      raw: input.limitRaw,
      fallback: input.limitFallback,
      min: 1,
      max: input.limitMax,
    }),
    windowMs: configuredInteger({
      field: input.windowField,
      raw: input.windowRaw,
      fallback: input.windowFallback,
      min: 1_000,
      max: 24 * 60 * 60_000,
    }),
  };
}

function normalizeEmailOtpConfig(
  input: CloudflareD1RouterApiAuthServiceOptions,
): EmailOtpRuntimeConfig {
  const production = parseBooleanFlag(input.emailOtpProduction, false, 'emailOtpProduction');
  const deliveryMode = normalizeEmailOtpDeliveryMode(input.emailOtpDeliveryMode);
  const challengeDefault = production
    ? { limit: 5, windowMs: 5 * 60_000 }
    : { limit: 100, windowMs: 60_000 };
  const verifyDefault = production
    ? { limit: 10, windowMs: 5 * 60_000 }
    : { limit: 100, windowMs: 60_000 };
  const grantDefault = production
    ? { limit: 8, windowMs: 5 * 60_000 }
    : { limit: 100, windowMs: 60_000 };
  const recoveryKeyAttemptDefault = production
    ? { limit: 10, windowMs: 5 * 60_000 }
    : { limit: 100, windowMs: 60_000 };
  const googleRegistrationAttemptDefault = production
    ? { limit: 12, windowMs: 10 * 60_000 }
    : { limit: 200, windowMs: 60_000 };
  return {
    deliveryMode,
    ...(input.emailOtpDeliveryProvider
      ? { deliveryProvider: input.emailOtpDeliveryProvider }
      : {}),
    production,
    devOutboxEnabled:
      deliveryMode === 'dev_d1_outbox' &&
      !production &&
      parseBooleanFlag(input.emailOtpDevOutboxEnabled, true, 'emailOtpDevOutboxEnabled'),
    challengeTtlMs: configuredInteger({
      field: 'emailOtpChallengeTtlMs',
      raw: input.emailOtpChallengeTtlMs,
      fallback: 5 * 60_000,
      min: 30_000,
      max: 15 * 60_000,
    }),
    grantTtlMs: configuredInteger({
      field: 'emailOtpGrantTtlMs',
      raw: input.emailOtpGrantTtlMs,
      fallback: 30_000,
      min: 10_000,
      max: 5 * 60_000,
    }),
    maxAttempts: configuredInteger({
      field: 'emailOtpMaxAttempts',
      raw: input.emailOtpMaxAttempts,
      fallback: 5,
      min: 1,
      max: 10,
    }),
    lockoutTtlMs: configuredInteger({
      field: 'emailOtpLockoutTtlMs',
      raw: input.emailOtpLockoutTtlMs,
      fallback: 15 * 60_000,
      min: 60_000,
      max: 24 * 60 * 60_000,
    }),
    codeLength: configuredInteger({
      field: 'emailOtpCodeLength',
      raw: input.emailOtpCodeLength,
      fallback: 6,
      min: 6,
      max: 8,
    }),
    maxActiveChallengesPerContext: configuredInteger({
      field: 'emailOtpMaxActiveChallengesPerContext',
      raw: input.emailOtpMaxActiveChallengesPerContext,
      fallback: 5,
      min: 1,
      max: 20,
    }),
    rateLimits: {
      challenge: emailOtpRateLimitPolicy({
        limitField: 'emailOtpChallengeRateLimitMax',
        limitRaw: input.emailOtpChallengeRateLimitMax,
        limitFallback: challengeDefault.limit,
        limitMax: 500,
        windowField: 'emailOtpChallengeRateLimitWindowMs',
        windowRaw: input.emailOtpChallengeRateLimitWindowMs,
        windowFallback: challengeDefault.windowMs,
      }),
      verify: emailOtpRateLimitPolicy({
        limitField: 'emailOtpVerifyRateLimitMax',
        limitRaw: input.emailOtpVerifyRateLimitMax,
        limitFallback: verifyDefault.limit,
        limitMax: 1000,
        windowField: 'emailOtpVerifyRateLimitWindowMs',
        windowRaw: input.emailOtpVerifyRateLimitWindowMs,
        windowFallback: verifyDefault.windowMs,
      }),
      grant: emailOtpRateLimitPolicy({
        limitField: 'emailOtpGrantRateLimitMax',
        limitRaw: input.emailOtpGrantRateLimitMax,
        limitFallback: grantDefault.limit,
        limitMax: 1000,
        windowField: 'emailOtpGrantRateLimitWindowMs',
        windowRaw: input.emailOtpGrantRateLimitWindowMs,
        windowFallback: grantDefault.windowMs,
      }),
      recoveryKeyAttempt: emailOtpRateLimitPolicy({
        limitField: 'emailOtpRecoveryKeyAttemptRateLimitMax',
        limitRaw: input.emailOtpRecoveryKeyAttemptRateLimitMax,
        limitFallback: recoveryKeyAttemptDefault.limit,
        limitMax: 1000,
        windowField: 'emailOtpRecoveryKeyAttemptRateLimitWindowMs',
        windowRaw: input.emailOtpRecoveryKeyAttemptRateLimitWindowMs,
        windowFallback: recoveryKeyAttemptDefault.windowMs,
      }),
      googleRegistrationAttempt: emailOtpRateLimitPolicy({
        limitField: 'emailOtpGoogleRegistrationAttemptRateLimitMax',
        limitRaw: input.emailOtpGoogleRegistrationAttemptRateLimitMax,
        limitFallback: googleRegistrationAttemptDefault.limit,
        limitMax: 1000,
        windowField: 'emailOtpGoogleRegistrationAttemptRateLimitWindowMs',
        windowRaw: input.emailOtpGoogleRegistrationAttemptRateLimitWindowMs,
        windowFallback: googleRegistrationAttemptDefault.windowMs,
      }),
    },
  };
}

function missingEmailOtpServerSealConfig(): EmailOtpServerSealRuntimeConfig {
  return {
    configured: false,
    message:
      'Email OTP server seal requires emailOtpServerSeal.keyVersion, emailOtpServerSeal.shamirPrimeB64u, emailOtpServerSeal.serverEncryptExponentB64u, and emailOtpServerSeal.serverDecryptExponentB64u',
  };
}

function normalizeEmailOtpServerSealConfig(
  input: CloudflareD1RouterApiAuthServiceOptions,
): EmailOtpServerSealRuntimeConfig {
  const raw = input.emailOtpServerSeal;
  if (!raw) return missingEmailOtpServerSealConfig();
  const keyVersionRaw = toOptionalTrimmedString(raw.keyVersion);
  const shamirPrimeRaw = toOptionalTrimmedString(raw.shamirPrimeB64u);
  const serverEncryptExponentB64u = toOptionalTrimmedString(raw.serverEncryptExponentB64u);
  const serverDecryptExponentB64u = toOptionalTrimmedString(raw.serverDecryptExponentB64u);
  if (
    !keyVersionRaw ||
    !shamirPrimeRaw ||
    !serverEncryptExponentB64u ||
    !serverDecryptExponentB64u
  ) {
    return missingEmailOtpServerSealConfig();
  }
  try {
    const keyVersion = formatSigningSessionSealKeyVersionForWire(
      parseSigningSessionSealKeyVersion(keyVersionRaw),
    );
    const shamirPrimeB64u = formatSigningSessionSealShamirPrimeB64uForWire(
      parseSigningSessionSealShamirPrimeB64u(shamirPrimeRaw),
    );
    return {
      configured: true,
      keyVersion,
      shamirPrimeB64u,
      serverEncryptExponentB64u,
      serverDecryptExponentB64u,
    };
  } catch (error: unknown) {
    return {
      configured: false,
      message: configErrorMessage(error) || 'Email OTP Shamir configuration is invalid',
    };
  }
}

function configErrorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error || '');
}
