import { secureRandomBase64Url } from '@shared/utils/secureRandomId';
import { isValidAccountId, toOptionalTrimmedString } from '@shared/utils/validation';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/encoders';
import {
  parseGoogleProviderSubject,
  parseOrgId,
  parseVerifiedGoogleEmail,
} from '@shared/utils/domainIds';
import type { RuntimePolicyScope } from '@shared/threshold/signingRootScope';
import {
  EMAIL_OTP_CHANNEL,
  WALLET_EMAIL_OTP_ACTIONS,
  WALLET_EMAIL_OTP_UNLOCK_OPERATION,
  isWalletEmailOtpLoginOperation,
} from '@shared/utils/emailOtpDomain';
import {
  EMAIL_OTP_RECOVERY_KEY_COUNT,
  EMAIL_OTP_RECOVERY_WRAP_ALG,
  EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_ESCROW_KIND,
  EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_SECRET_KIND,
  buildEmailOtpRecoveryWrapBinding,
  encodeEmailOtpRecoveryWrappedEnrollmentAad,
} from '@shared/utils/emailOtpRecoveryKey';
import { deriveHostedNearAccountId } from '../../core/hostedAccountIds';
import { buildRecoveryExecutionRecord } from '../../core/recoveryExecutionRecords';
import type {
  EmailOtpAuthStateRecord,
  EmailOtpChallengeAction,
  EmailOtpChallengeOperation,
  EmailOtpChallengeRecord,
  EmailOtpGrantAction,
  EmailOtpGrantRecord,
  EmailOtpLoginChallengeOperation,
  EmailOtpRecoveryWrappedEnrollmentEscrowRecord,
  EmailOtpUnlockChallengeRecord,
  EmailOtpWalletEnrollmentRecord,
  GoogleEmailOtpRegistrationAttemptRecord,
  GoogleEmailOtpRegistrationOfferCandidateRecord,
  NonEmptyGoogleEmailOtpRegistrationOfferCandidates,
  PendingGoogleEmailOtpRegistrationAttemptRecord,
} from '../../core/EmailOtpStores';
import type {
  RecoveryExecutionRecord,
  RecoveryExecutionStatus,
} from '../../core/RecoveryExecutionStore';
import type { RecoverySessionRecord, RecoverySessionStatus } from '../../core/RecoverySessionStore';
import {
  validateSecp256k1PublicKey33,
  verifySecp256k1RecoverableSignatureAgainstPublicKey33,
} from '../../core/ThresholdService/ethSignerWasm';
import type {
  D1DatabaseLike,
  D1PreparedStatementLike,
  D1ResultLike,
} from '../../storage/tenantRoute';
import type { CloudflareRelayAuthService } from '../authServicePort';
import { createDisabledCloudflareRelayAuthService } from './disabledRelayAuthService';

export type CloudflareD1EmailOtpDeliveryProviderInput = {
  readonly challengeId: string;
  readonly walletId: string;
  readonly userId: string;
  readonly orgId?: string;
  readonly email: string;
  readonly emailHint: string;
  readonly otpCode: string;
  readonly otpChannel: typeof EMAIL_OTP_CHANNEL;
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

export interface CloudflareD1RelayAuthServiceOptions {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
  readonly relayerAccount?: string;
  readonly relayerPublicKey?: string;
  readonly googleOidcClientId?: string;
  readonly accountIdDerivationSecret?: string;
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
}

type EmailOtpDeliveryMode = 'email_provider' | 'log' | 'memory';

type EmailOtpRuntimeConfig = {
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

type EmailOtpRateLimitPolicy = {
  readonly limit: number;
  readonly windowMs: number;
};

type NormalizedCloudflareD1RelayAuthServiceOptions = Omit<
  CloudflareD1RelayAuthServiceOptions,
  | 'relayerAccount'
  | 'relayerPublicKey'
  | 'googleOidcClientId'
  | 'accountIdDerivationSecret'
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
> & {
  readonly relayerAccount?: string;
  readonly relayerPublicKey?: string;
  readonly googleOidcClientId?: string;
  readonly accountIdDerivationSecret?: string;
  readonly emailOtp: EmailOtpRuntimeConfig;
};

type ListIdentitiesInput = Parameters<CloudflareRelayAuthService['listIdentities']>[0];
type ListIdentitiesResult = Awaited<ReturnType<CloudflareRelayAuthService['listIdentities']>>;
type LinkIdentityInput = Parameters<CloudflareRelayAuthService['linkIdentity']>[0];
type LinkIdentityResult = Awaited<ReturnType<CloudflareRelayAuthService['linkIdentity']>>;
type UnlinkIdentityInput = Parameters<CloudflareRelayAuthService['unlinkIdentity']>[0];
type UnlinkIdentityResult = Awaited<ReturnType<CloudflareRelayAuthService['unlinkIdentity']>>;
type ResolveOidcWalletIdInput = Parameters<CloudflareRelayAuthService['resolveOidcWalletId']>[0];
type ResolveOidcWalletIdResult = Awaited<
  ReturnType<CloudflareRelayAuthService['resolveOidcWalletId']>
>;
type ReadEmailOtpEnrollmentInput = Parameters<
  CloudflareRelayAuthService['readEmailOtpEnrollment']
>[0];
type ReadEmailOtpEnrollmentResult = Awaited<
  ReturnType<CloudflareRelayAuthService['readEmailOtpEnrollment']>
>;
type ReadActiveEmailOtpEnrollmentInput = Parameters<
  CloudflareRelayAuthService['readActiveEmailOtpEnrollment']
>[0];
type ReadActiveEmailOtpEnrollmentResult = Awaited<
  ReturnType<CloudflareRelayAuthService['readActiveEmailOtpEnrollment']>
>;
type IsEmailOtpStrongAuthRequiredInput = Parameters<
  CloudflareRelayAuthService['isEmailOtpStrongAuthRequired']
>[0];
type IsEmailOtpStrongAuthRequiredResult = Awaited<
  ReturnType<CloudflareRelayAuthService['isEmailOtpStrongAuthRequired']>
>;
type MarkEmailOtpStrongAuthSatisfiedInput = Parameters<
  CloudflareRelayAuthService['markEmailOtpStrongAuthSatisfied']
>[0];
type MarkEmailOtpStrongAuthSatisfiedResult = Awaited<
  ReturnType<CloudflareRelayAuthService['markEmailOtpStrongAuthSatisfied']>
>;
type GetEmailOtpRecoveryCodeStatusInput = Parameters<
  CloudflareRelayAuthService['getEmailOtpRecoveryCodeStatus']
>[0];
type GetEmailOtpRecoveryCodeStatusResult = Awaited<
  ReturnType<CloudflareRelayAuthService['getEmailOtpRecoveryCodeStatus']>
>;
type ConsumeEmailOtpGrantInput = Parameters<CloudflareRelayAuthService['consumeEmailOtpGrant']>[0];
type ConsumeEmailOtpGrantResult = Awaited<
  ReturnType<CloudflareRelayAuthService['consumeEmailOtpGrant']>
>;
type ConsumeEmailOtpRecoveryKeyInput = Parameters<
  CloudflareRelayAuthService['consumeEmailOtpRecoveryKey']
>[0];
type ConsumeEmailOtpRecoveryKeyResult = Awaited<
  ReturnType<CloudflareRelayAuthService['consumeEmailOtpRecoveryKey']>
>;
type RecordEmailOtpRecoveryKeyAttemptFailureInput = Parameters<
  CloudflareRelayAuthService['recordEmailOtpRecoveryKeyAttemptFailure']
>[0];
type RecordEmailOtpRecoveryKeyAttemptFailureResult = Awaited<
  ReturnType<CloudflareRelayAuthService['recordEmailOtpRecoveryKeyAttemptFailure']>
>;
type RotateEmailOtpRecoveryKeysInput = Parameters<
  CloudflareRelayAuthService['rotateEmailOtpRecoveryKeys']
>[0];
type RotateEmailOtpRecoveryKeysResult = Awaited<
  ReturnType<CloudflareRelayAuthService['rotateEmailOtpRecoveryKeys']>
>;
type CreateEmailOtpChallengeInput = Parameters<
  CloudflareRelayAuthService['createEmailOtpChallenge']
>[0];
type CreateEmailOtpChallengeResult = Awaited<
  ReturnType<CloudflareRelayAuthService['createEmailOtpChallenge']>
>;
type VerifyEmailOtpChallengeInput = Parameters<
  CloudflareRelayAuthService['verifyEmailOtpChallenge']
>[0];
type VerifyEmailOtpChallengeResult = Awaited<
  ReturnType<CloudflareRelayAuthService['verifyEmailOtpChallenge']>
>;
type CreateEmailOtpDeviceRecoveryChallengeInput = Parameters<
  CloudflareRelayAuthService['createEmailOtpDeviceRecoveryChallenge']
>[0];
type CreateEmailOtpDeviceRecoveryChallengeResult = Awaited<
  ReturnType<CloudflareRelayAuthService['createEmailOtpDeviceRecoveryChallenge']>
>;
type VerifyEmailOtpDeviceRecoveryChallengeInput = Parameters<
  CloudflareRelayAuthService['verifyEmailOtpDeviceRecoveryChallenge']
>[0];
type VerifyEmailOtpDeviceRecoveryChallengeResult = Awaited<
  ReturnType<CloudflareRelayAuthService['verifyEmailOtpDeviceRecoveryChallenge']>
>;
type ReadEmailOtpOutboxEntryInput = Parameters<
  CloudflareRelayAuthService['readEmailOtpOutboxEntry']
>[0];
type ReadEmailOtpOutboxEntryResult = Awaited<
  ReturnType<CloudflareRelayAuthService['readEmailOtpOutboxEntry']>
>;
type CreateEmailOtpUnlockChallengeInput = Parameters<
  CloudflareRelayAuthService['createEmailOtpUnlockChallenge']
>[0];
type CreateEmailOtpUnlockChallengeResult = Awaited<
  ReturnType<CloudflareRelayAuthService['createEmailOtpUnlockChallenge']>
>;
type VerifyEmailOtpUnlockProofInput = Parameters<
  CloudflareRelayAuthService['verifyEmailOtpUnlockProof']
>[0];
type VerifyEmailOtpUnlockProofResult = Awaited<
  ReturnType<CloudflareRelayAuthService['verifyEmailOtpUnlockProof']>
>;
type GetOrCreateAppSessionVersionInput = Parameters<
  CloudflareRelayAuthService['getOrCreateAppSessionVersion']
>[0];
type GetOrCreateAppSessionVersionResult = Awaited<
  ReturnType<CloudflareRelayAuthService['getOrCreateAppSessionVersion']>
>;
type GetRecoverySessionInput = Parameters<CloudflareRelayAuthService['getRecoverySession']>[0];
type GetRecoverySessionResult = Awaited<
  ReturnType<CloudflareRelayAuthService['getRecoverySession']>
>;
type UpdateRecoverySessionStatusInput = Parameters<
  CloudflareRelayAuthService['updateRecoverySessionStatus']
>[0];
type UpdateRecoverySessionStatusResult = Awaited<
  ReturnType<CloudflareRelayAuthService['updateRecoverySessionStatus']>
>;
type RecordRecoveryExecutionInput = Parameters<
  CloudflareRelayAuthService['recordRecoveryExecution']
>[0];
type RecordRecoveryExecutionResult = Awaited<
  ReturnType<CloudflareRelayAuthService['recordRecoveryExecution']>
>;
type RotateAppSessionVersionInput = Parameters<
  CloudflareRelayAuthService['rotateAppSessionVersion']
>[0];
type RotateAppSessionVersionResult = Awaited<
  ReturnType<CloudflareRelayAuthService['rotateAppSessionVersion']>
>;
type ValidateAppSessionVersionInput = Parameters<
  CloudflareRelayAuthService['validateAppSessionVersion']
>[0];
type ValidateAppSessionVersionResult = Awaited<
  ReturnType<CloudflareRelayAuthService['validateAppSessionVersion']>
>;
type ListWebAuthnAuthenticatorsInput = Parameters<
  CloudflareRelayAuthService['listWebAuthnAuthenticatorsForUser']
>[0];
type ListWebAuthnAuthenticatorsResult = Awaited<
  ReturnType<CloudflareRelayAuthService['listWebAuthnAuthenticatorsForUser']>
>;
type ListNearPublicKeysInput = Parameters<
  CloudflareRelayAuthService['listNearPublicKeysForUser']
>[0];
type ListNearPublicKeysResult = Awaited<
  ReturnType<CloudflareRelayAuthService['listNearPublicKeysForUser']>
>;
type ConsumeGoogleEmailOtpRegistrationAttemptRateLimitInput = Parameters<
  CloudflareRelayAuthService['consumeGoogleEmailOtpRegistrationAttemptRateLimit']
>[0];
type ConsumeGoogleEmailOtpRegistrationAttemptRateLimitResult = Awaited<
  ReturnType<CloudflareRelayAuthService['consumeGoogleEmailOtpRegistrationAttemptRateLimit']>
>;
type ResolveGoogleEmailOtpSessionInput = Parameters<
  CloudflareRelayAuthService['resolveGoogleEmailOtpSession']
>[0];
type ResolveGoogleEmailOtpSessionResult = Awaited<
  ReturnType<CloudflareRelayAuthService['resolveGoogleEmailOtpSession']>
>;
type VerifyGoogleLoginInput = Parameters<CloudflareRelayAuthService['verifyGoogleLogin']>[0];
type VerifyGoogleLoginResult = Awaited<
  ReturnType<CloudflareRelayAuthService['verifyGoogleLogin']>
>;
type VerifyGoogleLoginFailure = {
  readonly ok: false;
  readonly verified: false;
  readonly code: string;
  readonly message: string;
};
type GoogleEmailOtpRegistrationOfferForResponse = Extract<
  ResolveGoogleEmailOtpSessionResult,
  { readonly ok: true; readonly mode: 'register_started' }
>['offer'];

type D1IdentityRow = {
  readonly subject?: unknown;
  readonly user_id?: unknown;
  readonly created_at_ms?: unknown;
  readonly subject_count?: unknown;
};

type D1SessionRow = {
  readonly session_version?: unknown;
  readonly record_json?: unknown;
};

type D1EmailOtpEnrollmentRow = {
  readonly record_json?: unknown;
  readonly updated_at_ms?: unknown;
};

type D1EmailOtpAuthStateRow = {
  readonly record_json?: unknown;
  readonly updated_at_ms?: unknown;
};

type D1EmailOtpChallengeRow = {
  readonly challenge_id?: unknown;
  readonly record_json?: unknown;
  readonly expires_at_ms?: unknown;
};

type D1EmailOtpRecoveryEscrowRow = {
  readonly record_json?: unknown;
  readonly updated_at_ms?: unknown;
};

type D1EmailOtpGrantRow = {
  readonly record_json?: unknown;
  readonly expires_at_ms?: unknown;
};

type D1EmailOtpRateLimitRow = {
  readonly consumed_count?: unknown;
  readonly reset_at_ms?: unknown;
};

type D1EmailOtpUnlockChallengeRow = {
  readonly record_json?: unknown;
  readonly expires_at_ms?: unknown;
};

type D1EmailOtpRegistrationAttemptRow = {
  readonly attempt_id?: unknown;
  readonly record_json?: unknown;
  readonly expires_at_ms?: unknown;
  readonly updated_at_ms?: unknown;
};

type D1RecoverySessionRow = {
  readonly record_json?: unknown;
};

type D1RecoveryExecutionRow = {
  readonly record_json?: unknown;
};

type D1AuthenticatorRow = {
  readonly credential_id_b64u?: unknown;
  readonly created_at_ms?: unknown;
  readonly updated_at_ms?: unknown;
};

type D1RecordJsonRow = {
  readonly record_json?: unknown;
};

type JsonWebKeyCache = {
  readonly keysByKid: Map<string, JsonWebKey>;
  readonly expiresAtMs: number;
};

type AppSessionVersionRecord = {
  readonly version: 'app_session_version_v1';
  readonly userId: string;
  readonly appSessionVersion: string;
  readonly createdAtMs: number;
  readonly updatedAtMs: number;
};

type IdentitySubjectRecord = {
  readonly version: 'identity_subject_v1';
  readonly subject: string;
  readonly userId: string;
  readonly createdAtMs: number;
  readonly updatedAtMs: number;
};

type WebAuthnCredentialBindingRecord = {
  readonly rpId: string;
  readonly credentialIdB64u: string;
  readonly userId: string;
  readonly signerSlot: number;
  readonly publicKey?: string;
  readonly createdAtMs?: number;
  readonly updatedAtMs?: number;
};

type NearPublicKeyRecord = {
  readonly publicKey: string;
  readonly kind: 'threshold' | 'local' | 'backup' | 'ephemeral';
  readonly signerSlot?: number;
  readonly credentialIdB64u?: string;
  readonly rpId?: string;
  readonly createdAtMs?: number;
  readonly updatedAtMs?: number;
};

type EmailOtpOutboxEntry = {
  readonly walletId: string;
  readonly userId: string;
  readonly otpChannel: typeof EMAIL_OTP_CHANNEL;
  readonly emailHint: string;
  readonly otpCode: string;
  readonly expiresAtMs: number;
};

type EmailOtpAuthStatePatch = {
  readonly otpFailureCount?: number | null;
  readonly lastOtpFailureAtMs?: number | null;
  readonly otpLockedUntilMs?: number | null;
  readonly lastEmailOtpLoginAtMs?: number | null;
  readonly lastStrongAuthAtMs?: number | null;
};

type EmailOtpRateLimitScope =
  | 'challenge'
  | 'verify'
  | 'grant'
  | 'recoveryKeyAttempt'
  | 'googleRegistrationAttempt';
type EmailOtpExistingChallengeAction =
  | typeof WALLET_EMAIL_OTP_ACTIONS.login
  | typeof WALLET_EMAIL_OTP_ACTIONS.deviceRecovery;

type EmailOtpRecoveryChallengeEscrow = Omit<
  EmailOtpRecoveryWrappedEnrollmentEscrowRecord,
  | 'recoveryKeyId'
  | 'recoveryKeyStatus'
  | 'issuedAtMs'
  | 'updatedAtMs'
  | 'consumedAtMs'
  | 'revokedAtMs'
>;

type EmailOtpExistingChallengeIssueInput = {
  readonly userId?: unknown;
  readonly walletId?: unknown;
  readonly orgId?: unknown;
  readonly otpChannel?: unknown;
  readonly sessionHash?: unknown;
  readonly appSessionVersion?: unknown;
  readonly clientIp?: unknown;
  readonly reuseActiveChallenge?: unknown;
  readonly action: EmailOtpExistingChallengeAction;
  readonly operation: EmailOtpChallengeOperation;
};

type EmailOtpExistingChallengeIssueResult =
  | {
      ok: true;
      challenge: {
        readonly challengeId: string;
        readonly issuedAtMs: number;
        readonly expiresAtMs: number;
        readonly challengeSubjectId: string;
        readonly walletId: string;
        readonly orgId: string;
        readonly otpChannel: typeof EMAIL_OTP_CHANNEL;
        readonly sessionHash: string;
        readonly appSessionVersion: string;
        readonly action: EmailOtpExistingChallengeAction;
        readonly operation: EmailOtpChallengeOperation;
      };
      delivery: {
        readonly status: 'sent' | 'reused';
        readonly mode: EmailOtpDeliveryMode;
        readonly emailHint: string;
      };
    }
  | {
      ok: false;
      code: string;
      message: string;
      lockedUntilMs?: number;
      retryAfterMs?: number;
      resetAtMs?: number;
    };

type EmailOtpExistingChallengeVerifyInput = {
  readonly userId?: unknown;
  readonly walletId?: unknown;
  readonly orgId?: unknown;
  readonly challengeId?: unknown;
  readonly otpCode?: unknown;
  readonly otpChannel?: unknown;
  readonly sessionHash?: unknown;
  readonly appSessionVersion?: unknown;
  readonly clientIp?: unknown;
  readonly action: EmailOtpExistingChallengeAction;
  readonly operation: EmailOtpChallengeOperation;
};

type EmailOtpExistingChallengeVerifyResult =
  | {
      ok: true;
      readonly challengeId: string;
      readonly userId: string;
      readonly walletId: string;
      readonly orgId: string;
      readonly otpChannel: typeof EMAIL_OTP_CHANNEL;
      readonly sessionHash: string;
      readonly appSessionVersion: string;
      readonly enrollment: EmailOtpWalletEnrollmentRecord;
    }
  | {
      ok: false;
      code: string;
      message: string;
      attemptsRemaining?: number;
      lockedUntilMs?: number;
      retryAfterMs?: number;
      resetAtMs?: number;
    };

function requireD1RelayAuthScopeString(input: unknown, field: string): string {
  const value = toOptionalTrimmedString(input);
  if (!value) throw new Error(`${field} is required for Cloudflare D1 relay auth service`);
  return value;
}

function parseBooleanFlag(input: unknown, fallback: boolean, field: string): boolean {
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

function isTrueFlag(input: unknown): boolean {
  return input === true || String(input || '').trim().toLowerCase() === 'true';
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
    case 'memory':
      return value;
    default:
      throw new Error('emailOtpDeliveryMode must be one of email_provider, log, or memory');
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
  input: CloudflareD1RelayAuthServiceOptions,
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
      deliveryMode === 'memory' &&
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

function normalizeD1RelayAuthOptions(
  input: CloudflareD1RelayAuthServiceOptions,
): NormalizedCloudflareD1RelayAuthServiceOptions {
  return {
    database: input.database,
    namespace: requireD1RelayAuthScopeString(input.namespace, 'namespace'),
    orgId: requireD1RelayAuthScopeString(input.orgId, 'orgId'),
    projectId: requireD1RelayAuthScopeString(input.projectId, 'projectId'),
    envId: requireD1RelayAuthScopeString(input.envId, 'envId'),
    relayerAccount: toOptionalTrimmedString(input.relayerAccount),
    relayerPublicKey: toOptionalTrimmedString(input.relayerPublicKey),
    googleOidcClientId: toOptionalTrimmedString(input.googleOidcClientId),
    accountIdDerivationSecret: toOptionalTrimmedString(input.accountIdDerivationSecret),
    emailOtp: normalizeEmailOtpConfig(input),
  };
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error || '');
}

function appSessionVersion(): string {
  return secureRandomBase64Url(32, 'app session versions');
}

function isRecord(input: unknown): input is Record<string, unknown> {
  return Boolean(input) && typeof input === 'object' && !Array.isArray(input);
}

function parseJsonObject(input: unknown): Record<string, unknown> | null {
  if (isRecord(input)) return input;
  if (typeof input !== 'string') return null;
  try {
    const parsed: unknown = JSON.parse(input);
    return isRecord(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

function positiveInteger(input: unknown): number | null {
  const value = typeof input === 'number' ? input : Number(input);
  if (!Number.isFinite(value) || value <= 0) return null;
  return Math.floor(value);
}

function positiveSafeInteger(input: unknown): number | null {
  const value = typeof input === 'number' ? input : Number(input);
  if (!Number.isSafeInteger(value) || value <= 0) return null;
  return Math.floor(value);
}

function nonNegativeSafeInteger(input: unknown): number | null {
  const value = typeof input === 'number' ? input : Number(input);
  if (!Number.isSafeInteger(value) || value < 0) return null;
  return Math.floor(value);
}

function isB64uString(input: string): boolean {
  return /^[A-Za-z0-9_-]+$/.test(input);
}

function parseRuntimePolicyScope(input: unknown): RuntimePolicyScope | undefined {
  const record = parseJsonObject(input);
  if (!record) return undefined;
  const orgId = toOptionalTrimmedString(record.orgId);
  const projectId = toOptionalTrimmedString(record.projectId);
  const envId = toOptionalTrimmedString(record.envId);
  const signingRootVersion = toOptionalTrimmedString(record.signingRootVersion);
  if (!orgId || !projectId || !envId || !signingRootVersion) return undefined;
  return { orgId, projectId, envId, signingRootVersion };
}

function requireRuntimePolicyScope(input: unknown): RuntimePolicyScope {
  const scope = parseRuntimePolicyScope(input);
  if (scope) return scope;
  throw new Error(
    'runtimePolicyScope.orgId, runtimePolicyScope.projectId, runtimePolicyScope.envId, and runtimePolicyScope.signingRootVersion are required for Google Email OTP registration',
  );
}

function runtimePolicyScopeKey(scope: RuntimePolicyScope | undefined): string {
  if (!scope) return '';
  return `${scope.orgId}\n${scope.projectId}\n${scope.envId}\n${scope.signingRootVersion}`;
}

function parseGoogleEmailOtpRegistrationOfferCandidate(
  input: unknown,
): GoogleEmailOtpRegistrationOfferCandidateRecord | null {
  const record = parseJsonObject(input);
  if (!record) return null;
  const candidateId = toOptionalTrimmedString(record.candidateId);
  const walletId = toOptionalTrimmedString(record.walletId);
  const collisionCounter = nonNegativeSafeInteger(record.collisionCounter);
  if (!candidateId || !walletId || collisionCounter == null) return null;
  return { candidateId, walletId, collisionCounter };
}

function parseGoogleEmailOtpRegistrationOfferCandidates(
  input: unknown,
): NonEmptyGoogleEmailOtpRegistrationOfferCandidates | null {
  if (!Array.isArray(input)) return null;
  const candidates: GoogleEmailOtpRegistrationOfferCandidateRecord[] = [];
  for (const item of input) {
    const candidate = parseGoogleEmailOtpRegistrationOfferCandidate(item);
    if (!candidate) return null;
    candidates.push(candidate);
  }
  const first = candidates[0];
  if (!first) return null;
  return [first, ...candidates.slice(1)];
}

function googleEmailOtpRegistrationOfferContainsCandidate(input: {
  readonly candidates: NonEmptyGoogleEmailOtpRegistrationOfferCandidates;
  readonly candidateId: string;
}): boolean {
  for (const candidate of input.candidates) {
    if (candidate.candidateId === input.candidateId) return true;
  }
  return false;
}

function googleEmailOtpRegistrationAttemptState(
  input: unknown,
): GoogleEmailOtpRegistrationAttemptRecord['state'] | null {
  const state = toOptionalTrimmedString(input);
  switch (state) {
    case 'started':
    case 'key_finalized':
    case 'active':
    case 'abandoned':
    case 'failed':
    case 'expired':
      return state;
    default:
      return null;
  }
}

type GoogleEmailOtpRegistrationAttemptParseFields = {
  readonly attemptId: string;
  readonly providerSubject: string;
  readonly email: string;
  readonly walletId: string;
  readonly offerId: string;
  readonly offerCandidates: NonEmptyGoogleEmailOtpRegistrationOfferCandidates;
  readonly selectedCandidateId: string;
  readonly appSessionVersion: string;
  readonly authProvider: string;
  readonly accountIdSlugVersion: 'hmac_readable_v1';
  readonly walletIdDerivationNonce: string;
  readonly collisionCounter: number;
  readonly createdAtMs: number;
  readonly updatedAtMs: number;
  readonly expiresAtMs: number;
  readonly runtimePolicyScope?: RuntimePolicyScope;
};

function startedGoogleEmailOtpRegistrationAttemptRecord(
  input: GoogleEmailOtpRegistrationAttemptParseFields,
): GoogleEmailOtpRegistrationAttemptRecord {
  return {
    version: 'google_email_otp_registration_attempt_v1',
    attemptId: input.attemptId,
    providerSubject: input.providerSubject,
    email: input.email,
    walletId: input.walletId,
    offerId: input.offerId,
    offerCandidates: input.offerCandidates,
    selectedCandidateId: input.selectedCandidateId,
    appSessionVersion: input.appSessionVersion,
    authProvider: input.authProvider,
    accountIdSlugVersion: 'hmac_readable_v1',
    walletIdDerivationNonce: input.walletIdDerivationNonce,
    collisionCounter: input.collisionCounter,
    state: 'started',
    createdAtMs: input.createdAtMs,
    updatedAtMs: input.updatedAtMs,
    expiresAtMs: input.expiresAtMs,
    ...(input.runtimePolicyScope ? { runtimePolicyScope: input.runtimePolicyScope } : {}),
  };
}

function keyFinalizedGoogleEmailOtpRegistrationAttemptRecord(
  input: GoogleEmailOtpRegistrationAttemptParseFields & { readonly finalizedPublicKey: string },
): GoogleEmailOtpRegistrationAttemptRecord {
  return {
    version: 'google_email_otp_registration_attempt_v1',
    attemptId: input.attemptId,
    providerSubject: input.providerSubject,
    email: input.email,
    walletId: input.walletId,
    offerId: input.offerId,
    offerCandidates: input.offerCandidates,
    selectedCandidateId: input.selectedCandidateId,
    appSessionVersion: input.appSessionVersion,
    authProvider: input.authProvider,
    accountIdSlugVersion: 'hmac_readable_v1',
    walletIdDerivationNonce: input.walletIdDerivationNonce,
    collisionCounter: input.collisionCounter,
    state: 'key_finalized',
    finalizedPublicKey: input.finalizedPublicKey,
    createdAtMs: input.createdAtMs,
    updatedAtMs: input.updatedAtMs,
    expiresAtMs: input.expiresAtMs,
    ...(input.runtimePolicyScope ? { runtimePolicyScope: input.runtimePolicyScope } : {}),
  };
}

function terminalGoogleEmailOtpRegistrationAttemptRecord(input: {
  readonly fields: GoogleEmailOtpRegistrationAttemptParseFields;
  readonly state: 'active' | 'abandoned' | 'failed' | 'expired';
  readonly finalizedPublicKey?: string;
  readonly failureCode?: string;
}): GoogleEmailOtpRegistrationAttemptRecord | null {
  const fields = input.fields;
  switch (input.state) {
    case 'active':
      return {
        version: 'google_email_otp_registration_attempt_v1',
        attemptId: fields.attemptId,
        providerSubject: fields.providerSubject,
        email: fields.email,
        walletId: fields.walletId,
        offerId: fields.offerId,
        offerCandidates: fields.offerCandidates,
        selectedCandidateId: fields.selectedCandidateId,
        appSessionVersion: fields.appSessionVersion,
        authProvider: fields.authProvider,
        accountIdSlugVersion: 'hmac_readable_v1',
        walletIdDerivationNonce: fields.walletIdDerivationNonce,
        collisionCounter: fields.collisionCounter,
        state: 'active',
        createdAtMs: fields.createdAtMs,
        updatedAtMs: fields.updatedAtMs,
        expiresAtMs: fields.expiresAtMs,
        ...(fields.runtimePolicyScope ? { runtimePolicyScope: fields.runtimePolicyScope } : {}),
        ...(input.finalizedPublicKey ? { finalizedPublicKey: input.finalizedPublicKey } : {}),
      };
    case 'abandoned':
      if (!input.failureCode) return null;
      return {
        version: 'google_email_otp_registration_attempt_v1',
        attemptId: fields.attemptId,
        providerSubject: fields.providerSubject,
        email: fields.email,
        walletId: fields.walletId,
        offerId: fields.offerId,
        offerCandidates: fields.offerCandidates,
        selectedCandidateId: fields.selectedCandidateId,
        appSessionVersion: fields.appSessionVersion,
        authProvider: fields.authProvider,
        accountIdSlugVersion: 'hmac_readable_v1',
        walletIdDerivationNonce: fields.walletIdDerivationNonce,
        collisionCounter: fields.collisionCounter,
        state: 'abandoned',
        createdAtMs: fields.createdAtMs,
        updatedAtMs: fields.updatedAtMs,
        expiresAtMs: fields.expiresAtMs,
        ...(fields.runtimePolicyScope ? { runtimePolicyScope: fields.runtimePolicyScope } : {}),
        ...(input.finalizedPublicKey ? { finalizedPublicKey: input.finalizedPublicKey } : {}),
        failureCode: input.failureCode,
      };
    case 'failed':
      if (!input.failureCode) return null;
      return {
        version: 'google_email_otp_registration_attempt_v1',
        attemptId: fields.attemptId,
        providerSubject: fields.providerSubject,
        email: fields.email,
        walletId: fields.walletId,
        offerId: fields.offerId,
        offerCandidates: fields.offerCandidates,
        selectedCandidateId: fields.selectedCandidateId,
        appSessionVersion: fields.appSessionVersion,
        authProvider: fields.authProvider,
        accountIdSlugVersion: 'hmac_readable_v1',
        walletIdDerivationNonce: fields.walletIdDerivationNonce,
        collisionCounter: fields.collisionCounter,
        state: 'failed',
        createdAtMs: fields.createdAtMs,
        updatedAtMs: fields.updatedAtMs,
        expiresAtMs: fields.expiresAtMs,
        ...(fields.runtimePolicyScope ? { runtimePolicyScope: fields.runtimePolicyScope } : {}),
        ...(input.finalizedPublicKey ? { finalizedPublicKey: input.finalizedPublicKey } : {}),
        failureCode: input.failureCode,
      };
    case 'expired':
      return {
        version: 'google_email_otp_registration_attempt_v1',
        attemptId: fields.attemptId,
        providerSubject: fields.providerSubject,
        email: fields.email,
        walletId: fields.walletId,
        offerId: fields.offerId,
        offerCandidates: fields.offerCandidates,
        selectedCandidateId: fields.selectedCandidateId,
        appSessionVersion: fields.appSessionVersion,
        authProvider: fields.authProvider,
        accountIdSlugVersion: 'hmac_readable_v1',
        walletIdDerivationNonce: fields.walletIdDerivationNonce,
        collisionCounter: fields.collisionCounter,
        state: 'expired',
        createdAtMs: fields.createdAtMs,
        updatedAtMs: fields.updatedAtMs,
        expiresAtMs: fields.expiresAtMs,
        ...(fields.runtimePolicyScope ? { runtimePolicyScope: fields.runtimePolicyScope } : {}),
        ...(input.finalizedPublicKey ? { finalizedPublicKey: input.finalizedPublicKey } : {}),
        ...(input.failureCode ? { failureCode: input.failureCode } : {}),
      };
  }
}

function parseGoogleEmailOtpRegistrationAttemptRecord(
  input: unknown,
): GoogleEmailOtpRegistrationAttemptRecord | null {
  const record = parseJsonObject(input);
  if (!record) return null;
  const version = toOptionalTrimmedString(record.version);
  const attemptId = toOptionalTrimmedString(record.attemptId);
  const providerSubject = toOptionalTrimmedString(record.providerSubject);
  const email = toOptionalTrimmedString(record.email);
  const walletId = toOptionalTrimmedString(record.walletId);
  const offerId = toOptionalTrimmedString(record.offerId);
  const offerCandidates = parseGoogleEmailOtpRegistrationOfferCandidates(record.offerCandidates);
  const selectedCandidateId = toOptionalTrimmedString(record.selectedCandidateId);
  const appSessionVersion = toOptionalTrimmedString(record.appSessionVersion);
  const authProvider = toOptionalTrimmedString(record.authProvider);
  const accountIdSlugVersion = toOptionalTrimmedString(record.accountIdSlugVersion);
  const walletIdDerivationNonce = toOptionalTrimmedString(record.walletIdDerivationNonce);
  const collisionCounter = nonNegativeSafeInteger(record.collisionCounter);
  const state = googleEmailOtpRegistrationAttemptState(record.state);
  const createdAtMs = positiveSafeInteger(record.createdAtMs);
  const updatedAtMs = positiveSafeInteger(record.updatedAtMs);
  const expiresAtMs = positiveSafeInteger(record.expiresAtMs);
  const runtimePolicyScope = parseRuntimePolicyScope(record.runtimePolicyScope);
  const finalizedPublicKey = toOptionalTrimmedString(record.finalizedPublicKey);
  const failureCode = toOptionalTrimmedString(record.failureCode);
  if (
    version !== 'google_email_otp_registration_attempt_v1' ||
    !attemptId ||
    !providerSubject ||
    !email ||
    !walletId ||
    !offerId ||
    !offerCandidates ||
    !selectedCandidateId ||
    !googleEmailOtpRegistrationOfferContainsCandidate({
      candidates: offerCandidates,
      candidateId: selectedCandidateId,
    }) ||
    !appSessionVersion ||
    !authProvider ||
    accountIdSlugVersion !== 'hmac_readable_v1' ||
    !walletIdDerivationNonce ||
    !isB64uString(walletIdDerivationNonce) ||
    collisionCounter == null ||
    !state ||
    !createdAtMs ||
    !updatedAtMs ||
    !expiresAtMs ||
    updatedAtMs < createdAtMs
  ) {
    return null;
  }
  if (state === 'key_finalized' && !finalizedPublicKey) return null;
  const fields: GoogleEmailOtpRegistrationAttemptParseFields = {
    attemptId,
    providerSubject,
    email,
    walletId,
    offerId,
    offerCandidates,
    selectedCandidateId,
    appSessionVersion,
    authProvider,
    accountIdSlugVersion: 'hmac_readable_v1',
    walletIdDerivationNonce,
    collisionCounter,
    createdAtMs,
    updatedAtMs,
    expiresAtMs,
    ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
  };
  switch (state) {
    case 'started':
      return startedGoogleEmailOtpRegistrationAttemptRecord(fields);
    case 'key_finalized':
      return keyFinalizedGoogleEmailOtpRegistrationAttemptRecord({
        ...fields,
        finalizedPublicKey: finalizedPublicKey || '',
      });
    case 'active':
    case 'abandoned':
    case 'failed':
    case 'expired':
      return terminalGoogleEmailOtpRegistrationAttemptRecord({
        fields,
        state,
        ...(finalizedPublicKey ? { finalizedPublicKey } : {}),
        ...(failureCode ? { failureCode } : {}),
      });
  }
}

function parseGoogleEmailOtpRegistrationAttemptRow(
  row: D1EmailOtpRegistrationAttemptRow | null,
): GoogleEmailOtpRegistrationAttemptRecord | null {
  const record = parseGoogleEmailOtpRegistrationAttemptRecord(row?.record_json);
  const expiresAtMs = positiveSafeInteger(row?.expires_at_ms);
  const updatedAtMs = positiveSafeInteger(row?.updated_at_ms);
  if (!record || !expiresAtMs || !updatedAtMs) return null;
  if (record.expiresAtMs !== expiresAtMs || record.updatedAtMs !== updatedAtMs) return null;
  return record;
}

function registrationAttemptMatchesStartedScope(
  record: GoogleEmailOtpRegistrationAttemptRecord,
  input: {
    readonly providerSubject: string;
    readonly email: string;
    readonly orgId: string;
    readonly appSessionVersion: string;
    readonly runtimePolicyScope?: RuntimePolicyScope;
    readonly nowMs: number;
  },
): record is PendingGoogleEmailOtpRegistrationAttemptRecord {
  return (
    record.providerSubject === input.providerSubject &&
    record.email === input.email &&
    record.appSessionVersion === input.appSessionVersion &&
    record.runtimePolicyScope?.orgId === input.orgId &&
    runtimePolicyScopeKey(record.runtimePolicyScope) ===
      runtimePolicyScopeKey(input.runtimePolicyScope) &&
    (record.state === 'started' || record.state === 'key_finalized') &&
    record.expiresAtMs > input.nowMs
  );
}

function registrationAttemptMatchesReplacementScope(
  record: GoogleEmailOtpRegistrationAttemptRecord,
  input: {
    readonly providerSubject: string;
    readonly email: string;
    readonly orgId: string;
    readonly appSessionVersion: string;
    readonly runtimePolicyScope?: RuntimePolicyScope;
    readonly nowMs: number;
  },
): record is PendingGoogleEmailOtpRegistrationAttemptRecord {
  return (
    record.providerSubject === input.providerSubject &&
    record.email === input.email &&
    record.appSessionVersion !== input.appSessionVersion &&
    record.runtimePolicyScope?.orgId === input.orgId &&
    runtimePolicyScopeKey(record.runtimePolicyScope) ===
      runtimePolicyScopeKey(input.runtimePolicyScope) &&
    (record.state === 'started' || record.state === 'key_finalized') &&
    record.expiresAtMs > input.nowMs
  );
}

function googleEmailOtpRegistrationOfferWalletIdsJson(
  candidates: NonEmptyGoogleEmailOtpRegistrationOfferCandidates,
): string {
  const walletIds: string[] = [];
  for (const candidate of candidates) walletIds.push(candidate.walletId);
  return JSON.stringify(walletIds);
}

function googleEmailOtpRegistrationOfferForResponse(
  input: Pick<
    PendingGoogleEmailOtpRegistrationAttemptRecord,
    'offerId' | 'offerCandidates' | 'selectedCandidateId'
  >,
): GoogleEmailOtpRegistrationOfferForResponse {
  const first = input.offerCandidates[0];
  const candidates: { readonly candidateId: string; readonly walletId: string }[] = [
    { candidateId: first.candidateId, walletId: first.walletId },
  ];
  for (let index = 1; index < input.offerCandidates.length; index += 1) {
    const candidate = input.offerCandidates[index];
    if (!candidate) continue;
    candidates.push({ candidateId: candidate.candidateId, walletId: candidate.walletId });
  }
  return {
    offerId: input.offerId,
    selectedCandidateId: input.selectedCandidateId,
    candidates: [candidates[0], ...candidates.slice(1)],
  };
}

function pendingGoogleEmailOtpRegistrationAttemptWithUpdatedAt(
  record: PendingGoogleEmailOtpRegistrationAttemptRecord,
  updatedAtMs: number,
): PendingGoogleEmailOtpRegistrationAttemptRecord {
  if (record.state === 'started') {
    return {
      version: 'google_email_otp_registration_attempt_v1',
      attemptId: record.attemptId,
      providerSubject: record.providerSubject,
      email: record.email,
      walletId: record.walletId,
      offerId: record.offerId,
      offerCandidates: record.offerCandidates,
      selectedCandidateId: record.selectedCandidateId,
      appSessionVersion: record.appSessionVersion,
      authProvider: record.authProvider,
      accountIdSlugVersion: 'hmac_readable_v1',
      walletIdDerivationNonce: record.walletIdDerivationNonce,
      collisionCounter: record.collisionCounter,
      state: 'started',
      createdAtMs: record.createdAtMs,
      updatedAtMs,
      expiresAtMs: record.expiresAtMs,
      ...(record.runtimePolicyScope ? { runtimePolicyScope: record.runtimePolicyScope } : {}),
    };
  }
  return {
    version: 'google_email_otp_registration_attempt_v1',
    attemptId: record.attemptId,
    providerSubject: record.providerSubject,
    email: record.email,
    walletId: record.walletId,
    offerId: record.offerId,
    offerCandidates: record.offerCandidates,
    selectedCandidateId: record.selectedCandidateId,
    appSessionVersion: record.appSessionVersion,
    authProvider: record.authProvider,
    accountIdSlugVersion: 'hmac_readable_v1',
    walletIdDerivationNonce: record.walletIdDerivationNonce,
    collisionCounter: record.collisionCounter,
    state: 'key_finalized',
    finalizedPublicKey: record.finalizedPublicKey,
    createdAtMs: record.createdAtMs,
    updatedAtMs,
    expiresAtMs: record.expiresAtMs,
    ...(record.runtimePolicyScope ? { runtimePolicyScope: record.runtimePolicyScope } : {}),
  };
}

function abandonedGoogleEmailOtpRegistrationAttemptRecord(input: {
  readonly record: PendingGoogleEmailOtpRegistrationAttemptRecord;
  readonly failureCode: 'app_session_version_replaced' | 'offer_restarted_by_user';
  readonly updatedAtMs: number;
}): GoogleEmailOtpRegistrationAttemptRecord {
  return {
    version: 'google_email_otp_registration_attempt_v1',
    attemptId: input.record.attemptId,
    providerSubject: input.record.providerSubject,
    email: input.record.email,
    walletId: input.record.walletId,
    offerId: input.record.offerId,
    offerCandidates: input.record.offerCandidates,
    selectedCandidateId: input.record.selectedCandidateId,
    appSessionVersion: input.record.appSessionVersion,
    authProvider: input.record.authProvider,
    accountIdSlugVersion: 'hmac_readable_v1',
    walletIdDerivationNonce: input.record.walletIdDerivationNonce,
    collisionCounter: input.record.collisionCounter,
    state: 'abandoned',
    ...(input.record.state === 'key_finalized'
      ? { finalizedPublicKey: input.record.finalizedPublicKey }
      : {}),
    failureCode: input.failureCode,
    createdAtMs: input.record.createdAtMs,
    updatedAtMs: input.updatedAtMs,
    expiresAtMs: input.record.expiresAtMs,
    ...(input.record.runtimePolicyScope
      ? { runtimePolicyScope: input.record.runtimePolicyScope }
      : {}),
  };
}

function failedGoogleEmailOtpRegistrationAttemptRecord(input: {
  readonly record: PendingGoogleEmailOtpRegistrationAttemptRecord;
  readonly failureCode: 'non_hmac_readable_wallet_id';
  readonly updatedAtMs: number;
}): GoogleEmailOtpRegistrationAttemptRecord {
  return {
    version: 'google_email_otp_registration_attempt_v1',
    attemptId: input.record.attemptId,
    providerSubject: input.record.providerSubject,
    email: input.record.email,
    walletId: input.record.walletId,
    offerId: input.record.offerId,
    offerCandidates: input.record.offerCandidates,
    selectedCandidateId: input.record.selectedCandidateId,
    appSessionVersion: input.record.appSessionVersion,
    authProvider: input.record.authProvider,
    accountIdSlugVersion: 'hmac_readable_v1',
    walletIdDerivationNonce: input.record.walletIdDerivationNonce,
    collisionCounter: input.record.collisionCounter,
    state: 'failed',
    ...(input.record.state === 'key_finalized'
      ? { finalizedPublicKey: input.record.finalizedPublicKey }
      : {}),
    failureCode: input.failureCode,
    createdAtMs: input.record.createdAtMs,
    updatedAtMs: input.updatedAtMs,
    expiresAtMs: input.record.expiresAtMs,
    ...(input.record.runtimePolicyScope
      ? { runtimePolicyScope: input.record.runtimePolicyScope }
      : {}),
  };
}

function hasDifferentWalletIdentitySubject(input: {
  readonly subjects: readonly string[];
  readonly expectedWalletSubject: string;
}): boolean {
  for (const subject of input.subjects) {
    if (subject.startsWith('wallet:') && subject !== input.expectedWalletSubject) return true;
  }
  return false;
}

function googleEmailOtpStaleIdentityMapping(input: {
  readonly providerSubject: string;
  readonly linkedWalletId: string;
  readonly email?: string;
}): Extract<ResolveGoogleEmailOtpSessionResult, { readonly ok: false }> {
  return {
    ok: false,
    mode: 'stale_identity_mapping',
    code: 'stale_identity_mapping',
    walletId: input.linkedWalletId,
    providerSubject: input.providerSubject,
    ...(input.email ? { email: input.email } : {}),
    message:
      'Google Email OTP identity mapping is stale. Clear the stale identity mapping with the dev cleanup route before registering this Google account.',
  };
}

function optionalNonNegativeInteger(input: unknown): number | undefined {
  const value = typeof input === 'number' ? input : Number(input);
  if (!Number.isFinite(value) || value < 0) return undefined;
  return Math.floor(value);
}

function parseAppSessionCreatedAt(input: unknown, fallback: number): number {
  const record = parseJsonObject(input);
  const value = positiveInteger(record?.createdAtMs);
  return value ?? fallback;
}

function parseIdentityCreatedAt(input: unknown, fallback: number): number {
  return positiveInteger(input) ?? fallback;
}

function parseIdentitySubjectCount(input: unknown): number {
  const value = typeof input === 'number' ? input : Number(input);
  return Number.isFinite(value) && value >= 0 ? Math.floor(value) : 0;
}

function d1MutationChanges(result: D1ResultLike<unknown>): number {
  const value = result.meta?.changes ?? result.meta?.rows_written;
  return parseIdentitySubjectCount(value);
}

function identitySubjectRecord(input: {
  readonly subject: string;
  readonly userId: string;
  readonly createdAtMs: number;
  readonly updatedAtMs: number;
}): IdentitySubjectRecord {
  return {
    version: 'identity_subject_v1',
    subject: input.subject,
    userId: input.userId,
    createdAtMs: input.createdAtMs,
    updatedAtMs: input.updatedAtMs,
  };
}

function hasRecordField(record: Record<string, unknown>, field: string): boolean {
  return Object.prototype.hasOwnProperty.call(record, field);
}

function parseEmailOtpWalletEnrollmentRecord(
  input: unknown,
): EmailOtpWalletEnrollmentRecord | null {
  const record = parseJsonObject(input);
  if (!record || hasRecordField(record, 'enrollmentEscrowCiphertextB64u')) return null;
  const version = toOptionalTrimmedString(record.version);
  const walletId = toOptionalTrimmedString(record.walletId);
  const providerUserId = toOptionalTrimmedString(record.providerUserId);
  const orgId = toOptionalTrimmedString(record.orgId);
  const verifiedEmail = toOptionalTrimmedString(record.verifiedEmail)?.toLowerCase() || '';
  const enrollmentId = toOptionalTrimmedString(record.enrollmentId);
  const enrollmentVersion = toOptionalTrimmedString(record.enrollmentVersion);
  const enrollmentSealKeyVersion = toOptionalTrimmedString(record.enrollmentSealKeyVersion);
  const signingRootId = toOptionalTrimmedString(record.signingRootId);
  const signingRootVersion = toOptionalTrimmedString(record.signingRootVersion);
  const recoveryWrappedEnrollmentEscrowCount = positiveSafeInteger(
    record.recoveryWrappedEnrollmentEscrowCount,
  );
  const clientUnlockPublicKeyB64u = toOptionalTrimmedString(record.clientUnlockPublicKeyB64u);
  const unlockKeyVersion = toOptionalTrimmedString(record.unlockKeyVersion);
  const thresholdEcdsaClientVerifyingShareB64u = toOptionalTrimmedString(
    record.thresholdEcdsaClientVerifyingShareB64u,
  );
  const createdAtMs = positiveSafeInteger(record.createdAtMs);
  const updatedAtMs = positiveSafeInteger(record.updatedAtMs);
  if (
    version !== 'email_otp_wallet_enrollment_v1' ||
    !walletId ||
    !providerUserId ||
    !orgId ||
    !verifiedEmail ||
    !enrollmentId ||
    !enrollmentVersion ||
    !enrollmentSealKeyVersion ||
    !signingRootId ||
    !signingRootVersion ||
    !recoveryWrappedEnrollmentEscrowCount ||
    !clientUnlockPublicKeyB64u ||
    !unlockKeyVersion ||
    !thresholdEcdsaClientVerifyingShareB64u ||
    !createdAtMs ||
    !updatedAtMs ||
    updatedAtMs < createdAtMs
  ) {
    return null;
  }
  return {
    version: 'email_otp_wallet_enrollment_v1',
    walletId,
    providerUserId,
    orgId,
    verifiedEmail,
    enrollmentId,
    enrollmentVersion,
    enrollmentSealKeyVersion,
    signingRootId,
    signingRootVersion,
    recoveryWrappedEnrollmentEscrowCount,
    clientUnlockPublicKeyB64u,
    unlockKeyVersion,
    thresholdEcdsaClientVerifyingShareB64u,
    createdAtMs,
    updatedAtMs,
  };
}

function parseEmailOtpWalletEnrollmentRow(
  row: D1EmailOtpEnrollmentRow | null,
): EmailOtpWalletEnrollmentRecord | null {
  const record = parseEmailOtpWalletEnrollmentRecord(row?.record_json);
  const updatedAtMs = positiveSafeInteger(row?.updated_at_ms);
  if (!record || !updatedAtMs || record.updatedAtMs !== updatedAtMs) return null;
  return record;
}

function optionalPositiveSafeIntegerField(
  record: Record<string, unknown>,
  field: string,
): number | undefined | null {
  if (!hasRecordField(record, field) || record[field] == null) return undefined;
  return positiveSafeInteger(record[field]);
}

function optionalNonNegativeSafeIntegerField(
  record: Record<string, unknown>,
  field: string,
): number | undefined | null {
  if (!hasRecordField(record, field) || record[field] == null) return undefined;
  return nonNegativeSafeInteger(record[field]);
}

function parseEmailOtpAuthStateRecord(input: unknown): EmailOtpAuthStateRecord | null {
  const record = parseJsonObject(input);
  if (!record) return null;
  const version = toOptionalTrimmedString(record.version);
  const walletId = toOptionalTrimmedString(record.walletId);
  const providerUserId = toOptionalTrimmedString(record.providerUserId);
  const orgId = toOptionalTrimmedString(record.orgId);
  const createdAtMs = positiveSafeInteger(record.createdAtMs);
  const updatedAtMs = positiveSafeInteger(record.updatedAtMs);
  const otpFailureCount = optionalNonNegativeSafeIntegerField(record, 'otpFailureCount');
  const lastOtpFailureAtMs = optionalPositiveSafeIntegerField(record, 'lastOtpFailureAtMs');
  const otpLockedUntilMs = optionalPositiveSafeIntegerField(record, 'otpLockedUntilMs');
  const lastEmailOtpLoginAtMs = optionalPositiveSafeIntegerField(
    record,
    'lastEmailOtpLoginAtMs',
  );
  const lastStrongAuthAtMs = optionalPositiveSafeIntegerField(record, 'lastStrongAuthAtMs');
  if (
    version !== 'email_otp_auth_state_v1' ||
    !walletId ||
    !providerUserId ||
    !orgId ||
    !createdAtMs ||
    !updatedAtMs ||
    otpFailureCount === null ||
    lastOtpFailureAtMs === null ||
    otpLockedUntilMs === null ||
    lastEmailOtpLoginAtMs === null ||
    lastStrongAuthAtMs === null ||
    updatedAtMs < createdAtMs
  ) {
    return null;
  }
  return {
    version: 'email_otp_auth_state_v1',
    walletId,
    providerUserId,
    orgId,
    createdAtMs,
    updatedAtMs,
    ...(otpFailureCount != null ? { otpFailureCount } : {}),
    ...(lastOtpFailureAtMs != null ? { lastOtpFailureAtMs } : {}),
    ...(otpLockedUntilMs != null ? { otpLockedUntilMs } : {}),
    ...(lastEmailOtpLoginAtMs != null ? { lastEmailOtpLoginAtMs } : {}),
    ...(lastStrongAuthAtMs != null ? { lastStrongAuthAtMs } : {}),
  };
}

function parseEmailOtpAuthStateRow(
  row: D1EmailOtpAuthStateRow | null,
): EmailOtpAuthStateRecord | null {
  const record = parseEmailOtpAuthStateRecord(row?.record_json);
  const updatedAtMs = positiveSafeInteger(row?.updated_at_ms);
  if (!record || !updatedAtMs || record.updatedAtMs !== updatedAtMs) return null;
  return record;
}

function parseEmailOtpChallengeOperation(input: unknown): EmailOtpChallengeOperation | null {
  const operation = toOptionalTrimmedString(input);
  if (!operation) return null;
  if (isWalletEmailOtpLoginOperation(operation)) return operation;
  return null;
}

function parseEmailOtpChallengeAction(input: unknown): EmailOtpExistingChallengeAction | null {
  const action = toOptionalTrimmedString(input);
  switch (action) {
    case WALLET_EMAIL_OTP_ACTIONS.login:
    case WALLET_EMAIL_OTP_ACTIONS.deviceRecovery:
      return action;
    default:
      return null;
  }
}

function parseEmailOtpLoginOperation(input: unknown): EmailOtpLoginChallengeOperation {
  const operation = toOptionalTrimmedString(input);
  if (operation && isWalletEmailOtpLoginOperation(operation)) return operation;
  return WALLET_EMAIL_OTP_UNLOCK_OPERATION;
}

function emailOtpExistingChallengePurposeIsValid(input: {
  readonly action: EmailOtpExistingChallengeAction;
  readonly operation: EmailOtpChallengeOperation;
}): boolean {
  switch (input.action) {
    case WALLET_EMAIL_OTP_ACTIONS.login:
      return isWalletEmailOtpLoginOperation(input.operation);
    case WALLET_EMAIL_OTP_ACTIONS.deviceRecovery:
      return input.operation === WALLET_EMAIL_OTP_UNLOCK_OPERATION;
  }
}

function parseEmailOtpChallengeRecord(input: unknown): EmailOtpChallengeRecord | null {
  const record = parseJsonObject(input);
  if (!record) return null;
  const version = toOptionalTrimmedString(record.version);
  const challengeId = toOptionalTrimmedString(record.challengeId);
  const challengeSubjectId = toOptionalTrimmedString(record.challengeSubjectId);
  const walletId = toOptionalTrimmedString(record.walletId);
  const orgId = toOptionalTrimmedString(record.orgId);
  const otpChannel = toOptionalTrimmedString(record.otpChannel);
  const email = toOptionalTrimmedString(record.email)?.toLowerCase() || '';
  const otpCode = toOptionalTrimmedString(record.otpCode);
  const sessionHash = toOptionalTrimmedString(record.sessionHash);
  const appSessionVersion = toOptionalTrimmedString(record.appSessionVersion);
  const action = parseEmailOtpChallengeAction(record.action);
  const operation = parseEmailOtpChallengeOperation(record.operation);
  const createdAtMs = positiveSafeInteger(record.createdAtMs);
  const expiresAtMs = positiveSafeInteger(record.expiresAtMs);
  const attemptCount = nonNegativeSafeInteger(record.attemptCount);
  const maxAttempts = positiveSafeInteger(record.maxAttempts);
  if (
    version !== 'email_otp_challenge_v1' ||
    !challengeId ||
    !challengeSubjectId ||
    !walletId ||
    !email ||
    !otpCode ||
    !sessionHash ||
    !appSessionVersion ||
    !action ||
    !operation ||
    !emailOtpExistingChallengePurposeIsValid({ action, operation }) ||
    otpChannel !== EMAIL_OTP_CHANNEL ||
    !createdAtMs ||
    !expiresAtMs ||
    attemptCount === null ||
    !maxAttempts ||
    expiresAtMs <= createdAtMs
  ) {
    return null;
  }
  return {
    version: 'email_otp_challenge_v1',
    challengeId,
    challengeSubjectId,
    walletId,
    ...(orgId ? { orgId } : {}),
    otpChannel: EMAIL_OTP_CHANNEL,
    email,
    otpCode,
    sessionHash,
    appSessionVersion,
    action,
    operation,
    createdAtMs,
    expiresAtMs,
    attemptCount,
    maxAttempts,
  };
}

function parseEmailOtpChallengeRow(
  row: D1EmailOtpChallengeRow | null,
): EmailOtpChallengeRecord | null {
  const record = parseEmailOtpChallengeRecord(row?.record_json);
  const expiresAtMs = positiveSafeInteger(row?.expires_at_ms);
  if (!record || !expiresAtMs || record.expiresAtMs !== expiresAtMs) return null;
  return record;
}

function parseEmailOtpUnlockChallengeRecord(
  input: unknown,
): EmailOtpUnlockChallengeRecord | null {
  const record = parseJsonObject(input);
  if (!record) return null;
  const version = toOptionalTrimmedString(record.version);
  const challengeId = toOptionalTrimmedString(record.challengeId);
  const walletId = toOptionalTrimmedString(record.walletId);
  const userId = toOptionalTrimmedString(record.userId);
  const orgId = toOptionalTrimmedString(record.orgId);
  const challengeB64u = toOptionalTrimmedString(record.challengeB64u);
  const createdAtMs = positiveSafeInteger(record.createdAtMs);
  const expiresAtMs = positiveSafeInteger(record.expiresAtMs);
  if (
    version !== 'email_otp_unlock_challenge_v1' ||
    !challengeId ||
    !walletId ||
    !userId ||
    !challengeB64u ||
    !createdAtMs ||
    !expiresAtMs ||
    expiresAtMs <= createdAtMs
  ) {
    return null;
  }
  return {
    version: 'email_otp_unlock_challenge_v1',
    challengeId,
    walletId,
    userId,
    ...(orgId ? { orgId } : {}),
    challengeB64u,
    createdAtMs,
    expiresAtMs,
  };
}

function parseEmailOtpUnlockChallengeRow(
  row: D1EmailOtpUnlockChallengeRow | null,
): EmailOtpUnlockChallengeRecord | null {
  const record = parseEmailOtpUnlockChallengeRecord(row?.record_json);
  const expiresAtMs = positiveSafeInteger(row?.expires_at_ms);
  if (!record || !expiresAtMs || record.expiresAtMs !== expiresAtMs) return null;
  return record;
}

function emailOtpChallengeContextValues(input: {
  readonly challengeSubjectId: string;
  readonly walletId: string;
  readonly orgId: string;
  readonly sessionHash: string;
  readonly appSessionVersion: string;
  readonly action: EmailOtpExistingChallengeAction;
  readonly operation: EmailOtpChallengeOperation;
}): readonly unknown[] {
  return [
    input.challengeSubjectId,
    input.walletId,
    input.orgId,
    EMAIL_OTP_CHANNEL,
    input.sessionHash,
    input.appSessionVersion,
    input.action,
    input.operation,
  ];
}

function emailOtpChallengeRecord(input: {
  readonly challengeId: string;
  readonly challengeSubjectId: string;
  readonly walletId: string;
  readonly orgId: string;
  readonly email: string;
  readonly otpCode: string;
  readonly sessionHash: string;
  readonly appSessionVersion: string;
  readonly action: EmailOtpExistingChallengeAction;
  readonly operation: EmailOtpChallengeOperation;
  readonly createdAtMs: number;
  readonly expiresAtMs: number;
  readonly maxAttempts: number;
}): EmailOtpChallengeRecord {
  return {
    version: 'email_otp_challenge_v1',
    challengeId: input.challengeId,
    challengeSubjectId: input.challengeSubjectId,
    walletId: input.walletId,
    orgId: input.orgId,
    otpChannel: EMAIL_OTP_CHANNEL,
    email: input.email,
    otpCode: input.otpCode,
    sessionHash: input.sessionHash,
    appSessionVersion: input.appSessionVersion,
    action: input.action,
    operation: input.operation,
    createdAtMs: input.createdAtMs,
    expiresAtMs: input.expiresAtMs,
    attemptCount: 0,
    maxAttempts: input.maxAttempts,
  };
}

function emailOtpGrantRecord(input: {
  readonly grantToken: string;
  readonly userId: string;
  readonly walletId: string;
  readonly orgId: string;
  readonly challengeId: string;
  readonly sessionHash: string;
  readonly appSessionVersion: string;
  readonly action: EmailOtpGrantAction;
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
}): EmailOtpGrantRecord {
  return {
    version: 'email_otp_grant_v1',
    grantToken: input.grantToken,
    userId: input.userId,
    walletId: input.walletId,
    orgId: input.orgId,
    challengeId: input.challengeId,
    otpChannel: EMAIL_OTP_CHANNEL,
    sessionHash: input.sessionHash,
    appSessionVersion: input.appSessionVersion,
    action: input.action,
    issuedAtMs: input.issuedAtMs,
    expiresAtMs: input.expiresAtMs,
  };
}

function emailOtpUnlockChallengeRecord(input: {
  readonly challengeId: string;
  readonly walletId: string;
  readonly userId: string;
  readonly orgId: string;
  readonly challengeB64u: string;
  readonly createdAtMs: number;
  readonly expiresAtMs: number;
}): EmailOtpUnlockChallengeRecord {
  return {
    version: 'email_otp_unlock_challenge_v1',
    challengeId: input.challengeId,
    walletId: input.walletId,
    userId: input.userId,
    orgId: input.orgId,
    challengeB64u: input.challengeB64u,
    createdAtMs: input.createdAtMs,
    expiresAtMs: input.expiresAtMs,
  };
}

function parseEmailOtpGrantRecord(input: unknown): EmailOtpGrantRecord | null {
  const record = parseJsonObject(input);
  if (!record) return null;
  const version = toOptionalTrimmedString(record.version);
  const grantToken = toOptionalTrimmedString(record.grantToken);
  const userId = toOptionalTrimmedString(record.userId);
  const walletId = toOptionalTrimmedString(record.walletId);
  const orgId = toOptionalTrimmedString(record.orgId);
  const challengeId = toOptionalTrimmedString(record.challengeId);
  const otpChannel = toOptionalTrimmedString(record.otpChannel);
  const sessionHash = toOptionalTrimmedString(record.sessionHash);
  const appSessionVersion = toOptionalTrimmedString(record.appSessionVersion);
  const action = toOptionalTrimmedString(record.action);
  const issuedAtMs = positiveSafeInteger(record.issuedAtMs);
  const expiresAtMs = positiveSafeInteger(record.expiresAtMs);
  if (
    version !== 'email_otp_grant_v1' ||
    !grantToken ||
    !userId ||
    !walletId ||
    !challengeId ||
    otpChannel !== EMAIL_OTP_CHANNEL ||
    !sessionHash ||
    !appSessionVersion ||
    !action ||
    !issuedAtMs ||
    !expiresAtMs ||
    expiresAtMs <= issuedAtMs
  ) {
    return null;
  }
  if (
    action !== WALLET_EMAIL_OTP_ACTIONS.unseal &&
    action !== WALLET_EMAIL_OTP_ACTIONS.deviceRecovery
  ) {
    return null;
  }
  return {
    version: 'email_otp_grant_v1',
    grantToken,
    userId,
    walletId,
    ...(orgId ? { orgId } : {}),
    challengeId,
    otpChannel: EMAIL_OTP_CHANNEL,
    sessionHash,
    appSessionVersion,
    action,
    issuedAtMs,
    expiresAtMs,
  };
}

function parseEmailOtpGrantRow(row: D1EmailOtpGrantRow | null): EmailOtpGrantRecord | null {
  const record = parseEmailOtpGrantRecord(row?.record_json);
  const expiresAtMs = positiveSafeInteger(row?.expires_at_ms);
  if (!record || !expiresAtMs || record.expiresAtMs !== expiresAtMs) return null;
  return record;
}

function parseEmailOtpRecoveryEscrowRecord(
  input: unknown,
): EmailOtpRecoveryWrappedEnrollmentEscrowRecord | null {
  const record = parseJsonObject(input);
  if (!record) return null;
  const version = toOptionalTrimmedString(record.version);
  const alg = toOptionalTrimmedString(record.alg);
  const secretKind = toOptionalTrimmedString(record.secretKind);
  const escrowKind = toOptionalTrimmedString(record.escrowKind);
  const walletId = toOptionalTrimmedString(record.walletId);
  const userId = toOptionalTrimmedString(record.userId);
  const authSubjectId = toOptionalTrimmedString(record.authSubjectId);
  const authMethod = toOptionalTrimmedString(record.authMethod);
  const enrollmentId = toOptionalTrimmedString(record.enrollmentId);
  const enrollmentVersion = toOptionalTrimmedString(record.enrollmentVersion);
  const enrollmentSealKeyVersion = toOptionalTrimmedString(record.enrollmentSealKeyVersion);
  const signingRootId = toOptionalTrimmedString(record.signingRootId);
  const signingRootVersion = toOptionalTrimmedString(record.signingRootVersion);
  const recoveryKeyId = toOptionalTrimmedString(record.recoveryKeyId);
  const recoveryKeyLabel = toOptionalTrimmedString(record.recoveryKeyLabel);
  const recoveryKeyStatus = toOptionalTrimmedString(record.recoveryKeyStatus);
  const nonceB64u = toOptionalTrimmedString(record.nonceB64u);
  const wrappedDeviceEnrollmentEscrowB64u = toOptionalTrimmedString(
    record.wrappedDeviceEnrollmentEscrowB64u,
  );
  const aadHashB64u = toOptionalTrimmedString(record.aadHashB64u);
  const issuedAtMs = positiveSafeInteger(record.issuedAtMs);
  const updatedAtMs = positiveSafeInteger(record.updatedAtMs);
  const consumedAtMs =
    record.consumedAtMs == null ? undefined : positiveSafeInteger(record.consumedAtMs);
  const revokedAtMs =
    record.revokedAtMs == null ? undefined : positiveSafeInteger(record.revokedAtMs);
  if (
    version !== 'email_otp_recovery_wrapped_enrollment_escrow_v1' ||
    alg !== EMAIL_OTP_RECOVERY_WRAP_ALG ||
    secretKind !== EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_SECRET_KIND ||
    escrowKind !== EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_ESCROW_KIND ||
    !walletId ||
    !userId ||
    !authSubjectId ||
    authMethod !== 'google_sso_email_otp' ||
    !enrollmentId ||
    !enrollmentVersion ||
    !enrollmentSealKeyVersion ||
    !signingRootId ||
    !signingRootVersion ||
    !recoveryKeyId ||
    !nonceB64u ||
    !wrappedDeviceEnrollmentEscrowB64u ||
    !aadHashB64u ||
    !recoveryKeyStatus ||
    !issuedAtMs ||
    !updatedAtMs ||
    userId !== authSubjectId ||
    !isB64uString(nonceB64u) ||
    !isB64uString(wrappedDeviceEnrollmentEscrowB64u) ||
    !isB64uString(aadHashB64u) ||
    hasRecordField(record, 'acknowledgedAtMs') ||
    hasRecordField(record, 'abandonedAtMs') ||
    hasRecordField(record, 'cleanupReason') ||
    updatedAtMs < issuedAtMs
  ) {
    return null;
  }
  const base = {
    version: 'email_otp_recovery_wrapped_enrollment_escrow_v1' as const,
    alg: EMAIL_OTP_RECOVERY_WRAP_ALG,
    secretKind: EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_SECRET_KIND,
    escrowKind: EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_ESCROW_KIND,
    walletId,
    userId,
    authSubjectId,
    authMethod: 'google_sso_email_otp' as const,
    enrollmentId,
    enrollmentVersion,
    enrollmentSealKeyVersion,
    signingRootId,
    signingRootVersion,
    recoveryKeyId,
    ...(recoveryKeyLabel ? { recoveryKeyLabel } : {}),
    nonceB64u,
    wrappedDeviceEnrollmentEscrowB64u,
    aadHashB64u,
    issuedAtMs,
    updatedAtMs,
  };
  switch (recoveryKeyStatus) {
    case 'active':
      if (consumedAtMs !== undefined || revokedAtMs !== undefined) return null;
      return { ...base, recoveryKeyStatus };
    case 'consumed':
      if (consumedAtMs == null || revokedAtMs !== undefined) return null;
      return { ...base, recoveryKeyStatus, consumedAtMs };
    case 'revoked':
      if (consumedAtMs !== undefined || revokedAtMs == null) return null;
      return { ...base, recoveryKeyStatus, revokedAtMs };
    default:
      return null;
  }
}

function parseEmailOtpRecoveryEscrowRow(
  row: D1EmailOtpRecoveryEscrowRow | null,
): EmailOtpRecoveryWrappedEnrollmentEscrowRecord | null {
  const record = parseEmailOtpRecoveryEscrowRecord(row?.record_json);
  const updatedAtMs = positiveSafeInteger(row?.updated_at_ms);
  if (!record || !updatedAtMs || record.updatedAtMs !== updatedAtMs) return null;
  return record;
}

function emailOtpRecoveryEscrowMatchesEnrollment(input: {
  readonly escrow: EmailOtpRecoveryWrappedEnrollmentEscrowRecord;
  readonly enrollment: EmailOtpWalletEnrollmentRecord;
}): boolean {
  return (
    input.escrow.walletId === input.enrollment.walletId &&
    input.escrow.userId === input.enrollment.providerUserId &&
    input.escrow.authSubjectId === input.enrollment.providerUserId &&
    input.escrow.enrollmentId === input.enrollment.enrollmentId &&
    input.escrow.enrollmentVersion === input.enrollment.enrollmentVersion &&
    input.escrow.enrollmentSealKeyVersion === input.enrollment.enrollmentSealKeyVersion &&
    input.escrow.signingRootId === input.enrollment.signingRootId &&
    input.escrow.signingRootVersion === input.enrollment.signingRootVersion
  );
}

function toArrayBufferCopy(bytes: Uint8Array): ArrayBuffer {
  const out = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(out).set(bytes);
  return out;
}

function parseJwtSegmentJson(input: string | undefined): Record<string, unknown> | null {
  if (!input) return null;
  try {
    const decoded = base64UrlDecode(input);
    const parsed: unknown = JSON.parse(new TextDecoder().decode(decoded));
    return isRecord(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

function parseJwtAud(input: unknown): string[] {
  const values: string[] = [];
  if (Array.isArray(input)) {
    for (const item of input) {
      const value = toOptionalTrimmedString(item);
      if (value) values.push(value);
    }
    return values;
  }
  const value = toOptionalTrimmedString(input);
  return value ? [value] : [];
}

function parseCacheControlMaxAgeSec(input: unknown): number | null {
  const header = toOptionalTrimmedString(input);
  if (!header) return null;
  for (const part of header.split(',')) {
    const segment = part.trim().toLowerCase();
    if (!segment.startsWith('max-age=')) continue;
    const value = Number(segment.slice('max-age='.length));
    if (Number.isFinite(value) && value > 0) return Math.floor(value);
  }
  return null;
}

function parseGoogleJwks(input: unknown): Map<string, JsonWebKey> | null {
  if (!isRecord(input)) return null;
  const rawKeys = input.keys;
  if (!Array.isArray(rawKeys)) return null;
  const keysByKid = new Map<string, JsonWebKey>();
  for (const rawKey of rawKeys) {
    if (!isRecord(rawKey)) continue;
    const kid = toOptionalTrimmedString(rawKey.kid);
    const kty = toOptionalTrimmedString(rawKey.kty);
    const use = toOptionalTrimmedString(rawKey.use);
    const alg = toOptionalTrimmedString(rawKey.alg);
    const n = toOptionalTrimmedString(rawKey.n);
    const e = toOptionalTrimmedString(rawKey.e);
    if (!kid || kty !== 'RSA' || use !== 'sig' || alg !== 'RS256' || !n || !e) continue;
    keysByKid.set(kid, {
      kty: 'RSA',
      use: 'sig',
      alg: 'RS256',
      n,
      e,
    });
  }
  return keysByKid.size > 0 ? keysByKid : null;
}

function parseBooleanJwtClaim(input: unknown): boolean | undefined {
  if (typeof input === 'boolean') return input;
  const value = toOptionalTrimmedString(input)?.toLowerCase();
  if (value === 'true') return true;
  if (value === 'false') return false;
  return undefined;
}

async function sha256BytesPortable(input: Uint8Array): Promise<Uint8Array> {
  const subtle = globalThis.crypto?.subtle;
  if (subtle && typeof subtle.digest === 'function') {
    return new Uint8Array(await subtle.digest('SHA-256', toArrayBufferCopy(input)));
  }
  if (typeof process !== 'undefined' && process.versions?.node) {
    const { createHash } = await import('node:crypto');
    return Uint8Array.from(createHash('sha256').update(input).digest());
  }
  throw new Error('SHA-256 digest is unavailable in this runtime');
}

function invalidRecoveryRotationBody(message: string): RotateEmailOtpRecoveryKeysResult {
  return { ok: false, code: 'invalid_body', message };
}

function recoveryRotationBindingMismatch(): RotateEmailOtpRecoveryKeysResult {
  return {
    ok: false,
    code: 'recovery_rotation_binding_mismatch',
    message: 'Recovery-code rotation does not match the active Email OTP enrollment',
  };
}

function recoveryRotationInputObject(input: unknown): Record<string, unknown> | null {
  if (!input || typeof input !== 'object' || Array.isArray(input)) return null;
  return input as Record<string, unknown>;
}

function revokedEmailOtpRecoveryEscrowRecord(input: {
  readonly record: Extract<
    EmailOtpRecoveryWrappedEnrollmentEscrowRecord,
    { readonly recoveryKeyStatus: 'active' }
  >;
  readonly revokedAtMs: number;
}): EmailOtpRecoveryWrappedEnrollmentEscrowRecord {
  return {
    version: input.record.version,
    alg: input.record.alg,
    secretKind: input.record.secretKind,
    escrowKind: input.record.escrowKind,
    walletId: input.record.walletId,
    userId: input.record.userId,
    authSubjectId: input.record.authSubjectId,
    authMethod: input.record.authMethod,
    enrollmentId: input.record.enrollmentId,
    enrollmentVersion: input.record.enrollmentVersion,
    enrollmentSealKeyVersion: input.record.enrollmentSealKeyVersion,
    signingRootId: input.record.signingRootId,
    signingRootVersion: input.record.signingRootVersion,
    recoveryKeyId: input.record.recoveryKeyId,
    ...(input.record.recoveryKeyLabel ? { recoveryKeyLabel: input.record.recoveryKeyLabel } : {}),
    recoveryKeyStatus: 'revoked',
    nonceB64u: input.record.nonceB64u,
    wrappedDeviceEnrollmentEscrowB64u: input.record.wrappedDeviceEnrollmentEscrowB64u,
    aadHashB64u: input.record.aadHashB64u,
    issuedAtMs: input.record.issuedAtMs,
    updatedAtMs: input.revokedAtMs,
    revokedAtMs: input.revokedAtMs,
  };
}

async function activeEmailOtpRecoveryRotationEscrowRecord(input: {
  readonly raw: unknown;
  readonly enrollment: EmailOtpWalletEnrollmentRecord;
  readonly issuedAtMs: number;
  readonly recoveryKeyIds: Set<string>;
  readonly nonceB64us: Set<string>;
}): Promise<
  | { readonly ok: true; readonly record: EmailOtpRecoveryWrappedEnrollmentEscrowRecord }
  | { readonly ok: false; readonly result: RotateEmailOtpRecoveryKeysResult }
> {
  const obj = recoveryRotationInputObject(input.raw);
  if (!obj) {
    return {
      ok: false,
      result: invalidRecoveryRotationBody('Invalid recovery escrow input'),
    };
  }
  const recoveryKeyId = toOptionalTrimmedString(obj.recoveryKeyId);
  const nonceB64u = toOptionalTrimmedString(obj.nonceB64u);
  const wrappedDeviceEnrollmentEscrowB64u = toOptionalTrimmedString(
    obj.wrappedDeviceEnrollmentEscrowB64u,
  );
  const aadHashB64u = toOptionalTrimmedString(obj.aadHashB64u);
  if (!recoveryKeyId || !nonceB64u || !wrappedDeviceEnrollmentEscrowB64u || !aadHashB64u) {
    return {
      ok: false,
      result: invalidRecoveryRotationBody(
        'Recovery rotation escrow input is missing required fields',
      ),
    };
  }
  if (input.recoveryKeyIds.has(recoveryKeyId)) {
    return {
      ok: false,
      result: invalidRecoveryRotationBody(
        'Recovery rotation recoveryKeyId values must be unique',
      ),
    };
  }
  if (input.nonceB64us.has(nonceB64u)) {
    return {
      ok: false,
      result: invalidRecoveryRotationBody('Recovery rotation nonce values must be unique'),
    };
  }
  try {
    base64UrlDecode(nonceB64u);
    base64UrlDecode(wrappedDeviceEnrollmentEscrowB64u);
    base64UrlDecode(aadHashB64u);
  } catch {
    return {
      ok: false,
      result: invalidRecoveryRotationBody(
        'Recovery rotation escrow input must use base64url fields',
      ),
    };
  }
  const binding = buildEmailOtpRecoveryWrapBinding({
    walletId: input.enrollment.walletId,
    userId: input.enrollment.providerUserId,
    authSubjectId: input.enrollment.providerUserId,
    authMethod: 'google_sso_email_otp',
    enrollmentId: input.enrollment.enrollmentId,
    enrollmentVersion: input.enrollment.enrollmentVersion,
    enrollmentSealKeyVersion: input.enrollment.enrollmentSealKeyVersion,
    signingRootId: input.enrollment.signingRootId,
    signingRootVersion: input.enrollment.signingRootVersion,
    recoveryKeyId,
  });
  const expectedAadHashB64u = base64UrlEncode(
    await sha256BytesPortable(encodeEmailOtpRecoveryWrappedEnrollmentAad(binding)),
  );
  if (aadHashB64u !== expectedAadHashB64u) {
    return {
      ok: false,
      result: invalidRecoveryRotationBody(
        'Recovery rotation aadHashB64u does not match enrollment metadata',
      ),
    };
  }
  input.recoveryKeyIds.add(recoveryKeyId);
  input.nonceB64us.add(nonceB64u);
  return {
    ok: true,
    record: {
      version: 'email_otp_recovery_wrapped_enrollment_escrow_v1',
      alg: EMAIL_OTP_RECOVERY_WRAP_ALG,
      secretKind: EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_SECRET_KIND,
      escrowKind: EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_ESCROW_KIND,
      walletId: input.enrollment.walletId,
      userId: input.enrollment.providerUserId,
      authSubjectId: input.enrollment.providerUserId,
      authMethod: 'google_sso_email_otp',
      enrollmentId: input.enrollment.enrollmentId,
      enrollmentVersion: input.enrollment.enrollmentVersion,
      enrollmentSealKeyVersion: input.enrollment.enrollmentSealKeyVersion,
      signingRootId: input.enrollment.signingRootId,
      signingRootVersion: input.enrollment.signingRootVersion,
      recoveryKeyId,
      recoveryKeyStatus: 'active',
      nonceB64u,
      wrappedDeviceEnrollmentEscrowB64u,
      aadHashB64u,
      issuedAtMs: input.issuedAtMs,
      updatedAtMs: input.issuedAtMs,
    },
  };
}

function countActiveEmailOtpRecoveryEscrows(
  records: readonly EmailOtpRecoveryWrappedEnrollmentEscrowRecord[],
): number {
  let count = 0;
  for (const record of records) {
    if (activeEmailOtpRecoveryEscrow(record)) count += 1;
  }
  return count;
}

function normalizeHexLike(input: unknown): string {
  const value = toOptionalTrimmedString(input);
  if (!value) return '';
  return value.startsWith('0x') ? value.toLowerCase() : value;
}

function normalizeAccountAddress(input: unknown): string {
  const value = toOptionalTrimmedString(input);
  if (!value) return '';
  return value.startsWith('0x') ? value.toLowerCase() : value;
}

function parseRecordMetadata(input: unknown): Record<string, unknown> | undefined {
  if (!isRecord(input)) return undefined;
  return { ...input };
}

function parseRecoverySessionStatus(input: unknown): RecoverySessionStatus | null {
  const status = toOptionalTrimmedString(input);
  switch (status) {
    case 'prepared':
    case 'verified':
    case 'near_recovered':
    case 'evm_recovering':
    case 'completed':
    case 'failed':
    case 'cancelled':
      return status;
    default:
      return null;
  }
}

function parseRecoveryExecutionStatus(input: unknown): RecoveryExecutionStatus | null {
  const status = toOptionalTrimmedString(input);
  switch (status) {
    case 'pending':
    case 'submitted':
    case 'confirmed':
    case 'failed':
    case 'skipped':
      return status;
    default:
      return null;
  }
}

function parseRecoverySessionRecord(input: unknown): RecoverySessionRecord | null {
  const record = parseJsonObject(input);
  if (!record) return null;
  const version = toOptionalTrimmedString(record.version);
  const sessionId = toOptionalTrimmedString(record.sessionId);
  const userId = toOptionalTrimmedString(record.userId);
  const nearAccountId = toOptionalTrimmedString(record.nearAccountId);
  const signerSlot = positiveSafeInteger(record.signerSlot);
  const status = parseRecoverySessionStatus(record.status);
  const createdAtMs = positiveSafeInteger(record.createdAtMs);
  const updatedAtMs = positiveSafeInteger(record.updatedAtMs);
  const expiresAtMs = positiveSafeInteger(record.expiresAtMs);
  const newNearPublicKey = toOptionalTrimmedString(record.newNearPublicKey);
  const newEvmOwnerAddress = normalizeHexLike(record.newEvmOwnerAddress);
  const recoveryDeadlineEpochSeconds = positiveSafeInteger(record.recoveryDeadlineEpochSeconds);
  const recoveryEmailPayloadHash = toOptionalTrimmedString(record.recoveryEmailPayloadHash);
  const verifiedRecoveryPayloadHash = toOptionalTrimmedString(record.verifiedRecoveryPayloadHash);
  const verifiedRecoveryArtifactHash = toOptionalTrimmedString(record.verifiedRecoveryArtifactHash);
  const scope = toOptionalTrimmedString(record.scope);
  const metadata = parseRecordMetadata(record.metadata);
  if (
    version !== 'recovery_session_v1' ||
    !sessionId ||
    !userId ||
    !nearAccountId ||
    !signerSlot ||
    !status ||
    !createdAtMs ||
    !updatedAtMs ||
    !expiresAtMs ||
    !newNearPublicKey ||
    !newEvmOwnerAddress ||
    !recoveryDeadlineEpochSeconds ||
    !recoveryEmailPayloadHash
  ) {
    return null;
  }
  return {
    version: 'recovery_session_v1',
    sessionId,
    userId,
    nearAccountId,
    signerSlot,
    status,
    createdAtMs,
    updatedAtMs,
    expiresAtMs,
    newNearPublicKey,
    newEvmOwnerAddress,
    recoveryDeadlineEpochSeconds,
    recoveryEmailPayloadHash,
    ...(verifiedRecoveryPayloadHash ? { verifiedRecoveryPayloadHash } : {}),
    ...(verifiedRecoveryArtifactHash ? { verifiedRecoveryArtifactHash } : {}),
    ...(scope ? { scope } : {}),
    ...(metadata ? { metadata } : {}),
  };
}

function parseRecoveryExecutionRecord(input: unknown): RecoveryExecutionRecord | null {
  const record = parseJsonObject(input);
  if (!record) return null;
  const version = toOptionalTrimmedString(record.version);
  const sessionId = toOptionalTrimmedString(record.sessionId);
  const userId = toOptionalTrimmedString(record.userId);
  const nearAccountId = toOptionalTrimmedString(record.nearAccountId);
  const chainIdKey = toOptionalTrimmedString(record.chainIdKey)?.toLowerCase() || '';
  const accountAddress = normalizeAccountAddress(record.accountAddress);
  const action = toOptionalTrimmedString(record.action);
  const status = parseRecoveryExecutionStatus(record.status);
  const createdAtMs = positiveSafeInteger(record.createdAtMs);
  const updatedAtMs = positiveSafeInteger(record.updatedAtMs);
  const transactionHash = toOptionalTrimmedString(record.transactionHash);
  const errorCode = toOptionalTrimmedString(record.errorCode);
  const errorMessage = toOptionalTrimmedString(record.errorMessage);
  const metadata = parseRecordMetadata(record.metadata);
  if (
    version !== 'recovery_execution_v1' ||
    !sessionId ||
    !userId ||
    !nearAccountId ||
    !chainIdKey ||
    !accountAddress ||
    !action ||
    !status ||
    !createdAtMs ||
    !updatedAtMs
  ) {
    return null;
  }
  return {
    version: 'recovery_execution_v1',
    sessionId,
    userId,
    nearAccountId,
    chainIdKey,
    accountAddress,
    action,
    status,
    createdAtMs,
    updatedAtMs,
    ...(transactionHash ? { transactionHash } : {}),
    ...(errorCode ? { errorCode } : {}),
    ...(errorMessage ? { errorMessage } : {}),
    ...(metadata ? { metadata } : {}),
  };
}

function recoverySessionWithStatus(input: {
  readonly record: RecoverySessionRecord;
  readonly status: RecoverySessionStatus;
  readonly updatedAtMs: number;
  readonly metadataPatch?: Record<string, unknown>;
}): RecoverySessionRecord {
  const metadata =
    input.metadataPatch
      ? { ...(input.record.metadata || {}), ...input.metadataPatch }
      : input.record.metadata
        ? { ...input.record.metadata }
        : undefined;
  return {
    version: 'recovery_session_v1',
    sessionId: input.record.sessionId,
    userId: input.record.userId,
    nearAccountId: input.record.nearAccountId,
    signerSlot: input.record.signerSlot,
    status: input.status,
    createdAtMs: input.record.createdAtMs,
    updatedAtMs: input.updatedAtMs,
    expiresAtMs: input.record.expiresAtMs,
    newNearPublicKey: input.record.newNearPublicKey,
    newEvmOwnerAddress: input.record.newEvmOwnerAddress,
    recoveryDeadlineEpochSeconds: input.record.recoveryDeadlineEpochSeconds,
    recoveryEmailPayloadHash: input.record.recoveryEmailPayloadHash,
    ...(input.record.verifiedRecoveryPayloadHash
      ? { verifiedRecoveryPayloadHash: input.record.verifiedRecoveryPayloadHash }
      : {}),
    ...(input.record.verifiedRecoveryArtifactHash
      ? { verifiedRecoveryArtifactHash: input.record.verifiedRecoveryArtifactHash }
      : {}),
    ...(input.record.scope ? { scope: input.record.scope } : {}),
    ...(metadata ? { metadata } : {}),
  };
}

function resolveHostedOidcWalletScope(input: unknown): {
  readonly projectId: string;
  readonly envId: string;
} {
  const scope = isRecord(input) ? input : {};
  const orgId = toOptionalTrimmedString(scope.orgId);
  const projectId = toOptionalTrimmedString(scope.projectId);
  const envId = toOptionalTrimmedString(scope.envId);
  if (orgId && projectId && envId) return { projectId, envId };
  throw new Error(
    'runtimePolicyScope.orgId, runtimePolicyScope.projectId, and runtimePolicyScope.envId are required for hosted wallet id derivation',
  );
}

function codedError(code: string, message: string): Error & { code: string } {
  const error = new Error(message) as Error & { code: string };
  error.code = code;
  return error;
}

function appSessionRecord(input: {
  readonly userId: string;
  readonly appSessionVersion: string;
  readonly createdAtMs: number;
  readonly updatedAtMs: number;
}): AppSessionVersionRecord {
  return {
    version: 'app_session_version_v1',
    userId: input.userId,
    appSessionVersion: input.appSessionVersion,
    createdAtMs: input.createdAtMs,
    updatedAtMs: input.updatedAtMs,
  };
}

function parseWebAuthnBinding(row: D1RecordJsonRow): WebAuthnCredentialBindingRecord | null {
  const record = parseJsonObject(row.record_json);
  if (!record) return null;
  const rpId = toOptionalTrimmedString(record.rpId);
  const credentialIdB64u = toOptionalTrimmedString(record.credentialIdB64u);
  const userId = toOptionalTrimmedString(record.userId);
  const signerSlot = positiveInteger(record.signerSlot);
  if (!rpId || !credentialIdB64u || !userId || signerSlot === null) return null;
  return {
    rpId,
    credentialIdB64u,
    userId,
    signerSlot,
    publicKey: toOptionalTrimmedString(record.publicKey),
    createdAtMs: optionalNonNegativeInteger(record.createdAtMs),
    updatedAtMs: optionalNonNegativeInteger(record.updatedAtMs),
  };
}

function parseNearPublicKey(row: D1RecordJsonRow): NearPublicKeyRecord | null {
  const record = parseJsonObject(row.record_json);
  if (!record) return null;
  const publicKey = toOptionalTrimmedString(record.publicKey);
  const kindRaw = toOptionalTrimmedString(record.kind);
  const kind = parseNearPublicKeyKind(kindRaw);
  if (!publicKey || !kind) return null;
  return {
    publicKey,
    kind,
    signerSlot: optionalNonNegativeInteger(record.signerSlot),
    credentialIdB64u: toOptionalTrimmedString(record.credentialIdB64u),
    rpId: toOptionalTrimmedString(record.rpId),
    createdAtMs: optionalNonNegativeInteger(record.createdAtMs),
    updatedAtMs: optionalNonNegativeInteger(record.updatedAtMs),
  };
}

function parseNearPublicKeyKind(
  input: string | undefined,
): NearPublicKeyRecord['kind'] | null {
  switch (input) {
    case 'threshold':
    case 'local':
    case 'backup':
    case 'ephemeral':
      return input;
    default:
      return null;
  }
}

function maskEmail(email: string): string {
  const trimmed = email.trim().toLowerCase();
  const atIndex = trimmed.indexOf('@');
  if (atIndex <= 0 || atIndex === trimmed.length - 1) return 'hidden';
  const local = trimmed.slice(0, atIndex);
  const domain = trimmed.slice(atIndex + 1);
  const localMask =
    local.length <= 2 ? `${local[0] || '*'}*` : `${local[0]}***${local.slice(-1)}`;
  const domainParts = domain.split('.');
  const domainName = domainParts[0] || '';
  const domainMask =
    domainName.length <= 2
      ? `${domainName[0] || '*'}*`
      : `${domainName[0]}***${domainName.slice(-1)}`;
  return `${localMask}@${[domainMask, ...domainParts.slice(1)].join('.')}`;
}

function generateNumericOtp(length: number): string {
  if (typeof crypto === 'undefined' || typeof crypto.getRandomValues !== 'function') {
    throw new Error('crypto.getRandomValues is unavailable in this runtime');
  }
  const bytes = crypto.getRandomValues(new Uint8Array(length));
  let code = '';
  for (const byte of bytes) code += String(byte % 10);
  return code;
}

function clampedEmailOtpUnlockTtlMs(input: unknown): number {
  const value = typeof input === 'number' ? input : Number(input);
  if (!Number.isFinite(value) || value <= 0) return 5 * 60_000;
  return Math.min(Math.max(Math.floor(value), 10_000), 10 * 60_000);
}

function decodeFixedBase64Url(input: string, byteLength: number): Uint8Array | null {
  try {
    const decoded = base64UrlDecode(input);
    return decoded.length === byteLength ? decoded : null;
  } catch {
    return null;
  }
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= (left[index] || 0) ^ (right[index] || 0);
  }
  return difference === 0;
}

function emailOtpRateLimitKeys(input: {
  readonly scope: EmailOtpRateLimitScope;
  readonly action?: string;
  readonly policy: EmailOtpRateLimitPolicy;
  readonly userId?: string;
  readonly walletId?: string;
  readonly providerSubject?: string;
  readonly orgId?: string;
  readonly clientIp?: string;
}): readonly string[] {
  const keySuffix = [
    `scope=${input.scope}`,
    `action=${input.action || 'default'}`,
    `limit=${input.policy.limit}`,
    `windowMs=${input.policy.windowMs}`,
  ].join(':');
  return [
    input.clientIp ? `${keySuffix}:ip:${input.clientIp}` : '',
    input.userId ? `${keySuffix}:user:${input.userId}` : '',
    input.walletId ? `${keySuffix}:wallet:${input.walletId}` : '',
    input.providerSubject ? `${keySuffix}:provider:${input.providerSubject}` : '',
    input.orgId ? `${keySuffix}:org:${input.orgId}` : '',
  ].filter(Boolean);
}

function emailOtpRateLimitExceeded(row: D1EmailOtpRateLimitRow | null): {
  ok: false;
  code: 'rate_limited';
  message: string;
  retryAfterMs?: number;
  resetAtMs?: number;
} {
  const resetAtMs = positiveSafeInteger(row?.reset_at_ms);
  const retryAfterMs = resetAtMs ? Math.max(0, resetAtMs - Date.now()) : undefined;
  return {
    ok: false,
    code: 'rate_limited',
    message: 'Email OTP rate limit exceeded',
    ...(retryAfterMs !== undefined ? { retryAfterMs } : {}),
    ...(resetAtMs ? { resetAtMs } : {}),
  };
}

function emailOtpChallengeInvalidOrExpired(): {
  ok: false;
  code: string;
  message: string;
} {
  return {
    ok: false,
    code: 'challenge_expired_or_invalid',
    message: 'Email OTP challenge expired or invalid',
  };
}

function emailOtpChallengeBindingMismatchCode(input: {
  readonly record: EmailOtpChallengeRecord;
  readonly userId: string;
  readonly walletId: string;
  readonly orgId: string;
  readonly sessionHash: string;
  readonly appSessionVersion: string;
  readonly action: EmailOtpExistingChallengeAction;
  readonly operation: EmailOtpChallengeOperation;
}): string | null {
  if (input.record.otpChannel !== EMAIL_OTP_CHANNEL) return 'challenge_channel_mismatch';
  if (input.record.challengeSubjectId !== input.userId) return 'challenge_subject_mismatch';
  if (input.record.walletId !== input.walletId) return 'challenge_wallet_mismatch';
  if (String(input.record.orgId || '') !== input.orgId) return 'challenge_org_mismatch';
  if (input.record.action !== input.action) return 'challenge_purpose_mismatch';
  if (input.record.operation !== input.operation) return 'challenge_purpose_mismatch';
  if (input.record.sessionHash !== input.sessionHash) return 'challenge_session_mismatch';
  if (input.record.appSessionVersion !== input.appSessionVersion) {
    return 'challenge_session_mismatch';
  }
  return null;
}

function redactEmailOtpRecoveryChallengeEscrow(
  record: EmailOtpRecoveryWrappedEnrollmentEscrowRecord,
): EmailOtpRecoveryChallengeEscrow {
  return {
    version: record.version,
    alg: record.alg,
    secretKind: record.secretKind,
    escrowKind: record.escrowKind,
    walletId: record.walletId,
    userId: record.userId,
    authSubjectId: record.authSubjectId,
    authMethod: record.authMethod,
    enrollmentId: record.enrollmentId,
    enrollmentVersion: record.enrollmentVersion,
    enrollmentSealKeyVersion: record.enrollmentSealKeyVersion,
    signingRootId: record.signingRootId,
    signingRootVersion: record.signingRootVersion,
    nonceB64u: record.nonceB64u,
    wrappedDeviceEnrollmentEscrowB64u: record.wrappedDeviceEnrollmentEscrowB64u,
    aadHashB64u: record.aadHashB64u,
  };
}

function activeEmailOtpRecoveryEscrow(
  record: EmailOtpRecoveryWrappedEnrollmentEscrowRecord,
): record is Extract<
  EmailOtpRecoveryWrappedEnrollmentEscrowRecord,
  { readonly recoveryKeyStatus: 'active' }
> {
  return record.recoveryKeyStatus === 'active';
}

function emailOtpChallengeWithAttemptCount(
  record: EmailOtpChallengeRecord,
  attemptCount: number,
): EmailOtpChallengeRecord {
  return {
    version: 'email_otp_challenge_v1',
    challengeId: record.challengeId,
    challengeSubjectId: record.challengeSubjectId,
    walletId: record.walletId,
    ...(record.orgId ? { orgId: record.orgId } : {}),
    otpChannel: EMAIL_OTP_CHANNEL,
    email: record.email,
    otpCode: record.otpCode,
    sessionHash: record.sessionHash,
    appSessionVersion: record.appSessionVersion,
    action: record.action,
    operation: record.operation,
    createdAtMs: record.createdAtMs,
    expiresAtMs: record.expiresAtMs,
    attemptCount,
    maxAttempts: record.maxAttempts,
  };
}

class CloudflareD1RelayAuthMetadataService {
  private readonly options: NormalizedCloudflareD1RelayAuthServiceOptions;
  private readonly emailOtpMemoryOutbox = new Map<string, EmailOtpOutboxEntry>();
  private googleJwksCache: JsonWebKeyCache | null = null;
  private googleJwksFetchPromise: Promise<JsonWebKeyCache> | null = null;

  constructor(input: CloudflareD1RelayAuthServiceOptions) {
    this.options = normalizeD1RelayAuthOptions(input);
  }

  async listIdentities(input: ListIdentitiesInput): Promise<ListIdentitiesResult> {
    try {
      const userId = toOptionalTrimmedString(input.userId);
      if (!userId) return { ok: false, code: 'invalid_args', message: 'Missing userId' };
      const result = await this.scopePrepare(
        `SELECT subject
           FROM signer_identity_links
          WHERE namespace = ?
            AND org_id = ?
            AND project_id = ?
            AND env_id = ?
            AND user_id = ?
          ORDER BY created_at_ms ASC`,
        [userId],
      ).all<D1IdentityRow>();
      const subjects: string[] = [];
      for (const row of result.results || []) {
        const subject = toOptionalTrimmedString(row.subject);
        if (subject) subjects.push(subject);
      }
      return { ok: true, subjects };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to list identities',
      };
    }
  }

  async linkIdentity(input: LinkIdentityInput): Promise<LinkIdentityResult> {
    try {
      const userId = toOptionalTrimmedString(input.userId);
      const subject = toOptionalTrimmedString(input.subject);
      if (!userId) return { ok: false, code: 'invalid_args', message: 'Missing userId' };
      if (!subject) return { ok: false, code: 'invalid_args', message: 'Missing subject' };

      const now = Date.now();
      const existing = await this.readIdentityLinkBySubject(subject);
      const existingUserId = toOptionalTrimmedString(existing?.user_id);
      const createdAtMs = parseIdentityCreatedAt(existing?.created_at_ms, now);

      if (existingUserId && existingUserId !== userId) {
        return await this.moveIdentityIfAllowed({
          userId,
          subject,
          existingUserId,
          createdAtMs,
          updatedAtMs: now,
          allowMoveIfSoleIdentity: Boolean(input.allowMoveIfSoleIdentity),
        });
      }

      await this.scopePrepare(
        `INSERT INTO signer_identity_links (
          namespace,
          org_id,
          project_id,
          env_id,
          subject,
          user_id,
          record_json,
          created_at_ms,
          updated_at_ms
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (namespace, org_id, project_id, env_id, subject)
        DO UPDATE SET
          user_id = EXCLUDED.user_id,
          record_json = EXCLUDED.record_json,
          updated_at_ms = EXCLUDED.updated_at_ms
        WHERE signer_identity_links.user_id = EXCLUDED.user_id`,
        [
          subject,
          userId,
          JSON.stringify(identitySubjectRecord({ subject, userId, createdAtMs, updatedAtMs: now })),
          createdAtMs,
          now,
        ],
      ).run();

      const finalUserId = await this.readIdentityUserIdBySubject(subject);
      if (finalUserId === userId) return { ok: true };
      if (finalUserId) return identityAlreadyLinked();
      return { ok: false, code: 'internal', message: 'Failed to link identity' };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to link identity',
      };
    }
  }

  async unlinkIdentity(input: UnlinkIdentityInput): Promise<UnlinkIdentityResult> {
    try {
      const userId = toOptionalTrimmedString(input.userId);
      const subject = toOptionalTrimmedString(input.subject);
      if (!userId) return { ok: false, code: 'invalid_args', message: 'Missing userId' };
      if (!subject) return { ok: false, code: 'invalid_args', message: 'Missing subject' };

      const deleted = d1MutationChanges(
        await this.options.database
          .prepare(
            `DELETE FROM signer_identity_links
              WHERE namespace = ?
                AND org_id = ?
                AND project_id = ?
                AND env_id = ?
                AND subject = ?
                AND user_id = ?
                AND (
                  SELECT COUNT(*)
                    FROM signer_identity_links
                   WHERE namespace = ?
                     AND org_id = ?
                     AND project_id = ?
                     AND env_id = ?
                     AND user_id = ?
                ) > 1`,
          )
          .bind(
            ...this.scopeValues([subject, userId]),
            ...this.scopeValues([userId]),
          )
          .run(),
      );
      if (deleted > 0) return { ok: true };

      const existingUserId = await this.readIdentityUserIdBySubject(subject);
      if (existingUserId !== userId) {
        return { ok: false, code: 'not_found', message: 'Subject is not linked to this user' };
      }
      const subjectCount = await this.readIdentitySubjectCountForUserId(userId);
      if (subjectCount <= 1) {
        return {
          ok: false,
          code: 'cannot_unlink_last_identity',
          message: 'Refusing to remove the last remaining identity',
        };
      }
      return { ok: false, code: 'internal', message: 'Failed to unlink identity' };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to unlink identity',
      };
    }
  }

  async resolveOidcWalletId(
    input: ResolveOidcWalletIdInput,
  ): Promise<ResolveOidcWalletIdResult> {
    const providerSubject = toOptionalTrimmedString(input.providerSubject ?? input.sub);
    if (!providerSubject) {
      throw new Error('Cannot resolve OIDC wallet id without provider subject');
    }
    if (providerSubject.startsWith('google:')) {
      const resolution = await this.resolveGoogleEmailOtpSession(input);
      if (resolution.ok) return resolution.walletId;
      throw codedError(resolution.code, resolution.message);
    }

    const linkedWalletId = await this.readIdentityUserIdBySubject(`wallet:${providerSubject}`);
    if (linkedWalletId && isValidAccountId(linkedWalletId)) return linkedWalletId;

    const scope = resolveHostedOidcWalletScope(input.runtimePolicyScope);
    const verifiedEmail = toOptionalTrimmedString(input.email);
    return await deriveHostedNearAccountId({
      accountIdDerivationSecret: requireD1RelayAuthScopeString(
        this.options.accountIdDerivationSecret,
        'ACCOUNT_ID_DERIVATION_SECRET',
      ),
      relayerAccount: requireD1RelayAuthScopeString(this.options.relayerAccount, 'relayerAccount'),
      projectId: scope.projectId,
      envId: scope.envId,
      authProvider: 'oidc',
      providerSubject,
      ...(verifiedEmail ? { verifiedEmail } : {}),
    });
  }

  async consumeGoogleEmailOtpRegistrationAttemptRateLimit(
    input: ConsumeGoogleEmailOtpRegistrationAttemptRateLimitInput,
  ): Promise<ConsumeGoogleEmailOtpRegistrationAttemptRateLimitResult> {
    const accountMode = toOptionalTrimmedString(input.accountMode)?.toLowerCase();
    if (accountMode !== 'register') return { ok: true };
    const providerSubject = parseGoogleProviderSubject(input.providerSubject);
    if (!providerSubject.ok) {
      return {
        ok: false,
        code: 'invalid_body',
        message: providerSubject.error.message,
      };
    }
    const email = parseVerifiedGoogleEmail(input.email);
    if (!email.ok) {
      return {
        ok: false,
        code: 'invalid_body',
        message: email.error.message,
      };
    }
    const orgId = parseOrgId(input.runtimePolicyScope?.orgId);
    if (!orgId.ok) {
      return {
        ok: false,
        code: 'invalid_body',
        message: orgId.error.message,
      };
    }
    const restartOffer = isTrueFlag(input.restartRegistrationOffer);
    return await this.consumeEmailOtpRateLimit({
      scope: 'googleRegistrationAttempt',
      action: restartOffer
        ? 'google_email_otp_registration_offer_restart'
        : 'google_email_otp_registration_create',
      userId: toOptionalTrimmedString(input.appSessionUserId),
      providerSubject: providerSubject.value,
      orgId: orgId.value,
      clientIp: toOptionalTrimmedString(input.clientIp),
    });
  }

  async resolveGoogleEmailOtpSession(
    input: ResolveGoogleEmailOtpSessionInput,
  ): Promise<ResolveGoogleEmailOtpSessionResult> {
    const providerSubject = parseGoogleProviderSubject(input.providerSubject ?? input.sub);
    if (!providerSubject.ok) {
      throw new Error('Cannot resolve Google Email OTP session without Google provider subject');
    }
    const accountMode = toOptionalTrimmedString(input.accountMode)?.toLowerCase();
    if (accountMode !== 'register' && accountMode !== 'login') {
      throw new Error('Google Email OTP accountMode must be register or login');
    }
    const email = toOptionalTrimmedString(input.email)?.toLowerCase() || '';
    const runtimePolicyScope = requireRuntimePolicyScope(input.runtimePolicyScope);
    const appSessionVersion = toOptionalTrimmedString(input.appSessionVersion);
    if (accountMode === 'register' && !appSessionVersion) {
      throw new Error('Google Email OTP registration requires appSessionVersion');
    }
    const restartRegistrationOffer = isTrueFlag(input.restartRegistrationOffer);
    const walletSubject = `wallet:${providerSubject.value}`;
    const linkedWalletId = await this.readIdentityUserIdBySubject(walletSubject);
    const linkedIsUsableRelayerWallet = Boolean(
      linkedWalletId && isValidAccountId(linkedWalletId) && this.isRelayerSubaccount(linkedWalletId),
    );
    const linkedIsHostedHmacReadableWallet = Boolean(
      linkedWalletId && this.isHostedHmacReadableRelayerSubaccount(linkedWalletId),
    );

    if (accountMode === 'login') {
      return await this.resolveGoogleEmailOtpLoginSession({
        providerSubject: providerSubject.value,
        email,
        orgId: runtimePolicyScope.orgId,
        walletSubject,
        linkedWalletId,
        linkedIsUsableRelayerWallet,
        linkedIsHostedHmacReadableWallet,
      });
    }

    if (!email) {
      throw new Error('Email is required to register a Google Email OTP wallet id');
    }
    return await this.resolveGoogleEmailOtpRegistrationSession({
      providerSubject: providerSubject.value,
      email,
      orgId: runtimePolicyScope.orgId,
      appSessionVersion: appSessionVersion || '',
      runtimePolicyScope,
      restartRegistrationOffer,
      walletSubject,
      linkedWalletId,
    });
  }

  async readEmailOtpEnrollment(
    input: ReadEmailOtpEnrollmentInput,
  ): Promise<ReadEmailOtpEnrollmentResult> {
    const walletId = toOptionalTrimmedString(input.walletId);
    const orgId = toOptionalTrimmedString(input.orgId);
    if (!walletId) return { ok: false, code: 'invalid_body', message: 'Missing walletId' };
    if (!orgId) return { ok: false, code: 'invalid_body', message: 'Missing orgId' };
    const enrollment = await this.readEmailOtpWalletEnrollment(walletId);
    if (!enrollment) {
      return { ok: false, code: 'not_found', message: 'Email OTP enrollment not found' };
    }
    if (enrollment.orgId !== orgId) return emailOtpEnrollmentTenantMismatch();
    return { ok: true, enrollment };
  }

  async readActiveEmailOtpEnrollment(
    input: ReadActiveEmailOtpEnrollmentInput,
  ): Promise<ReadActiveEmailOtpEnrollmentResult> {
    const walletId = toOptionalTrimmedString(input.walletId);
    const orgId = toOptionalTrimmedString(input.orgId);
    const providerUserId = toOptionalTrimmedString(input.providerUserId);
    if (!walletId) return { ok: false, code: 'invalid_body', message: 'Missing walletId' };
    if (!orgId) return { ok: false, code: 'invalid_body', message: 'Missing orgId' };
    const enrollment = await this.readEmailOtpWalletEnrollment(walletId);
    if (!enrollment) {
      return { ok: false, code: 'not_found', message: 'Email OTP enrollment not found' };
    }
    if (enrollment.orgId !== orgId) return emailOtpEnrollmentTenantMismatch();
    if (providerUserId && enrollment.providerUserId !== providerUserId) {
      return {
        ok: false,
        code: 'provider_identity_mismatch',
        message: 'Email OTP enrollment does not match the requested provider user',
      };
    }
    return { ok: true, enrollment };
  }

  async isEmailOtpStrongAuthRequired(
    input: IsEmailOtpStrongAuthRequiredInput,
  ): Promise<IsEmailOtpStrongAuthRequiredResult> {
    const walletId = toOptionalTrimmedString(input.walletId);
    if (!walletId) return { ok: false, code: 'invalid_body', message: 'Missing walletId' };
    const enrollment = await this.readEmailOtpWalletEnrollment(walletId);
    if (!enrollment) return { ok: true, required: false, walletId };
    const authState = await this.readEmailOtpAuthStateForEnrollment(enrollment);
    if (!authState.ok) return authState;
    const state = authState.state;
    if (!state) return { ok: true, required: false, walletId };
    const lastEmailOtpLoginAtMs =
      typeof state.lastEmailOtpLoginAtMs === 'number' ? state.lastEmailOtpLoginAtMs : undefined;
    const lastStrongAuthAtMs =
      typeof state.lastStrongAuthAtMs === 'number' ? state.lastStrongAuthAtMs : undefined;
    return {
      ok: true,
      required: Boolean(
        lastEmailOtpLoginAtMs &&
          (!lastStrongAuthAtMs || lastEmailOtpLoginAtMs > lastStrongAuthAtMs),
      ),
      walletId,
      ...(lastEmailOtpLoginAtMs ? { lastEmailOtpLoginAtMs } : {}),
      ...(lastStrongAuthAtMs ? { lastStrongAuthAtMs } : {}),
    };
  }

  async markEmailOtpStrongAuthSatisfied(
    input: MarkEmailOtpStrongAuthSatisfiedInput,
  ): Promise<MarkEmailOtpStrongAuthSatisfiedResult> {
    const walletId = toOptionalTrimmedString(input.walletId);
    if (!walletId) return { ok: false, code: 'invalid_body', message: 'Missing walletId' };
    const enrollment = await this.readEmailOtpWalletEnrollment(walletId);
    if (!enrollment) return { ok: true, walletId };
    const nowMs = Date.now();
    await this.putEmailOtpAuthStateForEnrollment(enrollment, { lastStrongAuthAtMs: nowMs });
    return { ok: true, walletId, lastStrongAuthAtMs: nowMs };
  }

  async getEmailOtpRecoveryCodeStatus(
    input: GetEmailOtpRecoveryCodeStatusInput,
  ): Promise<GetEmailOtpRecoveryCodeStatusResult> {
    try {
      const userId = toOptionalTrimmedString(input.userId);
      const walletId = toOptionalTrimmedString(input.walletId);
      const orgId = toOptionalTrimmedString(input.orgId);
      if (!userId) return { ok: false, code: 'invalid_body', message: 'Missing userId' };
      if (!walletId) return { ok: false, code: 'invalid_body', message: 'Missing walletId' };
      if (!orgId) return { ok: false, code: 'invalid_body', message: 'Missing orgId' };

      const enrollment = await this.readActiveEmailOtpEnrollment({
        walletId,
        orgId,
        providerUserId: userId,
      });
      if (!enrollment.ok) {
        if (enrollment.code === 'not_found') return emailOtpRecoveryNotEnrolledStatus(walletId);
        return enrollment;
      }

      const records = await this.listEmailOtpRecoveryEscrowsForEnrollment(enrollment.enrollment);
      let activeRecoveryCodeCount = 0;
      let consumedRecoveryCodeCount = 0;
      let revokedRecoveryCodeCount = 0;
      let issuedAtMs: number | null = null;
      for (const record of records) {
        switch (record.recoveryKeyStatus) {
          case 'active':
            activeRecoveryCodeCount += 1;
            break;
          case 'consumed':
            consumedRecoveryCodeCount += 1;
            break;
          case 'revoked':
            revokedRecoveryCodeCount += 1;
            break;
        }
        issuedAtMs =
          issuedAtMs === null ? record.issuedAtMs : Math.min(issuedAtMs, record.issuedAtMs);
      }
      return {
        ok: true,
        status:
          activeRecoveryCodeCount === EMAIL_OTP_RECOVERY_KEY_COUNT ? 'ready' : 'incomplete',
        walletId,
        enrollmentId: enrollment.enrollment.enrollmentId,
        enrollmentSealKeyVersion: enrollment.enrollment.enrollmentSealKeyVersion,
        expectedRecoveryCodeCount: EMAIL_OTP_RECOVERY_KEY_COUNT,
        activeRecoveryCodeCount,
        consumedRecoveryCodeCount,
        revokedRecoveryCodeCount,
        totalRecoveryCodeCount: records.length,
        issuedAtMs,
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to read Email OTP recovery-code status',
      };
    }
  }

  private async createEmailOtpExistingEnrollmentChallenge(
    input: EmailOtpExistingChallengeIssueInput,
  ): Promise<EmailOtpExistingChallengeIssueResult> {
    try {
      const userId = toOptionalTrimmedString(input.userId);
      const walletId = toOptionalTrimmedString(input.walletId);
      const orgId = toOptionalTrimmedString(input.orgId);
      const otpChannel = toOptionalTrimmedString(input.otpChannel);
      const sessionHash = toOptionalTrimmedString(input.sessionHash);
      const appSessionVersion = toOptionalTrimmedString(input.appSessionVersion);
      const clientIp = toOptionalTrimmedString(input.clientIp);
      const action = input.action;
      const operation = input.operation;
      if (!userId) return { ok: false, code: 'invalid_body', message: 'Missing userId' };
      if (!walletId) return { ok: false, code: 'invalid_body', message: 'Missing walletId' };
      if (!orgId) return { ok: false, code: 'invalid_body', message: 'Missing orgId' };
      if (otpChannel !== EMAIL_OTP_CHANNEL) {
        return { ok: false, code: 'invalid_body', message: 'otpChannel must be email_otp' };
      }
      if (!sessionHash) return { ok: false, code: 'invalid_body', message: 'Missing sessionHash' };
      if (!appSessionVersion) {
        return { ok: false, code: 'invalid_body', message: 'Missing appSessionVersion' };
      }

      const enrollment = await this.readActiveEmailOtpEnrollment({
        walletId,
        orgId,
        providerUserId: userId,
      });
      if (!enrollment.ok) return enrollment;
      const authState = await this.readEmailOtpAuthStateForEnrollment(enrollment.enrollment);
      if (!authState.ok) return authState;
      if (authState.state?.otpLockedUntilMs && authState.state.otpLockedUntilMs > Date.now()) {
        return {
          ok: false,
          code: 'otp_locked_out',
          message: 'Email OTP is temporarily locked for this wallet',
        };
      }

      const nowMs = Date.now();
      await this.pruneExpiredEmailOtpChallenges(nowMs);
      if (input.reuseActiveChallenge === true) {
        const existing = await this.findLatestActiveEmailOtpChallenge({
          challengeSubjectId: userId,
          walletId,
          orgId,
          action,
          sessionHash,
          appSessionVersion,
          operation,
          nowMs,
        });
        if (existing) {
          return {
            ok: true,
            challenge: {
              challengeId: existing.challengeId,
              issuedAtMs: existing.createdAtMs,
              expiresAtMs: existing.expiresAtMs,
              challengeSubjectId: userId,
              walletId,
              orgId,
              otpChannel: EMAIL_OTP_CHANNEL,
              sessionHash,
              appSessionVersion,
              action,
              operation,
            },
            delivery: {
              status: 'reused',
              mode: this.options.emailOtp.deliveryMode,
              emailHint: maskEmail(existing.email),
            },
          };
        }
      }

      const rateLimit = await this.consumeEmailOtpRateLimit({
        scope: 'challenge',
        action,
        userId,
        walletId,
        orgId,
        clientIp,
      });
      if (!rateLimit.ok) return rateLimit;

      await this.enforceEmailOtpActiveChallengeLimit({
        challengeSubjectId: userId,
        walletId,
        orgId,
        action,
        sessionHash,
        appSessionVersion,
        operation,
        nowMs,
      });

      const challengeId = secureRandomBase64Url(16, 'email otp challenge ids');
      const otpCode = generateNumericOtp(this.options.emailOtp.codeLength);
      const expiresAtMs = nowMs + this.options.emailOtp.challengeTtlMs;
      const record = emailOtpChallengeRecord({
        challengeId,
        challengeSubjectId: userId,
        walletId,
        orgId,
        email: enrollment.enrollment.verifiedEmail,
        otpCode,
        sessionHash,
        appSessionVersion,
        action,
        operation,
        createdAtMs: nowMs,
        expiresAtMs,
        maxAttempts: this.options.emailOtp.maxAttempts,
      });
      await this.putEmailOtpChallenge(record);
      const delivery = await this.deliverEmailOtpCode(record);
      if (!delivery.ok) {
        await this.deleteEmailOtpChallenge(challengeId);
        return delivery;
      }

      return {
        ok: true,
        challenge: {
          challengeId,
          issuedAtMs: nowMs,
          expiresAtMs,
          challengeSubjectId: userId,
          walletId,
          orgId,
          otpChannel: EMAIL_OTP_CHANNEL,
          sessionHash,
          appSessionVersion,
          action,
          operation,
        },
        delivery: {
          status: 'sent',
          mode: delivery.deliveryMode,
          emailHint: delivery.emailHint,
        },
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to create Email OTP challenge',
      };
    }
  }

  async createEmailOtpChallenge(
    input: CreateEmailOtpChallengeInput,
  ): Promise<CreateEmailOtpChallengeResult> {
    const operation = parseEmailOtpLoginOperation(input.operation);
    const result = await this.createEmailOtpExistingEnrollmentChallenge({
      ...input,
      action: WALLET_EMAIL_OTP_ACTIONS.login,
      operation,
    });
    if (!result.ok) return result;
    return {
      ok: true,
      challenge: {
        challengeId: result.challenge.challengeId,
        issuedAtMs: result.challenge.issuedAtMs,
        expiresAtMs: result.challenge.expiresAtMs,
        userId: result.challenge.challengeSubjectId,
        walletId: result.challenge.walletId,
        orgId: result.challenge.orgId,
        otpChannel: result.challenge.otpChannel,
        sessionHash: result.challenge.sessionHash,
        appSessionVersion: result.challenge.appSessionVersion,
        action: WALLET_EMAIL_OTP_ACTIONS.login,
        operation,
      },
      delivery: result.delivery,
    };
  }

  async createEmailOtpDeviceRecoveryChallenge(
    input: CreateEmailOtpDeviceRecoveryChallengeInput,
  ): Promise<CreateEmailOtpDeviceRecoveryChallengeResult> {
    const result = await this.createEmailOtpExistingEnrollmentChallenge({
      ...input,
      action: WALLET_EMAIL_OTP_ACTIONS.deviceRecovery,
      operation: WALLET_EMAIL_OTP_UNLOCK_OPERATION,
    });
    if (!result.ok) return result;
    return {
      ok: true,
      challenge: {
        challengeId: result.challenge.challengeId,
        issuedAtMs: result.challenge.issuedAtMs,
        expiresAtMs: result.challenge.expiresAtMs,
        userId: result.challenge.challengeSubjectId,
        walletId: result.challenge.walletId,
        orgId: result.challenge.orgId,
        otpChannel: result.challenge.otpChannel,
        sessionHash: result.challenge.sessionHash,
        appSessionVersion: result.challenge.appSessionVersion,
        action: WALLET_EMAIL_OTP_ACTIONS.deviceRecovery,
        operation: WALLET_EMAIL_OTP_UNLOCK_OPERATION,
      },
      delivery: result.delivery,
    };
  }

  private async verifyEmailOtpExistingChallengeCode(
    input: EmailOtpExistingChallengeVerifyInput,
  ): Promise<EmailOtpExistingChallengeVerifyResult> {
    try {
      const userId = toOptionalTrimmedString(input.userId);
      const walletId = toOptionalTrimmedString(input.walletId);
      const orgId = toOptionalTrimmedString(input.orgId);
      const challengeId = toOptionalTrimmedString(input.challengeId);
      const otpCode = toOptionalTrimmedString(input.otpCode);
      const otpChannel = toOptionalTrimmedString(input.otpChannel);
      const sessionHash = toOptionalTrimmedString(input.sessionHash);
      const appSessionVersion = toOptionalTrimmedString(input.appSessionVersion);
      const clientIp = toOptionalTrimmedString(input.clientIp);
      const action = input.action;
      const operation = input.operation;
      if (!userId) return { ok: false, code: 'invalid_body', message: 'Missing userId' };
      if (!walletId) return { ok: false, code: 'invalid_body', message: 'Missing walletId' };
      if (!orgId) return { ok: false, code: 'invalid_body', message: 'Missing orgId' };
      if (!challengeId) {
        return { ok: false, code: 'invalid_body', message: 'Missing challengeId' };
      }
      if (!otpCode) return { ok: false, code: 'invalid_body', message: 'Missing otpCode' };
      if (otpChannel !== EMAIL_OTP_CHANNEL) {
        return { ok: false, code: 'invalid_body', message: 'otpChannel must be email_otp' };
      }
      if (!sessionHash) return { ok: false, code: 'invalid_body', message: 'Missing sessionHash' };
      if (!appSessionVersion) {
        return { ok: false, code: 'invalid_body', message: 'Missing appSessionVersion' };
      }

      const rateLimit = await this.consumeEmailOtpRateLimit({
        scope: 'verify',
        action,
        userId,
        walletId,
        orgId,
        clientIp,
      });
      if (!rateLimit.ok) return rateLimit;

      const enrollment = await this.readActiveEmailOtpEnrollment({
        walletId,
        orgId,
        providerUserId: userId,
      });
      if (!enrollment.ok) return enrollment;
      const authState = await this.readEmailOtpAuthStateForEnrollment(enrollment.enrollment);
      if (!authState.ok) return authState;
      if (authState.state?.otpLockedUntilMs && authState.state.otpLockedUntilMs > Date.now()) {
        return {
          ok: false,
          code: 'otp_locked_out',
          message: 'Email OTP is temporarily locked for this wallet',
          lockedUntilMs: authState.state.otpLockedUntilMs,
        };
      }

      const nowMs = Date.now();
      await this.pruneExpiredEmailOtpChallenges(nowMs);
      const record = await this.readEmailOtpChallenge(challengeId);
      if (!record) return emailOtpChallengeInvalidOrExpired();
      if (nowMs > record.expiresAtMs) {
        await this.deleteEmailOtpChallenge(record.challengeId);
        return emailOtpChallengeInvalidOrExpired();
      }

      const bindingMismatch = emailOtpChallengeBindingMismatchCode({
        record,
        userId,
        walletId,
        orgId,
        sessionHash,
        appSessionVersion,
        action,
        operation,
      });
      if (bindingMismatch) {
        return {
          ok: false,
          code: bindingMismatch,
          message: 'Email OTP challenge is not valid for the current app session',
        };
      }

      if (record.otpCode !== otpCode) {
        return await this.recordEmailOtpInvalidAttempt({
          enrollment: enrollment.enrollment,
          authState: authState.state,
          record,
        });
      }

      const consumed = await this.consumeEmailOtpChallenge(record.challengeId);
      if (!consumed) return emailOtpChallengeInvalidOrExpired();
      await this.resetEmailOtpFailureState({
        enrollment: enrollment.enrollment,
        authState: authState.state,
      });

      return {
        ok: true,
        challengeId: consumed.challengeId,
        userId,
        walletId,
        orgId,
        otpChannel: EMAIL_OTP_CHANNEL,
        sessionHash,
        appSessionVersion,
        enrollment: enrollment.enrollment,
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to verify Email OTP challenge',
      };
    }
  }

  async verifyEmailOtpChallenge(
    input: VerifyEmailOtpChallengeInput,
  ): Promise<VerifyEmailOtpChallengeResult> {
    const operation = parseEmailOtpLoginOperation(input.operation);
    const verified = await this.verifyEmailOtpExistingChallengeCode({
      ...input,
      action: WALLET_EMAIL_OTP_ACTIONS.login,
      operation,
    });
    if (!verified.ok) return verified;

    const issuedAtMs = Date.now();
    const grantExpiresAtMs = issuedAtMs + this.options.emailOtp.grantTtlMs;
    const loginGrant = secureRandomBase64Url(24, 'email otp login grants');
    await this.putEmailOtpGrant(
      emailOtpGrantRecord({
        grantToken: loginGrant,
        userId: verified.userId,
        walletId: verified.walletId,
        orgId: verified.orgId,
        challengeId: verified.challengeId,
        sessionHash: verified.sessionHash,
        appSessionVersion: verified.appSessionVersion,
        action: WALLET_EMAIL_OTP_ACTIONS.unseal,
        issuedAtMs,
        expiresAtMs: grantExpiresAtMs,
      }),
    );

    return {
      ok: true,
      challengeId: verified.challengeId,
      loginGrant,
      grantExpiresAtMs,
      otpChannel: EMAIL_OTP_CHANNEL,
    };
  }

  async verifyEmailOtpDeviceRecoveryChallenge(
    input: VerifyEmailOtpDeviceRecoveryChallengeInput,
  ): Promise<VerifyEmailOtpDeviceRecoveryChallengeResult> {
    const verified = await this.verifyEmailOtpExistingChallengeCode({
      ...input,
      action: WALLET_EMAIL_OTP_ACTIONS.deviceRecovery,
      operation: WALLET_EMAIL_OTP_UNLOCK_OPERATION,
    });
    if (!verified.ok) return verified;

    const activeRecoveryWrappedEnrollmentEscrows = (
      await this.listEmailOtpRecoveryEscrowsForEnrollment(verified.enrollment)
    ).filter(activeEmailOtpRecoveryEscrow);
    if (activeRecoveryWrappedEnrollmentEscrows.length <= 0) {
      return {
        ok: false,
        code: 'recovery_wrapped_escrows_missing',
        message: 'No active Email OTP recovery-wrapped enrollment escrows are available',
      };
    }

    const issuedAtMs = Date.now();
    const recoveryConsumeGrantExpiresAtMs = issuedAtMs + this.options.emailOtp.grantTtlMs;
    const recoveryConsumeGrant = secureRandomBase64Url(
      24,
      'email otp device recovery grants',
    );
    await this.putEmailOtpGrant(
      emailOtpGrantRecord({
        grantToken: recoveryConsumeGrant,
        userId: verified.userId,
        walletId: verified.walletId,
        orgId: verified.orgId,
        challengeId: verified.challengeId,
        sessionHash: verified.sessionHash,
        appSessionVersion: verified.appSessionVersion,
        action: WALLET_EMAIL_OTP_ACTIONS.deviceRecovery,
        issuedAtMs,
        expiresAtMs: recoveryConsumeGrantExpiresAtMs,
      }),
    );

    return {
      ok: true,
      challengeId: verified.challengeId,
      otpChannel: verified.otpChannel,
      recoveryConsumeGrant,
      recoveryConsumeGrantExpiresAtMs,
      recoveryWrappedEnrollmentEscrows: activeRecoveryWrappedEnrollmentEscrows.map(
        redactEmailOtpRecoveryChallengeEscrow,
      ),
      enrollment: {
        walletId: verified.enrollment.walletId,
        providerUserId: verified.enrollment.providerUserId,
        orgId: verified.enrollment.orgId,
        enrollmentId: verified.enrollment.enrollmentId,
        enrollmentVersion: verified.enrollment.enrollmentVersion,
        enrollmentSealKeyVersion: verified.enrollment.enrollmentSealKeyVersion,
        signingRootId: verified.enrollment.signingRootId,
        signingRootVersion: verified.enrollment.signingRootVersion,
        recoveryWrappedEnrollmentEscrowCount:
          verified.enrollment.recoveryWrappedEnrollmentEscrowCount,
      },
    };
  }

  async readEmailOtpOutboxEntry(
    input: ReadEmailOtpOutboxEntryInput,
  ): Promise<ReadEmailOtpOutboxEntryResult> {
    if (!this.options.emailOtp.devOutboxEnabled) {
      return { ok: false, code: 'not_found', message: 'Email OTP dev outbox is not enabled' };
    }
    const challengeId = toOptionalTrimmedString(input.challengeId);
    const userId = toOptionalTrimmedString(input.userId);
    const walletId = toOptionalTrimmedString(input.walletId);
    if (!challengeId) return { ok: false, code: 'invalid_body', message: 'Missing challengeId' };
    if (!userId) return { ok: false, code: 'invalid_body', message: 'Missing userId' };
    if (!walletId) return { ok: false, code: 'invalid_body', message: 'Missing walletId' };
    const entry = this.emailOtpMemoryOutbox.get(challengeId);
    if (!entry || entry.userId !== userId || entry.walletId !== walletId) {
      return { ok: false, code: 'not_found', message: 'Email OTP outbox entry was not found' };
    }
    if (Date.now() > entry.expiresAtMs) {
      this.emailOtpMemoryOutbox.delete(challengeId);
      return { ok: false, code: 'not_found', message: 'Email OTP outbox entry expired' };
    }
    return {
      ok: true,
      challengeId,
      walletId,
      userId,
      otpChannel: entry.otpChannel,
      emailHint: entry.emailHint,
      otpCode: entry.otpCode,
      expiresAtMs: entry.expiresAtMs,
    };
  }

  async createEmailOtpUnlockChallenge(
    input: CreateEmailOtpUnlockChallengeInput,
  ): Promise<CreateEmailOtpUnlockChallengeResult> {
    try {
      const walletId = toOptionalTrimmedString(input.walletId);
      const orgId = toOptionalTrimmedString(input.orgId);
      if (!walletId) return { ok: false, code: 'invalid_body', message: 'Missing walletId' };
      if (!isValidAccountId(walletId)) {
        return { ok: false, code: 'invalid_body', message: 'Invalid walletId' };
      }
      if (!orgId) return { ok: false, code: 'invalid_body', message: 'Missing orgId' };
      const enrollment = await this.readActiveEmailOtpEnrollment({ walletId, orgId });
      if (!enrollment.ok) return enrollment;
      const nowMs = Date.now();
      const ttlMs = clampedEmailOtpUnlockTtlMs(input.ttlMs ?? input.ttl_ms);
      const challengeId = secureRandomBase64Url(16, 'email otp unlock challenge ids');
      const challengeB64u = secureRandomBase64Url(32, 'email otp unlock challenges');
      const expiresAtMs = nowMs + ttlMs;
      await this.putEmailOtpUnlockChallenge(
        emailOtpUnlockChallengeRecord({
          challengeId,
          walletId: enrollment.enrollment.walletId,
          userId: enrollment.enrollment.providerUserId,
          orgId: enrollment.enrollment.orgId,
          challengeB64u,
          createdAtMs: nowMs,
          expiresAtMs,
        }),
      );
      return {
        ok: true,
        walletId: enrollment.enrollment.walletId,
        challengeId,
        challengeB64u,
        expiresAtMs,
        unlockKeyVersion: enrollment.enrollment.unlockKeyVersion,
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to create Email OTP unlock challenge',
      };
    }
  }

  async verifyEmailOtpUnlockProof(
    input: VerifyEmailOtpUnlockProofInput,
  ): Promise<VerifyEmailOtpUnlockProofResult> {
    try {
      const walletId = toOptionalTrimmedString(input.walletId);
      const orgId = toOptionalTrimmedString(input.orgId);
      const challengeId = toOptionalTrimmedString(input.challengeId);
      const unlockProof = isRecord(input.unlockProof) ? input.unlockProof : null;
      if (!walletId) {
        return { ok: false, verified: false, code: 'invalid_body', message: 'Missing walletId' };
      }
      if (!isValidAccountId(walletId)) {
        return { ok: false, verified: false, code: 'invalid_body', message: 'Invalid walletId' };
      }
      if (!orgId) {
        return { ok: false, verified: false, code: 'invalid_body', message: 'Missing orgId' };
      }
      if (!challengeId) {
        return { ok: false, verified: false, code: 'invalid_body', message: 'Missing challengeId' };
      }
      if (!unlockProof) {
        return {
          ok: false,
          verified: false,
          code: 'invalid_body',
          message: 'unlockProof is required',
        };
      }

      const publicKeyB64u = toOptionalTrimmedString(unlockProof.publicKey);
      const signatureB64u = toOptionalTrimmedString(unlockProof.signature);
      if (!publicKeyB64u) {
        return {
          ok: false,
          verified: false,
          code: 'invalid_body',
          message: 'unlockProof.publicKey is required',
        };
      }
      if (!signatureB64u) {
        return {
          ok: false,
          verified: false,
          code: 'invalid_body',
          message: 'unlockProof.signature is required',
        };
      }

      const challenge = await this.consumeEmailOtpUnlockChallenge(challengeId);
      if (!challenge || Date.now() > challenge.expiresAtMs) {
        return {
          ok: false,
          verified: false,
          code: 'challenge_expired_or_invalid',
          message: 'Email OTP unlock challenge expired or invalid',
        };
      }
      if (challenge.walletId !== walletId) {
        return {
          ok: false,
          verified: false,
          code: 'challenge_binding_mismatch',
          message: 'Email OTP unlock challenge is not valid for this walletId',
        };
      }

      const enrollment = await this.readActiveEmailOtpEnrollment({ walletId, orgId });
      if (!enrollment.ok) {
        return {
          ok: false,
          verified: false,
          code: enrollment.code,
          message: enrollment.message,
        };
      }
      if (
        challenge.userId !== enrollment.enrollment.providerUserId ||
        challenge.orgId !== enrollment.enrollment.orgId
      ) {
        return {
          ok: false,
          verified: false,
          code: 'challenge_binding_mismatch',
          message: 'Email OTP unlock challenge is not valid for this enrollment',
        };
      }

      const providedPublicKey = decodeFixedBase64Url(publicKeyB64u, 33);
      if (!providedPublicKey) {
        return {
          ok: false,
          verified: false,
          code: 'invalid_body',
          message: 'unlockProof.publicKey must decode to 33 bytes',
        };
      }
      try {
        await validateSecp256k1PublicKey33(providedPublicKey);
      } catch {
        return {
          ok: false,
          verified: false,
          code: 'invalid_body',
          message: 'unlockProof.publicKey is not a valid secp256k1 public key',
        };
      }

      const signature = decodeFixedBase64Url(signatureB64u, 65);
      if (!signature) {
        return {
          ok: false,
          verified: false,
          code: 'invalid_body',
          message: 'unlockProof.signature must decode to 65 bytes',
        };
      }
      const enrolledPublicKey = decodeFixedBase64Url(
        enrollment.enrollment.clientUnlockPublicKeyB64u,
        33,
      );
      if (!enrolledPublicKey || !bytesEqual(enrolledPublicKey, providedPublicKey)) {
        return {
          ok: false,
          verified: false,
          code: 'invalid_unlock_proof',
          message: 'unlockProof.publicKey does not match the enrolled clientUnlockPublicKeyB64u',
        };
      }
      const challengeDigest = decodeFixedBase64Url(challenge.challengeB64u, 32);
      if (!challengeDigest) {
        return {
          ok: false,
          verified: false,
          code: 'internal',
          message: 'Stored unlock challenge digest must decode to 32 bytes',
        };
      }
      try {
        await verifySecp256k1RecoverableSignatureAgainstPublicKey33(
          challengeDigest,
          signature,
          providedPublicKey,
        );
      } catch {
        return {
          ok: false,
          verified: false,
          code: 'invalid_unlock_proof',
          message: 'unlockProof.signature did not verify against unlockProof.publicKey',
        };
      }

      await this.putEmailOtpAuthStateForEnrollment(enrollment.enrollment, {
        lastEmailOtpLoginAtMs: Date.now(),
      });
      return {
        ok: true,
        verified: true,
        userId: enrollment.enrollment.walletId,
        walletId: enrollment.enrollment.walletId,
        unlockKeyVersion: enrollment.enrollment.unlockKeyVersion,
      };
    } catch (error: unknown) {
      return {
        ok: false,
        verified: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to verify Email OTP unlock proof',
      };
    }
  }

  async consumeEmailOtpGrant(input: ConsumeEmailOtpGrantInput): Promise<ConsumeEmailOtpGrantResult> {
    try {
      const loginGrant = toOptionalTrimmedString(input.loginGrant);
      const userId = toOptionalTrimmedString(input.userId);
      const walletId = toOptionalTrimmedString(input.walletId);
      const orgId = toOptionalTrimmedString(input.orgId);
      const otpChannel = toOptionalTrimmedString(input.otpChannel);
      const sessionHash = toOptionalTrimmedString(input.sessionHash);
      const appSessionVersion = toOptionalTrimmedString(input.appSessionVersion);
      const clientIp = toOptionalTrimmedString(input.clientIp);
      if (!loginGrant) return { ok: false, code: 'invalid_body', message: 'Missing loginGrant' };
      if (!userId) return { ok: false, code: 'invalid_body', message: 'Missing userId' };
      if (!walletId) return { ok: false, code: 'invalid_body', message: 'Missing walletId' };
      if (!orgId) return { ok: false, code: 'invalid_body', message: 'Missing orgId' };
      if (otpChannel !== EMAIL_OTP_CHANNEL) {
        return { ok: false, code: 'invalid_body', message: 'otpChannel must be email_otp' };
      }
      if (!sessionHash) return { ok: false, code: 'invalid_body', message: 'Missing sessionHash' };
      if (!appSessionVersion) {
        return { ok: false, code: 'invalid_body', message: 'Missing appSessionVersion' };
      }

      const rateLimit = await this.consumeEmailOtpRateLimit({
        scope: 'grant',
        userId,
        walletId,
        orgId,
        clientIp,
      });
      if (!rateLimit.ok) return rateLimit;

      const record = await this.consumeEmailOtpGrantRecord(loginGrant);
      if (!record || Date.now() > record.expiresAtMs) return emailOtpGrantInvalidOrExpired();
      if (record.action !== WALLET_EMAIL_OTP_ACTIONS.unseal) {
        return emailOtpGrantInvalidOrExpired();
      }
      const bindingMismatch =
        record.userId !== userId ||
        record.walletId !== walletId ||
        record.otpChannel !== EMAIL_OTP_CHANNEL ||
        record.sessionHash !== sessionHash ||
        record.appSessionVersion !== appSessionVersion ||
        record.orgId !== orgId;
      if (bindingMismatch) {
        return {
          ok: false,
          code: 'recovery_grant_binding_mismatch',
          message: 'Recovery grant is not valid for the current app session',
        };
      }

      return {
        ok: true,
        challengeId: record.challengeId,
        otpChannel: EMAIL_OTP_CHANNEL,
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to consume Email OTP grant',
      };
    }
  }

  async consumeEmailOtpRecoveryKey(
    input: ConsumeEmailOtpRecoveryKeyInput,
  ): Promise<ConsumeEmailOtpRecoveryKeyResult> {
    try {
      const recoveryConsumeGrant = toOptionalTrimmedString(input.recoveryConsumeGrant);
      const userId = toOptionalTrimmedString(input.userId);
      const walletId = toOptionalTrimmedString(input.walletId);
      const orgId = toOptionalTrimmedString(input.orgId);
      const recoveryKeyId = toOptionalTrimmedString(input.recoveryKeyId);
      const sessionHash = toOptionalTrimmedString(input.sessionHash);
      const appSessionVersion = toOptionalTrimmedString(input.appSessionVersion);
      const clientIp = toOptionalTrimmedString(input.clientIp);
      if (!recoveryConsumeGrant) {
        return { ok: false, code: 'invalid_body', message: 'Missing recoveryConsumeGrant' };
      }
      if (!userId) return { ok: false, code: 'invalid_body', message: 'Missing userId' };
      if (!walletId) return { ok: false, code: 'invalid_body', message: 'Missing walletId' };
      if (!orgId) return { ok: false, code: 'invalid_body', message: 'Missing orgId' };
      if (!recoveryKeyId) {
        return { ok: false, code: 'invalid_body', message: 'Missing recoveryKeyId' };
      }
      if (!sessionHash) return { ok: false, code: 'invalid_body', message: 'Missing sessionHash' };
      if (!appSessionVersion) {
        return { ok: false, code: 'invalid_body', message: 'Missing appSessionVersion' };
      }

      const rateLimit = await this.consumeEmailOtpRateLimit({
        scope: 'grant',
        userId,
        walletId,
        orgId,
        clientIp,
      });
      if (!rateLimit.ok) return rateLimit;

      const grantRecord = await this.consumeEmailOtpGrantRecord(recoveryConsumeGrant);
      if (!grantRecord || Date.now() > grantRecord.expiresAtMs) {
        return emailOtpRecoveryConsumeGrantInvalidOrExpired();
      }
      if (grantRecord.action !== WALLET_EMAIL_OTP_ACTIONS.deviceRecovery) {
        return emailOtpRecoveryConsumeGrantInvalidOrExpired();
      }
      const bindingMismatch =
        grantRecord.userId !== userId ||
        grantRecord.walletId !== walletId ||
        grantRecord.otpChannel !== EMAIL_OTP_CHANNEL ||
        grantRecord.sessionHash !== sessionHash ||
        grantRecord.appSessionVersion !== appSessionVersion ||
        grantRecord.orgId !== orgId;
      if (bindingMismatch) return emailOtpRecoveryGrantBindingMismatch();

      const enrollment = await this.readActiveEmailOtpEnrollment({
        walletId,
        orgId,
        providerUserId: userId,
      });
      if (!enrollment.ok) return enrollment;

      const recoveryRecord = await this.readEmailOtpRecoveryEscrow({ walletId, recoveryKeyId });
      if (!recoveryRecord || recoveryRecord.recoveryKeyStatus !== 'active') {
        return {
          ok: false,
          code: 'recovery_key_not_active',
          message: 'Recovery key is not active',
        };
      }
      if (
        !emailOtpRecoveryEscrowMatchesEnrollment({
          escrow: recoveryRecord,
          enrollment: enrollment.enrollment,
        })
      ) {
        return {
          ok: false,
          code: 'recovery_key_binding_mismatch',
          message: 'Recovery key is not valid for this Email OTP enrollment',
        };
      }

      const consumedAtMs = Date.now();
      const consumedRecord = await this.consumeEmailOtpRecoveryEscrow({
        record: recoveryRecord,
        consumedAtMs,
      });
      if (!consumedRecord) {
        return {
          ok: false,
          code: 'recovery_key_not_active',
          message: 'Recovery key is not active',
        };
      }
      await this.putEmailOtpAuthStateForEnrollment(enrollment.enrollment, {
        lastStrongAuthAtMs: consumedAtMs,
      });
      const activeRecoveryWrappedEnrollmentEscrowCount = (
        await this.listEmailOtpRecoveryEscrowsForEnrollment(enrollment.enrollment)
      ).filter(activeEmailOtpRecoveryEscrow).length;

      return {
        ok: true,
        walletId,
        recoveryKeyId,
        consumedAtMs,
        activeRecoveryWrappedEnrollmentEscrowCount,
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to consume Email OTP recovery key',
      };
    }
  }

  async rotateEmailOtpRecoveryKeys(
    input: RotateEmailOtpRecoveryKeysInput,
  ): Promise<RotateEmailOtpRecoveryKeysResult> {
    try {
      const userId = toOptionalTrimmedString(input.userId);
      const walletId = toOptionalTrimmedString(input.walletId);
      const orgId = toOptionalTrimmedString(input.orgId);
      const enrollmentId = toOptionalTrimmedString(input.enrollmentId);
      const enrollmentSealKeyVersion = toOptionalTrimmedString(input.enrollmentSealKeyVersion);
      if (!userId) return invalidRecoveryRotationBody('Missing userId');
      if (!walletId) return invalidRecoveryRotationBody('Missing walletId');
      if (!orgId) return invalidRecoveryRotationBody('Missing orgId');
      if (!enrollmentId) return invalidRecoveryRotationBody('Missing enrollmentId');
      if (!enrollmentSealKeyVersion) {
        return invalidRecoveryRotationBody('Missing enrollmentSealKeyVersion');
      }
      const rawEscrows = Array.isArray(input.recoveryWrappedEnrollmentEscrows)
        ? input.recoveryWrappedEnrollmentEscrows
        : [];
      if (rawEscrows.length !== EMAIL_OTP_RECOVERY_KEY_COUNT) {
        return invalidRecoveryRotationBody(
          `Exactly ${EMAIL_OTP_RECOVERY_KEY_COUNT} recovery-wrapped enrollment escrows are required`,
        );
      }

      const enrollment = await this.readActiveEmailOtpEnrollment({
        walletId,
        orgId,
        providerUserId: userId,
      });
      if (!enrollment.ok) return enrollment;
      if (
        enrollment.enrollment.enrollmentId !== enrollmentId ||
        enrollment.enrollment.enrollmentSealKeyVersion !== enrollmentSealKeyVersion
      ) {
        return recoveryRotationBindingMismatch();
      }

      const authState = await this.readEmailOtpAuthStateForEnrollment(enrollment.enrollment);
      if (!authState.ok) return authState;
      const lastStrongAuthAtMs =
        typeof authState.state?.lastStrongAuthAtMs === 'number'
          ? authState.state.lastStrongAuthAtMs
          : 0;
      const issuedAtMs = Date.now();
      const freshAuthExpiresAtMs = lastStrongAuthAtMs + this.options.emailOtp.grantTtlMs;
      if (!lastStrongAuthAtMs || issuedAtMs > freshAuthExpiresAtMs) {
        return {
          ok: false,
          code: 'fresh_auth_required',
          message: 'Fresh account authentication is required to rotate recovery codes',
        };
      }

      const recoveryKeyIds = new Set<string>();
      const nonceB64us = new Set<string>();
      const nextActiveRecords: EmailOtpRecoveryWrappedEnrollmentEscrowRecord[] = [];
      for (const rawEscrow of rawEscrows) {
        const nextRecord = await activeEmailOtpRecoveryRotationEscrowRecord({
          raw: rawEscrow,
          enrollment: enrollment.enrollment,
          issuedAtMs,
          recoveryKeyIds,
          nonceB64us,
        });
        if (!nextRecord.ok) return nextRecord.result;
        nextActiveRecords.push(nextRecord.record);
      }

      const existingRecords = await this.listEmailOtpRecoveryEscrowsForEnrollment(
        enrollment.enrollment,
      );
      const oldActiveRecords: Extract<
        EmailOtpRecoveryWrappedEnrollmentEscrowRecord,
        { readonly recoveryKeyStatus: 'active' }
      >[] = [];
      for (const record of existingRecords) {
        if (activeEmailOtpRecoveryEscrow(record)) oldActiveRecords.push(record);
      }
      const revokedRecords: EmailOtpRecoveryWrappedEnrollmentEscrowRecord[] = [];
      for (const record of oldActiveRecords) {
        revokedRecords.push(
          revokedEmailOtpRecoveryEscrowRecord({ record, revokedAtMs: issuedAtMs }),
        );
      }

      await this.putEmailOtpRecoveryEscrows([...revokedRecords, ...nextActiveRecords]);
      const updatedRecords = await this.listEmailOtpRecoveryEscrowsForEnrollment(
        enrollment.enrollment,
      );
      const activeRecoveryCodeCount = countActiveEmailOtpRecoveryEscrows(updatedRecords);
      if (activeRecoveryCodeCount !== EMAIL_OTP_RECOVERY_KEY_COUNT) {
        return {
          ok: false,
          code: 'internal',
          message: `Email OTP recovery-code rotation left ${activeRecoveryCodeCount} active codes; expected ${EMAIL_OTP_RECOVERY_KEY_COUNT}`,
        };
      }
      return {
        ok: true,
        walletId,
        enrollmentId,
        enrollmentSealKeyVersion,
        activeRecoveryCodeCount,
        revokedRecoveryCodeCount: revokedRecords.length,
        totalRecoveryCodeCount: updatedRecords.length,
        issuedAtMs,
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to rotate Email OTP recovery codes',
      };
    }
  }

  async recordEmailOtpRecoveryKeyAttemptFailure(
    input: RecordEmailOtpRecoveryKeyAttemptFailureInput,
  ): Promise<RecordEmailOtpRecoveryKeyAttemptFailureResult> {
    try {
      const recoveryConsumeGrant = toOptionalTrimmedString(input.recoveryConsumeGrant);
      const userId = toOptionalTrimmedString(input.userId);
      const walletId = toOptionalTrimmedString(input.walletId);
      const orgId = toOptionalTrimmedString(input.orgId);
      const sessionHash = toOptionalTrimmedString(input.sessionHash);
      const appSessionVersion = toOptionalTrimmedString(input.appSessionVersion);
      const clientIp = toOptionalTrimmedString(input.clientIp);
      if (!recoveryConsumeGrant) {
        return { ok: false, code: 'invalid_body', message: 'Missing recoveryConsumeGrant' };
      }
      if (!userId) return { ok: false, code: 'invalid_body', message: 'Missing userId' };
      if (!walletId) return { ok: false, code: 'invalid_body', message: 'Missing walletId' };
      if (!orgId) return { ok: false, code: 'invalid_body', message: 'Missing orgId' };
      if (!sessionHash) return { ok: false, code: 'invalid_body', message: 'Missing sessionHash' };
      if (!appSessionVersion) {
        return { ok: false, code: 'invalid_body', message: 'Missing appSessionVersion' };
      }

      const grantRecord = await this.readEmailOtpGrantRecord(recoveryConsumeGrant);
      if (!grantRecord || Date.now() > grantRecord.expiresAtMs) {
        if (grantRecord) await this.deleteEmailOtpGrantRecord(recoveryConsumeGrant);
        return emailOtpRecoveryConsumeGrantInvalidOrExpired();
      }
      if (grantRecord.action !== WALLET_EMAIL_OTP_ACTIONS.deviceRecovery) {
        return emailOtpRecoveryConsumeGrantInvalidOrExpired();
      }
      const bindingMismatch =
        grantRecord.userId !== userId ||
        grantRecord.walletId !== walletId ||
        grantRecord.otpChannel !== EMAIL_OTP_CHANNEL ||
        grantRecord.sessionHash !== sessionHash ||
        grantRecord.appSessionVersion !== appSessionVersion ||
        grantRecord.orgId !== orgId;
      if (bindingMismatch) return emailOtpRecoveryGrantBindingMismatch();

      const rateLimit = await this.consumeEmailOtpRateLimit({
        scope: 'recoveryKeyAttempt',
        action: WALLET_EMAIL_OTP_ACTIONS.deviceRecovery,
        userId,
        walletId,
        orgId,
        clientIp,
      });
      if (!rateLimit.ok) return rateLimit;

      const enrollment = await this.readActiveEmailOtpEnrollment({
        walletId,
        orgId,
        providerUserId: userId,
      });
      if (!enrollment.ok) return enrollment;

      const activeRecoveryWrappedEnrollmentEscrowCount = (
        await this.listEmailOtpRecoveryEscrowsForEnrollment(enrollment.enrollment)
      ).filter(activeEmailOtpRecoveryEscrow).length;
      if (activeRecoveryWrappedEnrollmentEscrowCount <= 0) {
        return {
          ok: false,
          code: 'recovery_wrapped_escrows_missing',
          message: 'No active Email OTP recovery-wrapped enrollment escrows are available',
        };
      }

      return {
        ok: true,
        walletId,
        recordedAtMs: Date.now(),
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to record Email OTP recovery-key failure',
      };
    }
  }

  async getRecoverySession(input: GetRecoverySessionInput): Promise<GetRecoverySessionResult> {
    try {
      const sessionId = toOptionalTrimmedString(input.sessionId);
      if (!sessionId) return { ok: false, code: 'invalid_args', message: 'Missing sessionId' };
      return { ok: true, record: await this.readRecoverySessionRecord(sessionId) };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to read recovery session',
      };
    }
  }

  async updateRecoverySessionStatus(
    input: UpdateRecoverySessionStatusInput,
  ): Promise<UpdateRecoverySessionStatusResult> {
    try {
      const sessionId = toOptionalTrimmedString(input.sessionId);
      const status = parseRecoverySessionStatus(input.status);
      if (!sessionId || !status) {
        return { ok: false, code: 'invalid_args', message: 'Invalid recovery session update' };
      }
      if (input.metadataPatch != null && !isRecord(input.metadataPatch)) {
        return { ok: false, code: 'invalid_args', message: 'Invalid recovery metadata patch' };
      }

      const existing = await this.readRecoverySessionRecord(sessionId);
      if (!existing) {
        return {
          ok: false,
          code: 'invalid_args',
          message: `Unknown recovery session: ${sessionId}`,
        };
      }
      const record = recoverySessionWithStatus({
        record: existing,
        status,
        updatedAtMs: Date.now(),
        ...(input.metadataPatch ? { metadataPatch: input.metadataPatch } : {}),
      });
      await this.putRecoverySessionRecord(record);
      return { ok: true, record };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to update recovery session',
      };
    }
  }

  async recordRecoveryExecution(
    input: RecordRecoveryExecutionInput,
  ): Promise<RecordRecoveryExecutionResult> {
    try {
      const sessionId = toOptionalTrimmedString(input.sessionId);
      const chainIdKey = toOptionalTrimmedString(input.chainIdKey)?.toLowerCase() || '';
      const accountAddress = normalizeAccountAddress(input.accountAddress);
      const action = toOptionalTrimmedString(input.action);
      if (!sessionId || !chainIdKey || !accountAddress || !action) {
        return { ok: false, code: 'invalid_args', message: 'Missing recovery execution fields' };
      }

      const recoverySession = await this.readRecoverySessionRecord(sessionId);
      if (!recoverySession) {
        return {
          ok: false,
          code: 'invalid_args',
          message: `Unknown recovery session: ${sessionId}`,
        };
      }

      const existing = await this.readRecoveryExecutionRecord({
        sessionId,
        chainIdKey,
        accountAddress,
        action,
      });
      const nowMs = Date.now();
      const record = buildRecoveryExecutionRecord({
        sessionId,
        userId: recoverySession.userId,
        nearAccountId: recoverySession.nearAccountId,
        chainIdKey,
        accountAddress,
        action,
        status: input.status,
        createdAtMs: existing?.createdAtMs ?? nowMs,
        nowMs,
        transactionHash: input.transactionHash,
        errorCode: input.errorCode,
        errorMessage: input.errorMessage,
        metadata: input.metadata,
      });
      if (!record) {
        return {
          ok: false,
          code: 'invalid_args',
          message: 'Invalid recovery execution payload',
        };
      }

      await this.putRecoveryExecutionRecord(record);
      return { ok: true, record };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to persist recovery execution',
      };
    }
  }

  async getOrCreateAppSessionVersion(
    input: GetOrCreateAppSessionVersionInput,
  ): Promise<GetOrCreateAppSessionVersionResult> {
    try {
      const userId = toOptionalTrimmedString(input.userId);
      if (!userId) return { ok: false, code: 'invalid_args', message: 'Missing userId' };
      const existing = await this.readAppSessionVersion(userId);
      if (existing) return { ok: true, appSessionVersion: existing };
      const now = Date.now();
      const next = appSessionVersion();
      await this.scopePrepare(
        `INSERT INTO signer_app_session_versions (
          namespace,
          org_id,
          project_id,
          env_id,
          user_id,
          session_version,
          record_json,
          created_at_ms,
          updated_at_ms
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (namespace, org_id, project_id, env_id, user_id) DO NOTHING`,
        [
          userId,
          next,
          JSON.stringify(
            appSessionRecord({
              userId,
              appSessionVersion: next,
              createdAtMs: now,
              updatedAtMs: now,
            }),
          ),
          now,
          now,
        ],
      ).run();
      return { ok: true, appSessionVersion: (await this.readAppSessionVersion(userId)) || next };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to ensure app session version',
      };
    }
  }

  async rotateAppSessionVersion(
    input: RotateAppSessionVersionInput,
  ): Promise<RotateAppSessionVersionResult> {
    try {
      const userId = toOptionalTrimmedString(input.userId);
      if (!userId) return { ok: false, code: 'invalid_args', message: 'Missing userId' };
      const existing = await this.scopePrepare(
        `SELECT record_json
           FROM signer_app_session_versions
          WHERE namespace = ?
            AND org_id = ?
            AND project_id = ?
            AND env_id = ?
            AND user_id = ?
          LIMIT 1`,
        [userId],
      ).first<D1SessionRow>();
      const now = Date.now();
      const next = appSessionVersion();
      const createdAtMs = parseAppSessionCreatedAt(existing?.record_json, now);
      await this.scopePrepare(
        `INSERT INTO signer_app_session_versions (
          namespace,
          org_id,
          project_id,
          env_id,
          user_id,
          session_version,
          record_json,
          created_at_ms,
          updated_at_ms
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (namespace, org_id, project_id, env_id, user_id)
        DO UPDATE SET
          session_version = EXCLUDED.session_version,
          record_json = EXCLUDED.record_json,
          updated_at_ms = EXCLUDED.updated_at_ms`,
        [
          userId,
          next,
          JSON.stringify(
            appSessionRecord({
              userId,
              appSessionVersion: next,
              createdAtMs,
              updatedAtMs: now,
            }),
          ),
          createdAtMs,
          now,
        ],
      ).run();
      return { ok: true, appSessionVersion: next };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to rotate app session version',
      };
    }
  }

  async validateAppSessionVersion(
    input: ValidateAppSessionVersionInput,
  ): Promise<ValidateAppSessionVersionResult> {
    try {
      const userId = toOptionalTrimmedString(input.userId);
      const appSession = toOptionalTrimmedString(input.appSessionVersion);
      if (!userId || !appSession) {
        return { ok: false, code: 'unauthorized', message: 'Invalid app session' };
      }
      const current = await this.readAppSessionVersion(userId);
      if (!current || current !== appSession) {
        return { ok: false, code: 'invalid_session_version', message: 'App session revoked' };
      }
      return { ok: true };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to validate app session version',
      };
    }
  }

  async listWebAuthnAuthenticatorsForUser(
    input: ListWebAuthnAuthenticatorsInput,
  ): Promise<ListWebAuthnAuthenticatorsResult> {
    try {
      const userId = toOptionalTrimmedString(input.userId);
      if (!userId) return { ok: false, code: 'invalid_args', message: 'Missing userId' };
      const rpId = toOptionalTrimmedString(input.rpId);
      const authRows = await this.readWebAuthnAuthenticatorRows(userId);
      const bindingRows = await this.readWebAuthnBindingRows({ userId, rpId });
      const authByCredentialId = new Map<string, D1AuthenticatorRow>();
      for (const row of authRows) {
        const credentialId = toOptionalTrimmedString(row.credential_id_b64u);
        if (credentialId) authByCredentialId.set(credentialId, row);
      }
      const authenticators: NonNullable<
        ListWebAuthnAuthenticatorsResult['authenticators']
      > = [];
      for (const row of bindingRows) {
        const binding = parseWebAuthnBinding(row);
        if (!binding) continue;
        const authenticator = authByCredentialId.get(binding.credentialIdB64u);
        authenticators.push({
          credentialIdB64u: binding.credentialIdB64u,
          signerSlot: binding.signerSlot,
          publicKey: binding.publicKey,
          createdAtMs:
            optionalNonNegativeInteger(authenticator?.created_at_ms) ?? binding.createdAtMs,
          updatedAtMs:
            optionalNonNegativeInteger(authenticator?.updated_at_ms) ?? binding.updatedAtMs,
        });
      }
      authenticators.sort(compareAuthenticatorSlots);
      return { ok: true, authenticators };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to list authenticators',
      };
    }
  }

  async listNearPublicKeysForUser(
    input: ListNearPublicKeysInput,
  ): Promise<ListNearPublicKeysResult> {
    try {
      const userId = toOptionalTrimmedString(input.userId);
      if (!userId) return { ok: false, code: 'invalid_args', message: 'Missing userId' };
      const result = await this.scopePrepare(
        `SELECT record_json
           FROM signer_near_public_keys
          WHERE namespace = ?
            AND org_id = ?
            AND project_id = ?
            AND env_id = ?
            AND user_id = ?
          ORDER BY COALESCE(signer_slot, 0) ASC, created_at_ms ASC, public_key ASC`,
        [userId],
      ).all<D1RecordJsonRow>();
      const keys: NonNullable<ListNearPublicKeysResult['keys']> = [];
      for (const row of result.results || []) {
        const record = parseNearPublicKey(row);
        if (!record) continue;
        keys.push({
          publicKey: record.publicKey,
          kind: record.kind,
          signerSlot: record.signerSlot,
          createdAtMs: record.createdAtMs,
          updatedAtMs: record.updatedAtMs,
          rpId: record.rpId,
          credentialIdB64u: record.credentialIdB64u,
        });
      }
      return { ok: true, keys };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to list keys',
      };
    }
  }

  getGoogleOidcPublicConfig(): ReturnType<CloudflareRelayAuthService['getGoogleOidcPublicConfig']> {
    const clientId = toOptionalTrimmedString(this.options.googleOidcClientId);
    return {
      configured: Boolean(clientId),
      ...(clientId ? { clientId } : {}),
    };
  }

  async verifyGoogleLogin(input: VerifyGoogleLoginInput): Promise<VerifyGoogleLoginResult> {
    try {
      const clientId = toOptionalTrimmedString(this.options.googleOidcClientId);
      if (!clientId) {
        return {
          ok: false,
          verified: false,
          code: 'not_configured',
          message: 'Google OIDC is not configured on this Worker',
        };
      }
      const idToken = toOptionalTrimmedString(input.idToken ?? input.id_token);
      if (!idToken) {
        return {
          ok: false,
          verified: false,
          code: 'invalid_body',
          message: 'id_token is required',
        };
      }
      const subtle = globalThis.crypto?.subtle;
      if (!subtle) {
        return {
          ok: false,
          verified: false,
          code: 'unsupported',
          message: 'WebCrypto (crypto.subtle) is unavailable in this runtime',
        };
      }

      const parts = idToken.split('.');
      if (parts.length !== 3) {
        return {
          ok: false,
          verified: false,
          code: 'invalid_body',
          message: 'id_token must be a JWT (3 segments)',
        };
      }
      const headerB64u = parts[0] || '';
      const payloadB64u = parts[1] || '';
      const signatureB64u = parts[2] || '';
      const header = parseJwtSegmentJson(headerB64u);
      if (!header) {
        return {
          ok: false,
          verified: false,
          code: 'invalid_body',
          message: 'Invalid id_token header encoding',
        };
      }
      const payload = parseJwtSegmentJson(payloadB64u);
      if (!payload) {
        return {
          ok: false,
          verified: false,
          code: 'invalid_body',
          message: 'Invalid id_token payload encoding',
        };
      }

      const kid = toOptionalTrimmedString(header.kid);
      const alg = toOptionalTrimmedString(header.alg);
      if (!kid) {
        return {
          ok: false,
          verified: false,
          code: 'invalid_body',
          message: 'id_token header.kid is required',
        };
      }
      if (alg !== 'RS256') {
        return {
          ok: false,
          verified: false,
          code: 'invalid_body',
          message: 'id_token header.alg must be RS256',
        };
      }

      const jwks = await this.getGoogleJwks();
      const jwk = jwks.keysByKid.get(kid);
      if (!jwk) {
        return {
          ok: false,
          verified: false,
          code: 'unknown_kid',
          message: 'Unknown Google key id (kid)',
        };
      }

      let signatureBytes: Uint8Array;
      try {
        signatureBytes = base64UrlDecode(signatureB64u);
      } catch {
        return {
          ok: false,
          verified: false,
          code: 'invalid_body',
          message: 'Invalid id_token signature encoding',
        };
      }
      const dataBytes = new TextEncoder().encode(`${headerB64u}.${payloadB64u}`);
      const key = await subtle.importKey(
        'jwk',
        jwk,
        { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
        false,
        ['verify'],
      );
      const verified = await subtle.verify(
        { name: 'RSASSA-PKCS1-v1_5' },
        key,
        toArrayBufferCopy(signatureBytes),
        toArrayBufferCopy(dataBytes),
      );
      if (!verified) {
        return {
          ok: false,
          verified: false,
          code: 'invalid_signature',
          message: 'Invalid Google id_token signature',
        };
      }

      const claims = this.validateGoogleIdTokenClaims({ payload, clientId });
      if (!claims.ok) return claims;
      const providerSubject = `google:${claims.sub}`;
      let userId = providerSubject;
      const linked = await this.readIdentityUserIdBySubject(providerSubject);
      if (linked) userId = linked;
      await this.linkIdentity({
        userId,
        subject: providerSubject,
        allowMoveIfSoleIdentity: false,
      });
      return {
        ok: true,
        verified: true,
        userId,
        providerSubject,
        sub: claims.sub,
        ...(claims.email ? { email: claims.email } : {}),
        ...(claims.name ? { name: claims.name } : {}),
        ...(claims.givenName ? { given_name: claims.givenName } : {}),
        ...(claims.familyName ? { family_name: claims.familyName } : {}),
        ...(typeof claims.emailVerified === 'boolean'
          ? { emailVerified: claims.emailVerified }
          : {}),
        ...(claims.hostedDomain ? { hostedDomain: claims.hostedDomain } : {}),
      };
    } catch (error: unknown) {
      return {
        ok: false,
        verified: false,
        code: 'internal',
        message: errorMessage(error) || 'Google OIDC verification failed',
      };
    }
  }

  private validateGoogleIdTokenClaims(input: {
    readonly payload: Record<string, unknown>;
    readonly clientId: string;
  }):
    | {
        readonly ok: true;
        readonly sub: string;
        readonly email?: string;
        readonly name?: string;
        readonly givenName?: string;
        readonly familyName?: string;
        readonly emailVerified?: boolean;
        readonly hostedDomain?: string;
      }
    | VerifyGoogleLoginFailure {
    const payload = input.payload;
    const iss = toOptionalTrimmedString(payload.iss);
    if (iss !== 'https://accounts.google.com' && iss !== 'accounts.google.com') {
      return {
        ok: false,
        verified: false,
        code: 'invalid_issuer',
        message: 'Invalid Google id_token issuer',
      };
    }
    const nowSec = Math.floor(Date.now() / 1000);
    const exp = Number(payload.exp);
    if (!Number.isFinite(exp) || exp <= 0) {
      return {
        ok: false,
        verified: false,
        code: 'invalid_claims',
        message: 'Invalid Google id_token exp',
      };
    }
    if (nowSec >= exp) {
      return {
        ok: false,
        verified: false,
        code: 'expired',
        message: 'Google id_token is expired',
      };
    }
    if (payload.nbf !== undefined) {
      const nbf = Number(payload.nbf);
      if (!Number.isFinite(nbf)) {
        return {
          ok: false,
          verified: false,
          code: 'invalid_claims',
          message: 'Invalid Google id_token nbf',
        };
      }
      if (nowSec < nbf) {
        return {
          ok: false,
          verified: false,
          code: 'not_yet_valid',
          message: 'Google id_token is not yet valid',
        };
      }
    }

    const aud = parseJwtAud(payload.aud);
    if (aud.length === 0) {
      return {
        ok: false,
        verified: false,
        code: 'invalid_claims',
        message: 'Missing Google id_token aud',
      };
    }
    if (!aud.includes(input.clientId)) {
      return {
        ok: false,
        verified: false,
        code: 'invalid_audience',
        message: 'Google id_token audience mismatch',
      };
    }

    const sub = toOptionalTrimmedString(payload.sub);
    if (!sub) {
      return {
        ok: false,
        verified: false,
        code: 'invalid_claims',
        message: 'Missing Google id_token sub',
      };
    }
    const email = toOptionalTrimmedString(payload.email);
    const name = toOptionalTrimmedString(payload.name);
    const givenName = toOptionalTrimmedString(payload.given_name);
    const familyName = toOptionalTrimmedString(payload.family_name);
    const emailVerified = parseBooleanJwtClaim(payload.email_verified);
    const hostedDomain = toOptionalTrimmedString(payload.hd);
    return {
      ok: true,
      sub,
      ...(email ? { email } : {}),
      ...(name ? { name } : {}),
      ...(givenName ? { givenName } : {}),
      ...(familyName ? { familyName } : {}),
      ...(typeof emailVerified === 'boolean' ? { emailVerified } : {}),
      ...(hostedDomain ? { hostedDomain } : {}),
    };
  }

  private async getGoogleJwks(): Promise<JsonWebKeyCache> {
    const nowMs = Date.now();
    if (this.googleJwksCache && nowMs < this.googleJwksCache.expiresAtMs) {
      return this.googleJwksCache;
    }
    if (this.googleJwksFetchPromise) return await this.googleJwksFetchPromise;
    this.googleJwksFetchPromise = this.fetchGoogleJwks(nowMs);
    try {
      return await this.googleJwksFetchPromise;
    } finally {
      this.googleJwksFetchPromise = null;
    }
  }

  private async fetchGoogleJwks(nowMs: number): Promise<JsonWebKeyCache> {
    if (typeof fetch !== 'function') {
      throw new Error('fetch is unavailable in this runtime');
    }
    const response = await fetch('https://www.googleapis.com/oauth2/v3/certs');
    const text = await response.text();
    if (!response.ok) {
      throw new Error(
        `Google OIDC certs fetch failed (HTTP ${response.status}): ${text.slice(0, 200)}`,
      );
    }
    let parsed: unknown;
    try {
      parsed = text ? JSON.parse(text) : null;
    } catch {
      throw new Error('Google OIDC certs returned non-JSON response');
    }
    const keysByKid = parseGoogleJwks(parsed);
    if (!keysByKid) throw new Error('Google OIDC certs returned no usable RSA keys');
    const maxAgeSec = parseCacheControlMaxAgeSec(response.headers.get('cache-control')) || 60 * 60;
    const value = { keysByKid, expiresAtMs: nowMs + maxAgeSec * 1000 };
    this.googleJwksCache = value;
    return value;
  }

  private async resolveGoogleEmailOtpLoginSession(input: {
    readonly providerSubject: string;
    readonly email: string;
    readonly orgId: string;
    readonly walletSubject: string;
    readonly linkedWalletId: string | null;
    readonly linkedIsUsableRelayerWallet: boolean;
    readonly linkedIsHostedHmacReadableWallet: boolean;
  }): Promise<ResolveGoogleEmailOtpSessionResult> {
    if (
      input.linkedWalletId &&
      input.linkedIsUsableRelayerWallet &&
      input.linkedIsHostedHmacReadableWallet
    ) {
      const enrollment = await this.readActiveEmailOtpEnrollment({
        walletId: input.linkedWalletId,
        orgId: input.orgId,
        providerUserId: input.providerSubject,
      });
      if (enrollment.ok) {
        return {
          ok: true,
          mode: 'existing_wallet',
          walletId: input.linkedWalletId,
          providerSubject: input.providerSubject,
          ...(input.email ? { email: input.email } : {}),
          hasEmailOtpEnrollment: true,
        };
      }
      if (!this.isGoogleEmailOtpEnrollmentLookupMiss(enrollment.code)) {
        throw codedError(enrollment.code, enrollment.message);
      }
    }

    const discovered = await this.getGoogleEmailOtpEnrollmentBySubject({
      providerSubject: input.providerSubject,
      orgId: input.orgId,
    });
    if (!discovered) {
      if (input.linkedWalletId) {
        const stale = googleEmailOtpStaleIdentityMapping({
          providerSubject: input.providerSubject,
          linkedWalletId: input.linkedWalletId,
          ...(input.email ? { email: input.email } : {}),
        });
        throw codedError(stale.code, stale.message);
      }
      throw codedError('not_found', 'Email OTP enrollment not found');
    }

    const repaired = await this.repairGoogleEmailOtpWalletLink({
      providerSubject: input.providerSubject,
      walletId: discovered.walletId,
    });
    if (!repaired.ok) throw codedError(repaired.code, repaired.message);
    return {
      ok: true,
      mode: 'existing_wallet',
      walletId: discovered.walletId,
      providerSubject: input.providerSubject,
      ...(input.email ? { email: input.email } : {}),
      hasEmailOtpEnrollment: true,
    };
  }

  private async resolveGoogleEmailOtpRegistrationSession(input: {
    readonly providerSubject: string;
    readonly email: string;
    readonly orgId: string;
    readonly appSessionVersion: string;
    readonly runtimePolicyScope: RuntimePolicyScope;
    readonly restartRegistrationOffer: boolean;
    readonly walletSubject: string;
    readonly linkedWalletId: string | null;
  }): Promise<ResolveGoogleEmailOtpSessionResult> {
    const discoveredExistingEnrollment = await this.getGoogleEmailOtpEnrollmentBySubject({
      providerSubject: input.providerSubject,
      orgId: input.orgId,
    });
    if (discoveredExistingEnrollment && !input.restartRegistrationOffer) {
      const repaired = await this.repairGoogleEmailOtpWalletLink({
        providerSubject: input.providerSubject,
        walletId: discoveredExistingEnrollment.walletId,
      });
      if (!repaired.ok) {
        return {
          ok: false,
          mode: 'registration_incomplete',
          code: 'registration_incomplete',
          walletId: discoveredExistingEnrollment.walletId,
          providerSubject: input.providerSubject,
          email: input.email,
          message: repaired.message,
        };
      }
      return {
        ok: true,
        mode: 'existing_wallet',
        walletId: discoveredExistingEnrollment.walletId,
        providerSubject: input.providerSubject,
        email: input.email,
        hasEmailOtpEnrollment: true,
      };
    }
    if (input.linkedWalletId && !input.restartRegistrationOffer) {
      return googleEmailOtpStaleIdentityMapping({
        providerSubject: input.providerSubject,
        linkedWalletId: input.linkedWalletId,
        email: input.email,
      });
    }

    const nowMs = Date.now();
    await this.abandonStartedGoogleEmailOtpRegistrationAttemptsExceptAppSession({
      providerSubject: input.providerSubject,
      email: input.email,
      orgId: input.orgId,
      appSessionVersion: input.appSessionVersion,
      runtimePolicyScope: input.runtimePolicyScope,
      nowMs,
      failureCode: 'app_session_version_replaced',
    });

    const startedAttempt = await this.findStartedGoogleEmailOtpRegistrationAttempt({
      providerSubject: input.providerSubject,
      email: input.email,
      orgId: input.orgId,
      appSessionVersion: input.appSessionVersion,
      runtimePolicyScope: input.runtimePolicyScope,
    });
    if (startedAttempt) {
      if (input.restartRegistrationOffer) {
        await this.putGoogleEmailOtpRegistrationAttempt(
          abandonedGoogleEmailOtpRegistrationAttemptRecord({
            record: startedAttempt,
            failureCode: 'offer_restarted_by_user',
            updatedAtMs: Date.now(),
          }),
        );
      } else {
        return {
          ok: true,
          mode: 'register_started',
          walletId: startedAttempt.walletId,
          providerSubject: input.providerSubject,
          email: input.email,
          registrationAttemptId: startedAttempt.attemptId,
          expiresAtMs: startedAttempt.expiresAtMs,
          offer: googleEmailOtpRegistrationOfferForResponse(startedAttempt),
        };
      }
    }

    return await this.createFreshGoogleEmailOtpRegistrationAttempt(input);
  }

  private async createFreshGoogleEmailOtpRegistrationAttempt(input: {
    readonly providerSubject: string;
    readonly email: string;
    readonly orgId: string;
    readonly appSessionVersion: string;
    readonly runtimePolicyScope: RuntimePolicyScope;
    readonly walletSubject: string;
  }): Promise<ResolveGoogleEmailOtpSessionResult> {
    const nowMs = Date.now();
    const authProvider = 'google_oidc';
    const walletIdDerivationNonce = secureRandomBase64Url(
      18,
      'google email otp wallet derivation nonces',
    );
    const offerCandidates: GoogleEmailOtpRegistrationOfferCandidateRecord[] = [];
    for (let attempt = 0; attempt < 30 && offerCandidates.length < 5; attempt += 1) {
      const walletId = await this.deriveHostedGoogleEmailOtpWalletId({
        providerSubject: input.providerSubject,
        email: input.email,
        authProvider,
        runtimePolicyScope: input.runtimePolicyScope,
        walletIdDerivationNonce,
        collisionCounter: attempt,
      });
      const inUseByLiveAttempt = await this.hasLiveStartedGoogleEmailOtpWalletAttempt({
        walletId,
        nowMs,
      });
      if (inUseByLiveAttempt) continue;
      const inUseByEnrollment = await this.readEmailOtpWalletEnrollment(walletId);
      if (inUseByEnrollment) continue;
      const existingSubjects = await this.readIdentitySubjectsByUserId(walletId);
      if (
        hasDifferentWalletIdentitySubject({
          subjects: existingSubjects,
          expectedWalletSubject: input.walletSubject,
        })
      ) {
        continue;
      }
      offerCandidates.push({
        candidateId: secureRandomBase64Url(18, 'google email otp offer candidate ids'),
        walletId,
        collisionCounter: attempt,
      });
    }

    const selectedCandidate = offerCandidates[0];
    if (!selectedCandidate) {
      return {
        ok: false,
        mode: 'registration_incomplete',
        code: 'registration_incomplete',
        providerSubject: input.providerSubject,
        email: input.email,
        message: 'Unable to allocate a fresh Google Email OTP registration attempt',
      };
    }
    const nonEmptyOfferCandidates: NonEmptyGoogleEmailOtpRegistrationOfferCandidates = [
      selectedCandidate,
      ...offerCandidates.slice(1),
    ];
    const attempt = await this.createGoogleEmailOtpRegistrationAttempt({
      providerSubject: input.providerSubject,
      email: input.email,
      walletId: selectedCandidate.walletId,
      offerId: secureRandomBase64Url(18, 'google email otp offer ids'),
      offerCandidates: nonEmptyOfferCandidates,
      selectedCandidateId: selectedCandidate.candidateId,
      appSessionVersion: input.appSessionVersion,
      authProvider,
      walletIdDerivationNonce,
      collisionCounter: selectedCandidate.collisionCounter,
      runtimePolicyScope: input.runtimePolicyScope,
    });
    return {
      ok: true,
      mode: 'register_started',
      walletId: attempt.walletId,
      providerSubject: input.providerSubject,
      email: input.email,
      registrationAttemptId: attempt.attemptId,
      expiresAtMs: attempt.expiresAtMs,
      offer: googleEmailOtpRegistrationOfferForResponse(attempt),
    };
  }

  private isRelayerSubaccount(accountId: string): boolean {
    const relayerAccount = toOptionalTrimmedString(this.options.relayerAccount);
    return Boolean(relayerAccount && accountId.endsWith(`.${relayerAccount}`));
  }

  private isHostedHmacReadableRelayerSubaccount(accountId: string): boolean {
    const relayerAccount = toOptionalTrimmedString(this.options.relayerAccount);
    if (!relayerAccount || !accountId.endsWith(`.${relayerAccount}`)) return false;
    const slug = accountId.slice(0, -(relayerAccount.length + 1));
    return /^[a-z]+-[a-z]+-[a-z0-9]{10}$/.test(slug);
  }

  private async deriveHostedGoogleEmailOtpWalletId(input: {
    readonly providerSubject: string;
    readonly email: string;
    readonly authProvider: string;
    readonly runtimePolicyScope: RuntimePolicyScope;
    readonly walletIdDerivationNonce: string;
    readonly collisionCounter: number;
  }): Promise<string> {
    return await deriveHostedNearAccountId({
      accountIdDerivationSecret: requireD1RelayAuthScopeString(
        this.options.accountIdDerivationSecret,
        'ACCOUNT_ID_DERIVATION_SECRET',
      ),
      relayerAccount: requireD1RelayAuthScopeString(this.options.relayerAccount, 'relayerAccount'),
      projectId: input.runtimePolicyScope.projectId,
      envId: input.runtimePolicyScope.envId,
      authProvider: input.authProvider,
      providerSubject: input.providerSubject,
      verifiedEmail: input.email,
      walletIdDerivationNonce: input.walletIdDerivationNonce,
      ...(input.collisionCounter > 0 ? { collisionCounter: input.collisionCounter } : {}),
    });
  }

  private async getGoogleEmailOtpEnrollmentBySubject(input: {
    readonly providerSubject: string;
    readonly orgId: string;
  }): Promise<EmailOtpWalletEnrollmentRecord | null> {
    const enrollment = await this.readEmailOtpWalletEnrollmentByProviderUserId({
      providerUserId: input.providerSubject,
      orgId: input.orgId,
    });
    if (
      !enrollment ||
      enrollment.providerUserId !== input.providerSubject ||
      enrollment.orgId !== input.orgId ||
      !isValidAccountId(enrollment.walletId) ||
      !this.isHostedHmacReadableRelayerSubaccount(enrollment.walletId)
    ) {
      return null;
    }
    return enrollment;
  }

  private async repairGoogleEmailOtpWalletLink(input: {
    readonly providerSubject: string;
    readonly walletId: string;
  }): Promise<LinkIdentityResult> {
    return await this.linkIdentity({
      userId: input.walletId,
      subject: `wallet:${input.providerSubject}`,
      allowMoveIfSoleIdentity: true,
    });
  }

  private isGoogleEmailOtpEnrollmentLookupMiss(code: string): boolean {
    return (
      code === 'not_found' ||
      code === 'provider_identity_mismatch' ||
      code === 'tenant_scope_mismatch'
    );
  }

  private async cleanupGoogleEmailOtpRegistrationAttempts(nowMs: number): Promise<void> {
    await this.scopePrepare(
      `DELETE FROM signer_email_otp_registration_attempts
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND (expires_at_ms <= ? OR state = 'expired')`,
      [nowMs],
    ).run();
  }

  private async createGoogleEmailOtpRegistrationAttempt(input: {
    readonly providerSubject: string;
    readonly email: string;
    readonly walletId: string;
    readonly offerId: string;
    readonly offerCandidates: NonEmptyGoogleEmailOtpRegistrationOfferCandidates;
    readonly selectedCandidateId: string;
    readonly appSessionVersion: string;
    readonly authProvider: string;
    readonly walletIdDerivationNonce: string;
    readonly collisionCounter: number;
    readonly runtimePolicyScope: RuntimePolicyScope;
  }): Promise<PendingGoogleEmailOtpRegistrationAttemptRecord> {
    const nowMs = Date.now();
    await this.cleanupGoogleEmailOtpRegistrationAttempts(nowMs);
    const attempt: PendingGoogleEmailOtpRegistrationAttemptRecord = {
      version: 'google_email_otp_registration_attempt_v1',
      attemptId: secureRandomBase64Url(18, 'google email otp registration attempt ids'),
      providerSubject: input.providerSubject,
      email: input.email,
      walletId: input.walletId,
      offerId: input.offerId,
      offerCandidates: input.offerCandidates,
      selectedCandidateId: input.selectedCandidateId,
      appSessionVersion: input.appSessionVersion,
      authProvider: input.authProvider,
      accountIdSlugVersion: 'hmac_readable_v1',
      walletIdDerivationNonce: input.walletIdDerivationNonce,
      collisionCounter: input.collisionCounter,
      state: 'started',
      createdAtMs: nowMs,
      updatedAtMs: nowMs,
      expiresAtMs: nowMs + 30 * 60_000,
      runtimePolicyScope: input.runtimePolicyScope,
    };
    await this.putGoogleEmailOtpRegistrationAttempt(attempt);
    return attempt;
  }

  private async findStartedGoogleEmailOtpRegistrationAttempt(input: {
    readonly providerSubject: string;
    readonly email: string;
    readonly orgId: string;
    readonly appSessionVersion: string;
    readonly runtimePolicyScope: RuntimePolicyScope;
  }): Promise<PendingGoogleEmailOtpRegistrationAttemptRecord | null> {
    const nowMs = Date.now();
    await this.cleanupGoogleEmailOtpRegistrationAttempts(nowMs);
    const row = await this.scopePrepare(
      `SELECT record_json, expires_at_ms, updated_at_ms, attempt_id
         FROM signer_email_otp_registration_attempts
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND provider_subject = ?
          AND email = ?
          AND state IN ('started', 'key_finalized')
          AND expires_at_ms > ?
          AND app_session_version = ?
          AND runtime_org_id = ?
          AND runtime_policy_key = ?
        ORDER BY updated_at_ms DESC
        LIMIT 1`,
      [
        input.providerSubject,
        input.email,
        nowMs,
        input.appSessionVersion,
        input.orgId,
        runtimePolicyScopeKey(input.runtimePolicyScope),
      ],
    ).first<D1EmailOtpRegistrationAttemptRow>();
    const parsed = parseGoogleEmailOtpRegistrationAttemptRow(row);
    if (!parsed) {
      const malformedAttemptId = toOptionalTrimmedString(row?.attempt_id);
      if (malformedAttemptId) await this.deleteGoogleEmailOtpRegistrationAttempt(malformedAttemptId);
      return null;
    }
    if (
      !registrationAttemptMatchesStartedScope(parsed, {
        providerSubject: input.providerSubject,
        email: input.email,
        orgId: input.orgId,
        appSessionVersion: input.appSessionVersion,
        runtimePolicyScope: input.runtimePolicyScope,
        nowMs,
      })
    ) {
      return null;
    }
    if (!this.isHostedHmacReadableRelayerSubaccount(parsed.walletId)) {
      await this.putGoogleEmailOtpRegistrationAttempt(
        failedGoogleEmailOtpRegistrationAttemptRecord({
          record: parsed,
          failureCode: 'non_hmac_readable_wallet_id',
          updatedAtMs: nowMs,
        }),
      );
      return null;
    }
    const refreshed = pendingGoogleEmailOtpRegistrationAttemptWithUpdatedAt(parsed, nowMs);
    await this.putGoogleEmailOtpRegistrationAttempt(refreshed);
    return refreshed;
  }

  private async abandonStartedGoogleEmailOtpRegistrationAttemptsExceptAppSession(input: {
    readonly providerSubject: string;
    readonly email: string;
    readonly orgId: string;
    readonly appSessionVersion: string;
    readonly runtimePolicyScope: RuntimePolicyScope;
    readonly nowMs: number;
    readonly failureCode: 'app_session_version_replaced';
  }): Promise<void> {
    const result = await this.scopePrepare(
      `SELECT record_json, expires_at_ms, updated_at_ms, attempt_id
         FROM signer_email_otp_registration_attempts
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND provider_subject = ?
          AND email = ?
          AND state IN ('started', 'key_finalized')
          AND expires_at_ms > ?`,
      [input.providerSubject, input.email, input.nowMs],
    ).all<D1EmailOtpRegistrationAttemptRow>();
    for (const row of result.results || []) {
      const parsed = parseGoogleEmailOtpRegistrationAttemptRow(row);
      if (!parsed) {
        const malformedAttemptId = toOptionalTrimmedString(row.attempt_id);
        if (malformedAttemptId) {
          await this.deleteGoogleEmailOtpRegistrationAttempt(malformedAttemptId);
        }
        continue;
      }
      if (!registrationAttemptMatchesReplacementScope(parsed, input)) continue;
      await this.putGoogleEmailOtpRegistrationAttempt(
        abandonedGoogleEmailOtpRegistrationAttemptRecord({
          record: parsed,
          failureCode: input.failureCode,
          updatedAtMs: input.nowMs,
        }),
      );
    }
  }

  private async hasLiveStartedGoogleEmailOtpWalletAttempt(input: {
    readonly walletId: string;
    readonly nowMs: number;
  }): Promise<boolean> {
    const row = await this.scopePrepare(
      `SELECT 1 AS found
         FROM signer_email_otp_registration_attempts
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND state IN ('started', 'key_finalized')
          AND expires_at_ms > ?
          AND (
            wallet_id = ?
            OR EXISTS (
              SELECT 1
                FROM json_each(offer_wallet_ids_json)
               WHERE value = ?
            )
          )
        LIMIT 1`,
      [input.nowMs, input.walletId, input.walletId],
    ).first<{ readonly found?: unknown }>();
    return Boolean(row);
  }

  private async putGoogleEmailOtpRegistrationAttempt(
    record: GoogleEmailOtpRegistrationAttemptRecord,
  ): Promise<void> {
    if (record.runtimePolicyScope?.orgId !== this.options.orgId) {
      throw new Error('Google Email OTP registration attempt org scope mismatch');
    }
    await this.scopePrepare(
      `INSERT INTO signer_email_otp_registration_attempts (
        namespace,
        org_id,
        project_id,
        env_id,
        attempt_id,
        provider_subject,
        email,
        wallet_id,
        state,
        app_session_version,
        runtime_org_id,
        runtime_policy_key,
        offer_wallet_ids_json,
        record_json,
        created_at_ms,
        updated_at_ms,
        expires_at_ms
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT (namespace, org_id, project_id, env_id, attempt_id)
      DO UPDATE SET
        provider_subject = EXCLUDED.provider_subject,
        email = EXCLUDED.email,
        wallet_id = EXCLUDED.wallet_id,
        state = EXCLUDED.state,
        app_session_version = EXCLUDED.app_session_version,
        runtime_org_id = EXCLUDED.runtime_org_id,
        runtime_policy_key = EXCLUDED.runtime_policy_key,
        offer_wallet_ids_json = EXCLUDED.offer_wallet_ids_json,
        record_json = EXCLUDED.record_json,
        created_at_ms = EXCLUDED.created_at_ms,
        updated_at_ms = EXCLUDED.updated_at_ms,
        expires_at_ms = EXCLUDED.expires_at_ms`,
      [
        record.attemptId,
        record.providerSubject,
        record.email,
        record.walletId,
        record.state,
        record.appSessionVersion,
        record.runtimePolicyScope?.orgId || '',
        runtimePolicyScopeKey(record.runtimePolicyScope),
        googleEmailOtpRegistrationOfferWalletIdsJson(record.offerCandidates),
        JSON.stringify(record),
        record.createdAtMs,
        record.updatedAtMs,
        record.expiresAtMs,
      ],
    ).run();
  }

  private async deleteGoogleEmailOtpRegistrationAttempt(attemptId: string): Promise<void> {
    await this.scopePrepare(
      `DELETE FROM signer_email_otp_registration_attempts
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND attempt_id = ?`,
      [attemptId],
    ).run();
  }

  private scopePrepare(sql: string, values: readonly unknown[]): D1PreparedStatementLike {
    return this.options.database.prepare(sql).bind(...this.scopeValues(values));
  }

  private scopeValues(values: readonly unknown[]): readonly unknown[] {
    return [
      this.options.namespace,
      this.options.orgId,
      this.options.projectId,
      this.options.envId,
      ...values,
    ];
  }

  private async readIdentityLinkBySubject(subject: string): Promise<D1IdentityRow | null> {
    return await this.scopePrepare(
      `SELECT user_id, created_at_ms
         FROM signer_identity_links
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND subject = ?
        LIMIT 1`,
      [subject],
    ).first<D1IdentityRow>();
  }

  private async readIdentityUserIdBySubject(subject: string): Promise<string | null> {
    const row = await this.readIdentityLinkBySubject(subject);
    return toOptionalTrimmedString(row?.user_id) || null;
  }

  private async readIdentitySubjectCountForUserId(userId: string): Promise<number> {
    const row = await this.scopePrepare(
      `SELECT COUNT(*) AS subject_count
         FROM signer_identity_links
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND user_id = ?`,
      [userId],
    ).first<D1IdentityRow>();
    return parseIdentitySubjectCount(row?.subject_count);
  }

  private async readIdentitySubjectsByUserId(userId: string): Promise<string[]> {
    const result = await this.scopePrepare(
      `SELECT subject
         FROM signer_identity_links
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND user_id = ?
        ORDER BY subject ASC`,
      [userId],
    ).all<D1IdentityRow>();
    const subjects: string[] = [];
    for (const row of result.results || []) {
      const subject = toOptionalTrimmedString(row.subject);
      if (subject) subjects.push(subject);
    }
    return subjects;
  }

  private async moveIdentityIfAllowed(input: {
    readonly userId: string;
    readonly subject: string;
    readonly existingUserId: string;
    readonly createdAtMs: number;
    readonly updatedAtMs: number;
    readonly allowMoveIfSoleIdentity: boolean;
  }): Promise<LinkIdentityResult> {
    if (!input.allowMoveIfSoleIdentity) return identityAlreadyLinked();

    const moved = d1MutationChanges(
      await this.options.database
        .prepare(
          `UPDATE signer_identity_links
              SET user_id = ?,
                  record_json = ?,
                  updated_at_ms = ?
            WHERE namespace = ?
              AND org_id = ?
              AND project_id = ?
              AND env_id = ?
              AND subject = ?
              AND user_id = ?
              AND (
                SELECT COUNT(*)
                  FROM signer_identity_links
                 WHERE namespace = ?
                   AND org_id = ?
                   AND project_id = ?
                   AND env_id = ?
                   AND user_id = ?
              ) = 1`,
        )
        .bind(
          input.userId,
          JSON.stringify(
            identitySubjectRecord({
              subject: input.subject,
              userId: input.userId,
              createdAtMs: input.createdAtMs,
              updatedAtMs: input.updatedAtMs,
            }),
          ),
          input.updatedAtMs,
          ...this.scopeValues([input.subject, input.existingUserId]),
          ...this.scopeValues([input.existingUserId]),
        )
        .run(),
    );

    if (moved > 0) return { ok: true, movedFromUserId: input.existingUserId };
    const subjectCount = await this.readIdentitySubjectCountForUserId(input.existingUserId);
    if (subjectCount !== 1) return identityMoveDisallowed();
    return identityAlreadyLinked();
  }

  private async readEmailOtpWalletEnrollment(
    walletId: string,
  ): Promise<EmailOtpWalletEnrollmentRecord | null> {
    const row = await this.scopePrepare(
      `SELECT record_json, updated_at_ms
         FROM signer_email_otp_wallet_enrollments
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND wallet_id = ?
        LIMIT 1`,
      [walletId],
    ).first<D1EmailOtpEnrollmentRow>();
    return parseEmailOtpWalletEnrollmentRow(row);
  }

  private async readEmailOtpWalletEnrollmentByProviderUserId(input: {
    readonly providerUserId: string;
    readonly orgId: string;
  }): Promise<EmailOtpWalletEnrollmentRecord | null> {
    const row = await this.scopePrepare(
      `SELECT record_json, updated_at_ms
         FROM signer_email_otp_wallet_enrollments
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND provider_user_id = ?
          AND record_org_id = ?
        ORDER BY updated_at_ms DESC
        LIMIT 1`,
      [input.providerUserId, input.orgId],
    ).first<D1EmailOtpEnrollmentRow>();
    return parseEmailOtpWalletEnrollmentRow(row);
  }

  private async readEmailOtpAuthState(
    walletId: string,
  ): Promise<EmailOtpAuthStateRecord | null> {
    const row = await this.scopePrepare(
      `SELECT record_json, updated_at_ms
         FROM signer_email_otp_auth_states
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND wallet_id = ?
        LIMIT 1`,
      [walletId],
    ).first<D1EmailOtpAuthStateRow>();
    return parseEmailOtpAuthStateRow(row);
  }

  private async readEmailOtpAuthStateForEnrollment(
    enrollment: EmailOtpWalletEnrollmentRecord,
  ): Promise<
    | { ok: true; state: EmailOtpAuthStateRecord | null }
    | { ok: false; code: string; message: string }
  > {
    const state = await this.readEmailOtpAuthState(enrollment.walletId);
    if (!state) return { ok: true, state: null };
    if (state.orgId !== enrollment.orgId || state.providerUserId !== enrollment.providerUserId) {
      return {
        ok: false,
        code: 'auth_state_enrollment_mismatch',
        message: 'Email OTP auth state does not match the active enrollment',
      };
    }
    return { ok: true, state };
  }

  private async putEmailOtpAuthStateForEnrollment(
    enrollment: EmailOtpWalletEnrollmentRecord,
    patch: EmailOtpAuthStatePatch,
  ): Promise<EmailOtpAuthStateRecord> {
    const nowMs = Date.now();
    const existing = await this.readEmailOtpAuthState(enrollment.walletId);
    if (
      existing &&
      (existing.orgId !== enrollment.orgId || existing.providerUserId !== enrollment.providerUserId)
    ) {
      throw new Error('Email OTP auth state does not match the active enrollment');
    }
    const next = emailOtpAuthStateRecord({
      enrollment,
      existing,
      updatedAtMs: nowMs,
      patch,
    });
    await this.scopePrepare(
      `INSERT INTO signer_email_otp_auth_states (
        namespace,
        org_id,
        project_id,
        env_id,
        wallet_id,
        provider_user_id,
        record_org_id,
        record_json,
        created_at_ms,
        updated_at_ms
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT (namespace, org_id, project_id, env_id, wallet_id)
      DO UPDATE SET
        provider_user_id = EXCLUDED.provider_user_id,
        record_org_id = EXCLUDED.record_org_id,
        record_json = EXCLUDED.record_json,
        created_at_ms = EXCLUDED.created_at_ms,
        updated_at_ms = EXCLUDED.updated_at_ms`,
      [
        next.walletId,
        next.providerUserId,
        next.orgId,
        JSON.stringify(next),
        next.createdAtMs,
        next.updatedAtMs,
      ],
    ).run();
    return next;
  }

  private async resetEmailOtpFailureState(input: {
    readonly enrollment: EmailOtpWalletEnrollmentRecord;
    readonly authState: EmailOtpAuthStateRecord | null;
  }): Promise<void> {
    const hasFailureState =
      Number(input.authState?.otpFailureCount || 0) > 0 ||
      input.authState?.lastOtpFailureAtMs != null ||
      input.authState?.otpLockedUntilMs != null;
    if (!hasFailureState) return;
    await this.putEmailOtpAuthStateForEnrollment(input.enrollment, {
      otpFailureCount: 0,
      lastOtpFailureAtMs: null,
      otpLockedUntilMs: null,
    });
  }

  private async recordEmailOtpInvalidAttempt(input: {
    readonly enrollment: EmailOtpWalletEnrollmentRecord;
    readonly authState: EmailOtpAuthStateRecord | null;
    readonly record: EmailOtpChallengeRecord;
  }): Promise<Extract<EmailOtpExistingChallengeVerifyResult, { ok: false }>> {
    const nextAttemptCount = input.record.attemptCount + 1;
    const nextFailureCount = Number(input.authState?.otpFailureCount || 0) + 1;
    const exhausted = nextAttemptCount >= input.record.maxAttempts;
    const nowMs = Date.now();
    const lockedUntilMs = exhausted ? nowMs + this.options.emailOtp.lockoutTtlMs : undefined;
    await this.putEmailOtpAuthStateForEnrollment(input.enrollment, {
      otpFailureCount: nextFailureCount,
      lastOtpFailureAtMs: nowMs,
      ...(lockedUntilMs ? { otpLockedUntilMs: lockedUntilMs } : {}),
    });
    if (exhausted) {
      await this.deleteEmailOtpChallenge(input.record.challengeId);
      return {
        ok: false,
        code: 'otp_attempts_exhausted',
        message: 'Email OTP challenge exceeded the maximum number of attempts',
        attemptsRemaining: 0,
        ...(lockedUntilMs ? { lockedUntilMs } : {}),
      };
    }
    await this.updateEmailOtpChallengeAttemptCount(input.record, nextAttemptCount);
    return {
      ok: false,
      code: 'invalid_otp',
      message: 'OTP code is invalid',
      attemptsRemaining: input.record.maxAttempts - nextAttemptCount,
    };
  }

  private async pruneExpiredEmailOtpChallenges(nowMs: number): Promise<void> {
    const result = await this.scopePrepare(
      `DELETE FROM signer_email_otp_challenges
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND expires_at_ms <= ?
      RETURNING challenge_id`,
      [nowMs],
    ).all<D1EmailOtpChallengeRow>();
    for (const row of result.results || []) {
      const challengeId = toOptionalTrimmedString(row.challenge_id);
      if (challengeId) this.emailOtpMemoryOutbox.delete(challengeId);
    }
  }

  private async readEmailOtpChallenge(
    challengeId: string,
  ): Promise<EmailOtpChallengeRecord | null> {
    const row = await this.scopePrepare(
      `SELECT record_json, expires_at_ms
         FROM signer_email_otp_challenges
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND challenge_id = ?
        LIMIT 1`,
      [challengeId],
    ).first<D1EmailOtpChallengeRow>();
    return parseEmailOtpChallengeRow(row);
  }

  private async findLatestActiveEmailOtpChallenge(input: {
    readonly challengeSubjectId: string;
    readonly walletId: string;
    readonly orgId: string;
    readonly sessionHash: string;
    readonly appSessionVersion: string;
    readonly action: EmailOtpExistingChallengeAction;
    readonly operation: EmailOtpChallengeOperation;
    readonly nowMs: number;
  }): Promise<EmailOtpChallengeRecord | null> {
    const row = await this.scopePrepare(
      `SELECT record_json, expires_at_ms
         FROM signer_email_otp_challenges
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND challenge_subject_id = ?
          AND wallet_id = ?
          AND record_org_id = ?
          AND otp_channel = ?
          AND session_hash = ?
          AND app_session_version = ?
          AND action = ?
          AND operation = ?
          AND expires_at_ms > ?
        ORDER BY created_at_ms DESC
        LIMIT 1`,
      [...emailOtpChallengeContextValues(input), input.nowMs],
    ).first<D1EmailOtpChallengeRow>();
    return parseEmailOtpChallengeRow(row);
  }

  private async enforceEmailOtpActiveChallengeLimit(input: {
    readonly challengeSubjectId: string;
    readonly walletId: string;
    readonly orgId: string;
    readonly sessionHash: string;
    readonly appSessionVersion: string;
    readonly action: EmailOtpExistingChallengeAction;
    readonly operation: EmailOtpChallengeOperation;
    readonly nowMs: number;
  }): Promise<void> {
    let count = await this.countActiveEmailOtpChallenges(input);
    while (count >= this.options.emailOtp.maxActiveChallengesPerContext) {
      const deleted = await this.deleteOldestActiveEmailOtpChallenge(input);
      if (!deleted) return;
      this.emailOtpMemoryOutbox.delete(deleted.challengeId);
      count -= 1;
    }
  }

  private async countActiveEmailOtpChallenges(input: {
    readonly challengeSubjectId: string;
    readonly walletId: string;
    readonly orgId: string;
    readonly sessionHash: string;
    readonly appSessionVersion: string;
    readonly action: EmailOtpExistingChallengeAction;
    readonly operation: EmailOtpChallengeOperation;
    readonly nowMs: number;
  }): Promise<number> {
    const row = await this.scopePrepare(
      `SELECT COUNT(*) AS subject_count
         FROM signer_email_otp_challenges
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND challenge_subject_id = ?
          AND wallet_id = ?
          AND record_org_id = ?
          AND otp_channel = ?
          AND session_hash = ?
          AND app_session_version = ?
          AND action = ?
          AND operation = ?
          AND expires_at_ms > ?`,
      [...emailOtpChallengeContextValues(input), input.nowMs],
    ).first<D1IdentityRow>();
    return parseIdentitySubjectCount(row?.subject_count);
  }

  private async deleteOldestActiveEmailOtpChallenge(input: {
    readonly challengeSubjectId: string;
    readonly walletId: string;
    readonly orgId: string;
    readonly sessionHash: string;
    readonly appSessionVersion: string;
    readonly action: EmailOtpExistingChallengeAction;
    readonly operation: EmailOtpChallengeOperation;
    readonly nowMs: number;
  }): Promise<EmailOtpChallengeRecord | null> {
    const row = await this.scopePrepare(
      `DELETE FROM signer_email_otp_challenges
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND challenge_id = (
            SELECT challenge_id
              FROM signer_email_otp_challenges
             WHERE namespace = ?
               AND org_id = ?
               AND project_id = ?
               AND env_id = ?
               AND challenge_subject_id = ?
               AND wallet_id = ?
               AND record_org_id = ?
               AND otp_channel = ?
               AND session_hash = ?
               AND app_session_version = ?
               AND action = ?
               AND operation = ?
               AND expires_at_ms > ?
             ORDER BY created_at_ms ASC
             LIMIT 1
          )
      RETURNING record_json, expires_at_ms`,
      [...this.scopeValues([]), ...this.scopeValues([...emailOtpChallengeContextValues(input), input.nowMs])],
    ).first<D1EmailOtpChallengeRow>();
    return parseEmailOtpChallengeRow(row);
  }

  private async putEmailOtpChallenge(record: EmailOtpChallengeRecord): Promise<void> {
    await this.scopePrepare(
      `INSERT INTO signer_email_otp_challenges (
        namespace,
        org_id,
        project_id,
        env_id,
        challenge_id,
        challenge_subject_id,
        wallet_id,
        record_org_id,
        otp_channel,
        session_hash,
        app_session_version,
        action,
        operation,
        otp_code,
        record_json,
        created_at_ms,
        expires_at_ms
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        record.challengeId,
        record.challengeSubjectId,
        record.walletId,
        record.orgId || '',
        EMAIL_OTP_CHANNEL,
        record.sessionHash,
        record.appSessionVersion,
        record.action,
        record.operation,
        record.otpCode,
        JSON.stringify(record),
        record.createdAtMs,
        record.expiresAtMs,
      ],
    ).run();
  }

  private async updateEmailOtpChallengeAttemptCount(
    record: EmailOtpChallengeRecord,
    attemptCount: number,
  ): Promise<void> {
    const next = emailOtpChallengeWithAttemptCount(record, attemptCount);
    await this.scopePrepare(
      `UPDATE signer_email_otp_challenges
          SET record_json = ?,
              otp_code = ?,
              expires_at_ms = ?
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND challenge_id = ?`,
      [JSON.stringify(next), next.otpCode, next.expiresAtMs, next.challengeId],
    ).run();
  }

  private async deleteEmailOtpChallenge(challengeId: string): Promise<void> {
    await this.scopePrepare(
      `DELETE FROM signer_email_otp_challenges
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND challenge_id = ?`,
      [challengeId],
    ).run();
    this.emailOtpMemoryOutbox.delete(challengeId);
  }

  private async consumeEmailOtpChallenge(
    challengeId: string,
  ): Promise<EmailOtpChallengeRecord | null> {
    const row = await this.scopePrepare(
      `DELETE FROM signer_email_otp_challenges
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND challenge_id = ?
      RETURNING record_json, expires_at_ms`,
      [challengeId],
    ).first<D1EmailOtpChallengeRow>();
    this.emailOtpMemoryOutbox.delete(challengeId);
    return parseEmailOtpChallengeRow(row);
  }

  private async putEmailOtpUnlockChallenge(record: EmailOtpUnlockChallengeRecord): Promise<void> {
    await this.scopePrepare(
      `INSERT INTO signer_email_otp_unlock_challenges (
        namespace,
        org_id,
        project_id,
        env_id,
        challenge_id,
        wallet_id,
        user_id,
        record_org_id,
        record_json,
        created_at_ms,
        expires_at_ms
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        record.challengeId,
        record.walletId,
        record.userId,
        record.orgId || '',
        JSON.stringify(record),
        record.createdAtMs,
        record.expiresAtMs,
      ],
    ).run();
  }

  private async consumeEmailOtpUnlockChallenge(
    challengeId: string,
  ): Promise<EmailOtpUnlockChallengeRecord | null> {
    const row = await this.scopePrepare(
      `DELETE FROM signer_email_otp_unlock_challenges
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND challenge_id = ?
      RETURNING record_json, expires_at_ms`,
      [challengeId],
    ).first<D1EmailOtpUnlockChallengeRow>();
    return parseEmailOtpUnlockChallengeRow(row);
  }

  private async putEmailOtpGrant(record: EmailOtpGrantRecord): Promise<void> {
    await this.scopePrepare(
      `INSERT INTO signer_email_otp_grants (
        namespace,
        org_id,
        project_id,
        env_id,
        grant_token,
        user_id,
        wallet_id,
        record_org_id,
        challenge_id,
        action,
        record_json,
        issued_at_ms,
        expires_at_ms
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        record.grantToken,
        record.userId,
        record.walletId,
        record.orgId || '',
        record.challengeId,
        record.action,
        JSON.stringify(record),
        record.issuedAtMs,
        record.expiresAtMs,
      ],
    ).run();
  }

  private async deliverEmailOtpCode(record: EmailOtpChallengeRecord): Promise<
    | { ok: true; deliveryMode: EmailOtpDeliveryMode; emailHint: string }
    | { ok: false; code: string; message: string }
  > {
    if (this.options.emailOtp.production && this.options.emailOtp.deliveryMode !== 'email_provider') {
      return {
        ok: false,
        code: 'email_otp_delivery_not_allowed',
        message: `Email OTP delivery mode ${this.options.emailOtp.deliveryMode} is disabled in production`,
      };
    }
    const emailHint = maskEmail(record.email);
    if (this.options.emailOtp.deliveryMode === 'email_provider') {
      const provider = this.options.emailOtp.deliveryProvider;
      if (!provider) {
        return {
          ok: false,
          code: 'email_otp_delivery_not_configured',
          message: 'Email OTP email_provider delivery is not configured',
        };
      }
      const delivered = await provider.deliver({
        challengeId: record.challengeId,
        walletId: record.walletId,
        userId: record.challengeSubjectId,
        ...(record.orgId ? { orgId: record.orgId } : {}),
        email: record.email,
        emailHint,
        otpCode: record.otpCode,
        otpChannel: EMAIL_OTP_CHANNEL,
        action: record.action,
        operation: record.operation,
        expiresAtMs: record.expiresAtMs,
      });
      if (!delivered.ok) return delivered;
      return { ok: true, deliveryMode: 'email_provider', emailHint };
    }
    if (this.options.emailOtp.deliveryMode === 'memory') {
      this.emailOtpMemoryOutbox.set(record.challengeId, {
        walletId: record.walletId,
        userId: record.challengeSubjectId,
        otpChannel: EMAIL_OTP_CHANNEL,
        emailHint,
        otpCode: record.otpCode,
        expiresAtMs: record.expiresAtMs,
      });
    }
    console.warn('[email-otp] development OTP code', {
      challengeId: record.challengeId,
      walletId: record.walletId,
      userId: record.challengeSubjectId,
      otpChannel: EMAIL_OTP_CHANNEL,
      action: record.action,
      operation: record.operation,
      deliveryMode: this.options.emailOtp.deliveryMode,
      emailHint,
      devOtpCode: record.otpCode,
      expiresAtMs: record.expiresAtMs,
    });
    return { ok: true, deliveryMode: this.options.emailOtp.deliveryMode, emailHint };
  }

  private async consumeEmailOtpRateLimit(input: {
    readonly scope: EmailOtpRateLimitScope;
    readonly action?: string;
    readonly userId?: string;
    readonly walletId?: string;
    readonly providerSubject?: string;
    readonly orgId?: string;
    readonly clientIp?: string;
  }): Promise<
    | { ok: true }
    | {
        ok: false;
        code: 'rate_limited';
        message: string;
        retryAfterMs?: number;
        resetAtMs?: number;
      }
  > {
    const policy = this.options.emailOtp.rateLimits[input.scope];
    const keys = emailOtpRateLimitKeys({ ...input, policy });
    for (const key of keys) {
      const consumed = await this.consumeEmailOtpRateLimitKey({
        key,
        policy,
        nowMs: Date.now(),
      });
      if (!consumed.ok) return consumed;
    }
    return { ok: true };
  }

  private async consumeEmailOtpRateLimitKey(input: {
    readonly key: string;
    readonly policy: EmailOtpRateLimitPolicy;
    readonly nowMs: number;
  }): Promise<
    | { ok: true }
    | {
        ok: false;
        code: 'rate_limited';
        message: string;
        retryAfterMs?: number;
        resetAtMs?: number;
      }
  > {
    const resetAtMs = input.nowMs + input.policy.windowMs;
    const row = await this.scopePrepare(
      `INSERT INTO signer_email_otp_rate_limits (
        namespace,
        org_id,
        project_id,
        env_id,
        rate_key,
        consumed_count,
        reset_at_ms,
        updated_at_ms
      )
      VALUES (?, ?, ?, ?, ?, 1, ?, ?)
      ON CONFLICT (namespace, org_id, project_id, env_id, rate_key)
      DO UPDATE SET
        consumed_count = CASE
          WHEN signer_email_otp_rate_limits.reset_at_ms <= ?
            THEN 1
          ELSE signer_email_otp_rate_limits.consumed_count + 1
        END,
        reset_at_ms = CASE
          WHEN signer_email_otp_rate_limits.reset_at_ms <= ?
            THEN ?
          ELSE signer_email_otp_rate_limits.reset_at_ms
        END,
        updated_at_ms = ?
      WHERE signer_email_otp_rate_limits.reset_at_ms <= ?
         OR signer_email_otp_rate_limits.consumed_count < ?
      RETURNING consumed_count, reset_at_ms`,
      [
        input.key,
        resetAtMs,
        input.nowMs,
        input.nowMs,
        input.nowMs,
        resetAtMs,
        input.nowMs,
        input.nowMs,
        input.policy.limit,
      ],
    ).first<D1EmailOtpRateLimitRow>();
    if (row) return { ok: true };
    const existing = await this.scopePrepare(
      `SELECT consumed_count, reset_at_ms
         FROM signer_email_otp_rate_limits
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND rate_key = ?
        LIMIT 1`,
      [input.key],
    ).first<D1EmailOtpRateLimitRow>();
    return emailOtpRateLimitExceeded(existing);
  }

  private async listEmailOtpRecoveryEscrowsForEnrollment(
    enrollment: EmailOtpWalletEnrollmentRecord,
  ): Promise<EmailOtpRecoveryWrappedEnrollmentEscrowRecord[]> {
    const result = await this.scopePrepare(
      `SELECT record_json, updated_at_ms
         FROM signer_email_otp_recovery_wrapped_enrollment_escrows
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND wallet_id = ?
        ORDER BY issued_at_ms ASC, recovery_key_id ASC`,
      [enrollment.walletId],
    ).all<D1EmailOtpRecoveryEscrowRow>();
    const records: EmailOtpRecoveryWrappedEnrollmentEscrowRecord[] = [];
    for (const row of result.results || []) {
      const escrow = parseEmailOtpRecoveryEscrowRow(row);
      if (!escrow) continue;
      if (!emailOtpRecoveryEscrowMatchesEnrollment({ escrow, enrollment })) continue;
      records.push(escrow);
    }
    return records;
  }

  private async readEmailOtpRecoveryEscrow(input: {
    readonly walletId: string;
    readonly recoveryKeyId: string;
  }): Promise<EmailOtpRecoveryWrappedEnrollmentEscrowRecord | null> {
    const row = await this.scopePrepare(
      `SELECT record_json, updated_at_ms
         FROM signer_email_otp_recovery_wrapped_enrollment_escrows
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND wallet_id = ?
          AND recovery_key_id = ?
        LIMIT 1`,
      [input.walletId, input.recoveryKeyId],
    ).first<D1EmailOtpRecoveryEscrowRow>();
    return parseEmailOtpRecoveryEscrowRow(row);
  }

  private async consumeEmailOtpRecoveryEscrow(input: {
    readonly record: Extract<
      EmailOtpRecoveryWrappedEnrollmentEscrowRecord,
      { readonly recoveryKeyStatus: 'active' }
    >;
    readonly consumedAtMs: number;
  }): Promise<EmailOtpRecoveryWrappedEnrollmentEscrowRecord | null> {
    const consumedRecord = consumedEmailOtpRecoveryEscrowRecord(input);
    const row = await this.options.database
      .prepare(
        `UPDATE signer_email_otp_recovery_wrapped_enrollment_escrows
            SET recovery_key_status = ?,
                record_json = ?,
                updated_at_ms = ?
          WHERE namespace = ?
            AND org_id = ?
            AND project_id = ?
            AND env_id = ?
            AND wallet_id = ?
            AND recovery_key_id = ?
            AND recovery_key_status = 'active'
        RETURNING record_json, updated_at_ms`,
      )
      .bind(
        consumedRecord.recoveryKeyStatus,
        JSON.stringify(consumedRecord),
        consumedRecord.updatedAtMs,
        this.options.namespace,
        this.options.orgId,
        this.options.projectId,
        this.options.envId,
        consumedRecord.walletId,
        consumedRecord.recoveryKeyId,
      )
      .first<D1EmailOtpRecoveryEscrowRow>();
    return parseEmailOtpRecoveryEscrowRow(row);
  }

  private async putEmailOtpRecoveryEscrows(
    records: readonly EmailOtpRecoveryWrappedEnrollmentEscrowRecord[],
  ): Promise<void> {
    if (records.length === 0) return;
    const statements: D1PreparedStatementLike[] = [];
    for (const record of records) {
      statements.push(this.putEmailOtpRecoveryEscrowStatement(record));
    }
    await this.options.database.batch(statements);
  }

  private putEmailOtpRecoveryEscrowStatement(
    record: EmailOtpRecoveryWrappedEnrollmentEscrowRecord,
  ): D1PreparedStatementLike {
    return this.scopePrepare(
      `INSERT INTO signer_email_otp_recovery_wrapped_enrollment_escrows (
        namespace,
        org_id,
        project_id,
        env_id,
        wallet_id,
        recovery_key_id,
        recovery_key_status,
        record_json,
        issued_at_ms,
        updated_at_ms
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT (namespace, org_id, project_id, env_id, wallet_id, recovery_key_id)
      DO UPDATE SET
        recovery_key_status = EXCLUDED.recovery_key_status,
        record_json = EXCLUDED.record_json,
        issued_at_ms = EXCLUDED.issued_at_ms,
        updated_at_ms = EXCLUDED.updated_at_ms`,
      [
        record.walletId,
        record.recoveryKeyId,
        record.recoveryKeyStatus,
        JSON.stringify(record),
        record.issuedAtMs,
        record.updatedAtMs,
      ],
    );
  }

  private async consumeEmailOtpGrantRecord(
    loginGrant: string,
  ): Promise<EmailOtpGrantRecord | null> {
    const row = await this.scopePrepare(
      `DELETE FROM signer_email_otp_grants
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND grant_token = ?
      RETURNING record_json, expires_at_ms`,
      [loginGrant],
    ).first<D1EmailOtpGrantRow>();
    return parseEmailOtpGrantRow(row);
  }

  private async readEmailOtpGrantRecord(grantToken: string): Promise<EmailOtpGrantRecord | null> {
    const row = await this.scopePrepare(
      `SELECT record_json, expires_at_ms
         FROM signer_email_otp_grants
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND grant_token = ?
        LIMIT 1`,
      [grantToken],
    ).first<D1EmailOtpGrantRow>();
    return parseEmailOtpGrantRow(row);
  }

  private async deleteEmailOtpGrantRecord(grantToken: string): Promise<void> {
    await this.scopePrepare(
      `DELETE FROM signer_email_otp_grants
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND grant_token = ?`,
      [grantToken],
    ).run();
  }

  private async readRecoverySessionRecord(
    sessionId: string,
  ): Promise<RecoverySessionRecord | null> {
    const row = await this.scopePrepare(
      `SELECT record_json
         FROM signer_recovery_sessions
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND session_id = ?
        LIMIT 1`,
      [sessionId],
    ).first<D1RecoverySessionRow>();
    const record = parseRecoverySessionRecord(row?.record_json);
    if (!record) return null;
    if (Date.now() > record.expiresAtMs) return null;
    return record;
  }

  private async putRecoverySessionRecord(record: RecoverySessionRecord): Promise<void> {
    await this.scopePrepare(
      `INSERT INTO signer_recovery_sessions (
        namespace,
        org_id,
        project_id,
        env_id,
        session_id,
        near_account_id,
        record_json,
        expires_at_ms,
        created_at_ms,
        updated_at_ms
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT (namespace, org_id, project_id, env_id, session_id)
      DO UPDATE SET
        near_account_id = EXCLUDED.near_account_id,
        record_json = EXCLUDED.record_json,
        expires_at_ms = EXCLUDED.expires_at_ms,
        updated_at_ms = EXCLUDED.updated_at_ms`,
      [
        record.sessionId,
        record.nearAccountId,
        JSON.stringify(record),
        record.expiresAtMs,
        record.createdAtMs,
        record.updatedAtMs,
      ],
    ).run();
  }

  private async readRecoveryExecutionRecord(input: {
    readonly sessionId: string;
    readonly chainIdKey: string;
    readonly accountAddress: string;
    readonly action: string;
  }): Promise<RecoveryExecutionRecord | null> {
    const row = await this.scopePrepare(
      `SELECT record_json
         FROM signer_recovery_executions
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND session_id = ?
          AND chain_id_key = ?
          AND account_address = ?
          AND action = ?
        LIMIT 1`,
      [input.sessionId, input.chainIdKey, input.accountAddress, input.action],
    ).first<D1RecoveryExecutionRow>();
    return parseRecoveryExecutionRecord(row?.record_json);
  }

  private async putRecoveryExecutionRecord(record: RecoveryExecutionRecord): Promise<void> {
    await this.scopePrepare(
      `INSERT INTO signer_recovery_executions (
        namespace,
        org_id,
        project_id,
        env_id,
        session_id,
        chain_id_key,
        account_address,
        action,
        status,
        record_json,
        created_at_ms,
        updated_at_ms
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT (
        namespace,
        org_id,
        project_id,
        env_id,
        session_id,
        chain_id_key,
        account_address,
        action
      )
      DO UPDATE SET
        status = EXCLUDED.status,
        record_json = EXCLUDED.record_json,
        updated_at_ms = EXCLUDED.updated_at_ms`,
      [
        record.sessionId,
        record.chainIdKey,
        record.accountAddress,
        record.action,
        record.status,
        JSON.stringify(record),
        record.createdAtMs,
        record.updatedAtMs,
      ],
    ).run();
  }

  private async readAppSessionVersion(userId: string): Promise<string | null> {
    const row = await this.scopePrepare(
      `SELECT session_version
         FROM signer_app_session_versions
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND user_id = ?
        LIMIT 1`,
      [userId],
    ).first<D1SessionRow>();
    return toOptionalTrimmedString(row?.session_version) || null;
  }

  private async readWebAuthnAuthenticatorRows(userId: string): Promise<D1AuthenticatorRow[]> {
    const result = await this.scopePrepare(
      `SELECT credential_id_b64u, created_at_ms, updated_at_ms
         FROM signer_webauthn_authenticators
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND user_id = ?
        ORDER BY created_at_ms ASC`,
      [userId],
    ).all<D1AuthenticatorRow>();
    return [...(result.results || [])];
  }

  private async readWebAuthnBindingRows(input: {
    readonly userId: string;
    readonly rpId?: string;
  }): Promise<D1RecordJsonRow[]> {
    const rpId = toOptionalTrimmedString(input.rpId);
    const sql = rpId
      ? `SELECT record_json
           FROM signer_webauthn_credential_bindings
          WHERE namespace = ?
            AND org_id = ?
            AND project_id = ?
            AND env_id = ?
            AND user_id = ?
            AND rp_id = ?
          ORDER BY signer_slot ASC`
      : `SELECT record_json
           FROM signer_webauthn_credential_bindings
          WHERE namespace = ?
            AND org_id = ?
            AND project_id = ?
            AND env_id = ?
            AND user_id = ?
          ORDER BY signer_slot ASC`;
    const values = rpId ? [input.userId, rpId] : [input.userId];
    const result = await this.scopePrepare(sql, values).all<D1RecordJsonRow>();
    return [...(result.results || [])];
  }
}

function compareAuthenticatorSlots(
  left: NonNullable<ListWebAuthnAuthenticatorsResult['authenticators']>[number],
  right: NonNullable<ListWebAuthnAuthenticatorsResult['authenticators']>[number],
): number {
  return (Number(left.signerSlot || 0) || 0) - (Number(right.signerSlot || 0) || 0);
}

function identityAlreadyLinked(): LinkIdentityResult {
  return {
    ok: false,
    code: 'already_linked',
    message: 'Subject is already linked to a different user',
  };
}

function identityMoveDisallowed(): LinkIdentityResult {
  return {
    ok: false,
    code: 'already_linked',
    message: 'Subject is linked to a different user with other identities; merge is not allowed',
  };
}

function emailOtpEnrollmentTenantMismatch(): ReadEmailOtpEnrollmentResult {
  return {
    ok: false,
    code: 'tenant_scope_mismatch',
    message: 'Email OTP enrollment does not match the requested orgId',
  };
}

function emailOtpRecoveryNotEnrolledStatus(walletId: string): GetEmailOtpRecoveryCodeStatusResult {
  return {
    ok: true,
    status: 'not_enrolled',
    walletId,
    enrollmentId: '',
    enrollmentSealKeyVersion: '',
    expectedRecoveryCodeCount: EMAIL_OTP_RECOVERY_KEY_COUNT,
    activeRecoveryCodeCount: 0,
    consumedRecoveryCodeCount: 0,
    revokedRecoveryCodeCount: 0,
    totalRecoveryCodeCount: 0,
    issuedAtMs: null,
  };
}

function emailOtpGrantInvalidOrExpired(): ConsumeEmailOtpGrantResult {
  return {
    ok: false,
    code: 'login_grant_invalid_or_expired',
    message: 'Login grant is invalid or expired',
  };
}

function emailOtpRecoveryConsumeGrantInvalidOrExpired(): {
  ok: false;
  code: string;
  message: string;
} {
  return {
    ok: false,
    code: 'recovery_consume_grant_invalid_or_expired',
    message: 'Recovery consume grant is invalid or expired',
  };
}

function emailOtpRecoveryGrantBindingMismatch(): {
  ok: false;
  code: string;
  message: string;
} {
  return {
    ok: false,
    code: 'recovery_grant_binding_mismatch',
    message: 'Recovery grant is not valid for the current app session',
  };
}

function consumedEmailOtpRecoveryEscrowRecord(input: {
  readonly record: Extract<
    EmailOtpRecoveryWrappedEnrollmentEscrowRecord,
    { readonly recoveryKeyStatus: 'active' }
  >;
  readonly consumedAtMs: number;
}): EmailOtpRecoveryWrappedEnrollmentEscrowRecord {
  return {
    version: input.record.version,
    alg: input.record.alg,
    secretKind: input.record.secretKind,
    escrowKind: input.record.escrowKind,
    walletId: input.record.walletId,
    userId: input.record.userId,
    authSubjectId: input.record.authSubjectId,
    authMethod: input.record.authMethod,
    enrollmentId: input.record.enrollmentId,
    enrollmentVersion: input.record.enrollmentVersion,
    enrollmentSealKeyVersion: input.record.enrollmentSealKeyVersion,
    signingRootId: input.record.signingRootId,
    signingRootVersion: input.record.signingRootVersion,
    recoveryKeyId: input.record.recoveryKeyId,
    ...(input.record.recoveryKeyLabel ? { recoveryKeyLabel: input.record.recoveryKeyLabel } : {}),
    recoveryKeyStatus: 'consumed',
    nonceB64u: input.record.nonceB64u,
    wrappedDeviceEnrollmentEscrowB64u: input.record.wrappedDeviceEnrollmentEscrowB64u,
    aadHashB64u: input.record.aadHashB64u,
    issuedAtMs: input.record.issuedAtMs,
    updatedAtMs: input.consumedAtMs,
    consumedAtMs: input.consumedAtMs,
  };
}

function emailOtpAuthStateRecord(input: {
  readonly enrollment: EmailOtpWalletEnrollmentRecord;
  readonly existing: EmailOtpAuthStateRecord | null;
  readonly updatedAtMs: number;
  readonly patch: EmailOtpAuthStatePatch;
}): EmailOtpAuthStateRecord {
  const otpFailureCount = patchedNonNegativeAuthStateValue(
    input.existing?.otpFailureCount,
    input.patch.otpFailureCount,
  );
  const lastOtpFailureAtMs = patchedPositiveAuthStateValue(
    input.existing?.lastOtpFailureAtMs,
    input.patch.lastOtpFailureAtMs,
  );
  const otpLockedUntilMs = patchedPositiveAuthStateValue(
    input.existing?.otpLockedUntilMs,
    input.patch.otpLockedUntilMs,
  );
  const lastEmailOtpLoginAtMs = patchedPositiveAuthStateValue(
    input.existing?.lastEmailOtpLoginAtMs,
    input.patch.lastEmailOtpLoginAtMs,
  );
  const lastStrongAuthAtMs = patchedPositiveAuthStateValue(
    input.existing?.lastStrongAuthAtMs,
    input.patch.lastStrongAuthAtMs,
  );
  return {
    version: 'email_otp_auth_state_v1',
    walletId: input.enrollment.walletId,
    providerUserId: input.enrollment.providerUserId,
    orgId: input.enrollment.orgId,
    createdAtMs: input.existing?.createdAtMs ?? input.updatedAtMs,
    updatedAtMs: input.updatedAtMs,
    ...(otpFailureCount != null ? { otpFailureCount } : {}),
    ...(lastOtpFailureAtMs != null ? { lastOtpFailureAtMs } : {}),
    ...(otpLockedUntilMs != null ? { otpLockedUntilMs } : {}),
    ...(lastEmailOtpLoginAtMs != null ? { lastEmailOtpLoginAtMs } : {}),
    ...(lastStrongAuthAtMs != null ? { lastStrongAuthAtMs } : {}),
  };
}

function patchedPositiveAuthStateValue(
  current: number | undefined,
  patch: number | null | undefined,
): number | undefined {
  if (patch === null) return undefined;
  if (patch === undefined) return current;
  return patch > 0 ? Math.floor(patch) : undefined;
}

function patchedNonNegativeAuthStateValue(
  current: number | undefined,
  patch: number | null | undefined,
): number | undefined {
  if (patch === null) return undefined;
  if (patch === undefined) return current;
  return patch >= 0 ? Math.floor(patch) : undefined;
}

export function createCloudflareD1RelayAuthService(
  input: CloudflareD1RelayAuthServiceOptions,
): CloudflareRelayAuthService {
  const service = createDisabledCloudflareRelayAuthService({
    relayerAccount: input.relayerAccount,
    relayerPublicKey: input.relayerPublicKey,
  });
  const metadata = new CloudflareD1RelayAuthMetadataService(input);
  service.listIdentities = metadata.listIdentities.bind(metadata);
  service.linkIdentity = metadata.linkIdentity.bind(metadata);
  service.unlinkIdentity = metadata.unlinkIdentity.bind(metadata);
  service.resolveOidcWalletId = metadata.resolveOidcWalletId.bind(metadata);
  service.consumeGoogleEmailOtpRegistrationAttemptRateLimit =
    metadata.consumeGoogleEmailOtpRegistrationAttemptRateLimit.bind(metadata);
  service.resolveGoogleEmailOtpSession = metadata.resolveGoogleEmailOtpSession.bind(metadata);
  service.readEmailOtpEnrollment = metadata.readEmailOtpEnrollment.bind(metadata);
  service.readActiveEmailOtpEnrollment = metadata.readActiveEmailOtpEnrollment.bind(metadata);
  service.isEmailOtpStrongAuthRequired = metadata.isEmailOtpStrongAuthRequired.bind(metadata);
  service.markEmailOtpStrongAuthSatisfied = metadata.markEmailOtpStrongAuthSatisfied.bind(metadata);
  service.getEmailOtpRecoveryCodeStatus =
    metadata.getEmailOtpRecoveryCodeStatus.bind(metadata);
  service.createEmailOtpChallenge = metadata.createEmailOtpChallenge.bind(metadata);
  service.verifyEmailOtpChallenge = metadata.verifyEmailOtpChallenge.bind(metadata);
  service.createEmailOtpDeviceRecoveryChallenge =
    metadata.createEmailOtpDeviceRecoveryChallenge.bind(metadata);
  service.verifyEmailOtpDeviceRecoveryChallenge =
    metadata.verifyEmailOtpDeviceRecoveryChallenge.bind(metadata);
  service.readEmailOtpOutboxEntry = metadata.readEmailOtpOutboxEntry.bind(metadata);
  service.createEmailOtpUnlockChallenge = metadata.createEmailOtpUnlockChallenge.bind(metadata);
  service.verifyEmailOtpUnlockProof = metadata.verifyEmailOtpUnlockProof.bind(metadata);
  service.consumeEmailOtpGrant = metadata.consumeEmailOtpGrant.bind(metadata);
  service.consumeEmailOtpRecoveryKey = metadata.consumeEmailOtpRecoveryKey.bind(metadata);
  service.rotateEmailOtpRecoveryKeys = metadata.rotateEmailOtpRecoveryKeys.bind(metadata);
  service.recordEmailOtpRecoveryKeyAttemptFailure =
    metadata.recordEmailOtpRecoveryKeyAttemptFailure.bind(metadata);
  service.getRecoverySession = metadata.getRecoverySession.bind(metadata);
  service.updateRecoverySessionStatus = metadata.updateRecoverySessionStatus.bind(metadata);
  service.recordRecoveryExecution = metadata.recordRecoveryExecution.bind(metadata);
  service.getOrCreateAppSessionVersion = metadata.getOrCreateAppSessionVersion.bind(metadata);
  service.rotateAppSessionVersion = metadata.rotateAppSessionVersion.bind(metadata);
  service.validateAppSessionVersion = metadata.validateAppSessionVersion.bind(metadata);
  service.listWebAuthnAuthenticatorsForUser =
    metadata.listWebAuthnAuthenticatorsForUser.bind(metadata);
  service.listNearPublicKeysForUser = metadata.listNearPublicKeysForUser.bind(metadata);
  service.getGoogleOidcPublicConfig = metadata.getGoogleOidcPublicConfig.bind(metadata);
  service.verifyGoogleLogin = metadata.verifyGoogleLogin.bind(metadata);
  return service;
}
