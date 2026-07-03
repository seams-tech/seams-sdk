import type {
  EmailOtpChallengeAction,
  EmailOtpChallengeContextInput,
  EmailOtpChallengeOperation,
  EmailOtpChallengeRecord,
  EmailOtpChallengeStore,
  EmailOtpChannel,
  EmailOtpWalletEnrollmentRecord,
} from '../EmailOtpStores';
import {
  EMAIL_OTP_CHANNEL,
  WALLET_EMAIL_OTP_ACTIONS,
  WALLET_EMAIL_OTP_REGISTRATION_OPERATION,
  WALLET_EMAIL_OTP_UNLOCK_OPERATION,
  isWalletEmailOtpLoginOperation,
} from '@shared/utils/emailOtpDomain';
import { base64UrlEncode } from '@shared/utils/encoders';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import { errorMessage } from '@shared/utils/errors';
import { randomNumericCode } from './bytes';
import { maskEmailAddress, type EmailOtpConfig } from './emailOtpConfig';
import type { EmailOtpAuthStateReadResult } from './emailOtpEnrollment';
import type { EmailOtpDeliveryResult, EmailOtpMemoryOutbox } from './emailOtpDelivery';
import type { RateLimitResult } from './rateLimits';

export type EmailOtpChallengeStoreContext = {
  challengeSubjectId: string;
  walletId: string;
  orgId: string;
  otpChannel: EmailOtpChannel;
  sessionHash: string;
  appSessionVersion: string;
  action: EmailOtpChallengeAction;
  operation: EmailOtpChallengeOperation;
  nowMs: number;
};

export type PruneExpiredEmailOtpChallengesInput = {
  challengeStore: EmailOtpChallengeStore;
  memoryOutbox: EmailOtpMemoryOutbox;
  nowMs: number;
};

export type EnforceEmailOtpActiveChallengeLimitInput = {
  challengeStore: EmailOtpChallengeStore;
  memoryOutbox: EmailOtpMemoryOutbox;
  context: EmailOtpChallengeStoreContext;
  maxActiveChallenges: number;
};

export type CreateEmailOtpChallengeWithActionRequest = {
  challengeSubjectId?: unknown;
  walletId?: unknown;
  orgId?: unknown;
  email?: unknown;
  otpChannel?: unknown;
  sessionHash?: unknown;
  appSessionVersion?: unknown;
  clientIp?: unknown;
  operation?: unknown;
  reuseActiveChallenge?: unknown;
  action: EmailOtpChallengeAction;
};

export type CreatedEmailOtpChallenge = {
  challengeId: string;
  issuedAtMs: number;
  expiresAtMs: number;
  challengeSubjectId: string;
  walletId: string;
  orgId: string;
  otpChannel: EmailOtpChannel;
  sessionHash: string;
  appSessionVersion: string;
  action: EmailOtpChallengeAction;
  operation: EmailOtpChallengeOperation;
};

export type CreateEmailOtpChallengeWithActionResult =
  | {
      ok: true;
      challenge: CreatedEmailOtpChallenge;
      delivery: {
        status: 'sent' | 'reused';
        mode: 'email_provider' | 'log' | 'memory';
        emailHint: string;
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

export type EmailOtpChallengeEnrollmentReadResult =
  | { ok: true; enrollment: EmailOtpWalletEnrollmentRecord }
  | { ok: false; code: string; message: string };

export type EmailOtpChallengeRateLimitConsumer = (input: {
  scope: 'challenge';
  action: EmailOtpChallengeAction;
  userId: string;
  walletId: string;
  orgId: string;
  clientIp?: string;
}) => Promise<RateLimitResult>;

export type EmailOtpChallengeDeliverySender = (input: {
  challengeId: string;
  walletId: string;
  userId: string;
  otpChannel: EmailOtpChannel;
  action: EmailOtpChallengeAction;
  operation: EmailOtpChallengeOperation;
  email: string;
  otpCode: string;
  expiresAtMs: number;
}) => Promise<EmailOtpDeliveryResult>;

export type CreateEmailOtpChallengeWithActionInput = {
  request: CreateEmailOtpChallengeWithActionRequest;
  challengeStore: EmailOtpChallengeStore;
  memoryOutbox: EmailOtpMemoryOutbox;
  readActiveEnrollment: (input: {
    walletId: string;
    orgId: string;
  }) => Promise<EmailOtpChallengeEnrollmentReadResult>;
  readEnrollmentAuthState: (
    enrollment: EmailOtpWalletEnrollmentRecord,
  ) => Promise<EmailOtpAuthStateReadResult>;
  consumeRateLimit: EmailOtpChallengeRateLimitConsumer;
  resolveConfig: () => EmailOtpConfig;
  deliverCode: EmailOtpChallengeDeliverySender;
};

function activeChallengeLimit(value: number): number {
  return Math.max(1, Math.floor(value));
}

function emailOtpChallengeOperationFromRequest(input: {
  action: EmailOtpChallengeAction;
  operationRaw: string;
}): EmailOtpChallengeOperation {
  if (input.operationRaw && isWalletEmailOtpLoginOperation(input.operationRaw)) {
    return input.operationRaw;
  }
  if (input.operationRaw === WALLET_EMAIL_OTP_REGISTRATION_OPERATION) {
    return WALLET_EMAIL_OTP_REGISTRATION_OPERATION;
  }
  return input.action === WALLET_EMAIL_OTP_ACTIONS.registration
    ? WALLET_EMAIL_OTP_REGISTRATION_OPERATION
    : WALLET_EMAIL_OTP_UNLOCK_OPERATION;
}

function createdEmailOtpChallengeFromRecord(input: {
  record: EmailOtpChallengeRecord;
  challengeSubjectId: string;
  walletId: string;
  orgId: string;
  sessionHash: string;
  appSessionVersion: string;
  action: EmailOtpChallengeAction;
  operation: EmailOtpChallengeOperation;
}): CreatedEmailOtpChallenge {
  return {
    challengeId: input.record.challengeId,
    issuedAtMs: input.record.createdAtMs,
    expiresAtMs: input.record.expiresAtMs,
    challengeSubjectId: input.challengeSubjectId,
    walletId: input.walletId,
    orgId: input.orgId,
    otpChannel: EMAIL_OTP_CHANNEL,
    sessionHash: input.sessionHash,
    appSessionVersion: input.appSessionVersion,
    action: input.action,
    operation: input.operation,
  };
}

function emailOtpChallengeContextInput(
  context: EmailOtpChallengeStoreContext,
): EmailOtpChallengeContextInput {
  return {
    challengeSubjectId: context.challengeSubjectId,
    walletId: context.walletId,
    orgId: context.orgId,
    otpChannel: context.otpChannel,
    sessionHash: context.sessionHash,
    appSessionVersion: context.appSessionVersion,
    action: context.action,
    operation: context.operation,
    nowMs: context.nowMs,
  };
}

export async function pruneExpiredEmailOtpChallengesWithStore(
  input: PruneExpiredEmailOtpChallengesInput,
): Promise<readonly EmailOtpChallengeRecord[]> {
  const deleted = await input.challengeStore.deleteExpired(input.nowMs);
  for (const record of deleted) {
    input.memoryOutbox.delete(record.challengeId);
  }
  return deleted;
}

export async function enforceEmailOtpActiveChallengeLimitWithStore(
  input: EnforceEmailOtpActiveChallengeLimitInput,
): Promise<void> {
  const maxActive = activeChallengeLimit(input.maxActiveChallenges);
  const context = emailOtpChallengeContextInput(input.context);
  while ((await input.challengeStore.countActiveByContext(context)) >= maxActive) {
    const deleted = await input.challengeStore.deleteOldestActiveByContext(context);
    if (!deleted) break;
    input.memoryOutbox.delete(deleted.challengeId);
  }
}

export async function createEmailOtpChallengeWithAction(
  input: CreateEmailOtpChallengeWithActionInput,
): Promise<CreateEmailOtpChallengeWithActionResult> {
  try {
    const request = input.request;
    const challengeSubjectId = toOptionalTrimmedString(request.challengeSubjectId);
    const walletId = toOptionalTrimmedString(request.walletId);
    const orgId = toOptionalTrimmedString(request.orgId) || '';
    const email = toOptionalTrimmedString(request.email)?.toLowerCase() || '';
    const otpChannel = toOptionalTrimmedString(request.otpChannel);
    const sessionHash = toOptionalTrimmedString(request.sessionHash);
    const appSessionVersion = toOptionalTrimmedString(request.appSessionVersion);
    const clientIp = toOptionalTrimmedString(request.clientIp) || undefined;
    const reuseActiveChallenge = request.reuseActiveChallenge === true;
    const action = request.action;
    const operation = emailOtpChallengeOperationFromRequest({
      action,
      operationRaw: toOptionalTrimmedString(request.operation),
    });

    if (!challengeSubjectId) {
      return { ok: false, code: 'invalid_body', message: 'Missing challengeSubjectId' };
    }
    if (!walletId) return { ok: false, code: 'invalid_body', message: 'Missing walletId' };
    if (!orgId) return { ok: false, code: 'invalid_body', message: 'Missing orgId' };
    if (otpChannel !== EMAIL_OTP_CHANNEL) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'otpChannel must be email_otp',
      };
    }
    if (!sessionHash) return { ok: false, code: 'invalid_body', message: 'Missing sessionHash' };
    if (!appSessionVersion) {
      return { ok: false, code: 'invalid_body', message: 'Missing appSessionVersion' };
    }

    const activeEnrollment =
      action !== WALLET_EMAIL_OTP_ACTIONS.registration
        ? await input.readActiveEnrollment({ walletId, orgId })
        : null;
    if (activeEnrollment && !activeEnrollment.ok) return activeEnrollment;
    const existingEnrollment = activeEnrollment?.ok ? activeEnrollment.enrollment : null;
    const existingAuthStateResult = existingEnrollment
      ? await input.readEnrollmentAuthState(existingEnrollment)
      : { ok: true as const, state: null };
    if (!existingAuthStateResult.ok) return existingAuthStateResult;
    const existingAuthState = existingAuthStateResult.state;
    const challengeEmail =
      action === WALLET_EMAIL_OTP_ACTIONS.registration ? email : existingEnrollment?.verifiedEmail || '';
    if (!challengeEmail) {
      return {
        ok: false,
        code: 'recovery_email_missing',
        message: 'Current app session does not include a recovery email',
      };
    }
    if (existingAuthState?.otpLockedUntilMs && existingAuthState.otpLockedUntilMs > Date.now()) {
      return {
        ok: false,
        code: 'otp_locked_out',
        message: 'Email OTP is temporarily locked for this wallet',
        lockedUntilMs: existingAuthState.otpLockedUntilMs,
      };
    }

    const issuedAtMs = Date.now();
    await pruneExpiredEmailOtpChallengesWithStore({
      challengeStore: input.challengeStore,
      memoryOutbox: input.memoryOutbox,
      nowMs: issuedAtMs,
    });
    if (reuseActiveChallenge) {
      const existingChallenge = await input.challengeStore.findLatestActiveByContext({
        challengeSubjectId,
        walletId,
        orgId,
        otpChannel: EMAIL_OTP_CHANNEL,
        sessionHash,
        appSessionVersion,
        action,
        operation,
        nowMs: issuedAtMs,
      });
      if (existingChallenge) {
        return {
          ok: true,
          challenge: createdEmailOtpChallengeFromRecord({
            record: existingChallenge,
            challengeSubjectId,
            walletId,
            orgId,
            sessionHash,
            appSessionVersion,
            action,
            operation,
          }),
          delivery: {
            status: 'reused',
            mode: 'memory',
            emailHint: maskEmailAddress(existingChallenge.email),
          },
        };
      }
    }

    const rateLimit = await input.consumeRateLimit({
      scope: 'challenge',
      action,
      userId: challengeSubjectId,
      walletId,
      orgId,
      clientIp,
    });
    if (!rateLimit.ok) return rateLimit;
    if (typeof crypto === 'undefined' || typeof crypto.getRandomValues !== 'function') {
      return {
        ok: false,
        code: 'unsupported',
        message: 'crypto.getRandomValues is unavailable in this runtime',
      };
    }

    const otpConfig = input.resolveConfig();
    const expiresAtMs = issuedAtMs + otpConfig.challengeTtlMs;
    const challengeId = base64UrlEncode(crypto.getRandomValues(new Uint8Array(16)));
    const otpCode = randomNumericCode(otpConfig.codeLength);
    await enforceEmailOtpActiveChallengeLimitWithStore({
      challengeStore: input.challengeStore,
      memoryOutbox: input.memoryOutbox,
      context: {
        challengeSubjectId,
        walletId,
        orgId,
        otpChannel: EMAIL_OTP_CHANNEL,
        sessionHash,
        appSessionVersion,
        action,
        operation,
        nowMs: issuedAtMs,
      },
      maxActiveChallenges: otpConfig.maxActiveChallengesPerContext,
    });

    const challengeRecord: EmailOtpChallengeRecord = {
      version: 'email_otp_challenge_v1',
      challengeId,
      challengeSubjectId,
      walletId,
      orgId,
      otpChannel: EMAIL_OTP_CHANNEL,
      email: challengeEmail,
      otpCode,
      sessionHash,
      appSessionVersion,
      action,
      operation,
      createdAtMs: issuedAtMs,
      expiresAtMs,
      attemptCount: 0,
      maxAttempts: otpConfig.maxAttempts,
    };
    await input.challengeStore.put(challengeRecord);
    const persistedChallenge = await input.challengeStore.get(challengeId);
    if (!persistedChallenge) {
      return {
        ok: false,
        code: 'internal',
        message: 'Email OTP challenge could not be persisted',
      };
    }

    const delivery = await input.deliverCode({
      challengeId,
      walletId,
      userId: challengeSubjectId,
      otpChannel: EMAIL_OTP_CHANNEL,
      action,
      operation,
      email: challengeEmail,
      otpCode,
      expiresAtMs,
    });
    if (!delivery.ok) {
      await input.challengeStore.del(challengeId);
      input.memoryOutbox.delete(challengeId);
      return delivery;
    }

    return {
      ok: true,
      challenge: {
        challengeId,
        issuedAtMs,
        expiresAtMs,
        challengeSubjectId,
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
  } catch (e: unknown) {
    return {
      ok: false,
      code: 'internal',
      message: errorMessage(e) || 'Failed to create Email OTP challenge',
    };
  }
}
