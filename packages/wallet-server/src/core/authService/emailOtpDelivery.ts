import type {
  EmailOtpChannel,
  EmailOtpChallengeAction,
  EmailOtpChallengeOperation,
} from '../EmailOtpStores';
import type { NormalizedLogger } from '../logger';
import type { EmailOtpConfig, EmailOtpDeliveryMode } from './emailOtpConfig';
import { maskEmailAddress } from './emailOtpConfig';
import { toOptionalTrimmedString } from '@shared/utils/validation';

export type EmailOtpMemoryOutboxEntry = {
  walletId: string;
  userId: string;
  otpChannel: EmailOtpChannel;
  email: string;
  emailHint: string;
  otpCode: string;
  expiresAtMs: number;
};

export type EmailOtpMemoryOutbox = Map<string, EmailOtpMemoryOutboxEntry>;

export type EmailOtpDeliveryInput = {
  config: EmailOtpConfig;
  production: boolean;
  logger: NormalizedLogger;
  memoryOutbox: EmailOtpMemoryOutbox;
  challengeId: string;
  walletId: string;
  userId: string;
  otpChannel: EmailOtpChannel;
  action: EmailOtpChallengeAction;
  operation: EmailOtpChallengeOperation;
  email: string;
  otpCode: string;
  expiresAtMs: number;
};

export type EmailOtpDeliveryResult =
  | { ok: true; deliveryMode: EmailOtpDeliveryMode; emailHint: string }
  | { ok: false; code: string; message: string; lockedUntilMs?: number };

export type EmailOtpOutboxReadRequest = {
  challengeId?: unknown;
  userId?: unknown;
  walletId?: unknown;
};

export type EmailOtpOutboxReadResult =
  | {
      ok: true;
      challengeId: string;
      walletId: string;
      userId: string;
      otpChannel: EmailOtpChannel;
      emailHint: string;
      otpCode: string;
      expiresAtMs: number;
    }
  | { ok: false; code: string; message: string };

function logDevelopmentOtpCode(input: {
  logger: NormalizedLogger;
  deliveryMode: EmailOtpDeliveryMode;
  challengeId: string;
  walletId: string;
  userId: string;
  otpChannel: EmailOtpChannel;
  action: EmailOtpChallengeAction;
  operation: EmailOtpChallengeOperation;
  emailHint: string;
  otpCode: string;
  expiresAtMs: number;
}): void {
  input.logger.warn('[email-otp] development OTP code', {
    challengeId: input.challengeId,
    walletId: input.walletId,
    userId: input.userId,
    otpChannel: input.otpChannel,
    action: input.action,
    operation: input.operation,
    deliveryMode: input.deliveryMode,
    emailHint: input.emailHint,
    devOtpCode: input.otpCode,
    expiresAtMs: input.expiresAtMs,
  });
}

function storeMemoryOtp(input: {
  memoryOutbox: EmailOtpMemoryOutbox;
  challengeId: string;
  walletId: string;
  userId: string;
  otpChannel: EmailOtpChannel;
  email: string;
  emailHint: string;
  otpCode: string;
  expiresAtMs: number;
}): void {
  input.memoryOutbox.set(input.challengeId, {
    walletId: input.walletId,
    userId: input.userId,
    otpChannel: input.otpChannel,
    email: input.email,
    emailHint: input.emailHint,
    otpCode: input.otpCode,
    expiresAtMs: input.expiresAtMs,
  });
}

function logDevelopmentOtpDelivery(input: EmailOtpDeliveryInput & { emailHint: string }): void {
  logDevelopmentOtpCode({
    logger: input.logger,
    deliveryMode: input.config.deliveryMode,
    challengeId: input.challengeId,
    walletId: input.walletId,
    userId: input.userId,
    otpChannel: input.otpChannel,
    action: input.action,
    operation: input.operation,
    emailHint: input.emailHint,
    otpCode: input.otpCode,
    expiresAtMs: input.expiresAtMs,
  });
}

export async function deliverEmailOtpCode(
  input: EmailOtpDeliveryInput,
): Promise<EmailOtpDeliveryResult> {
  if (input.production && input.config.deliveryMode !== 'email_provider') {
    return {
      ok: false,
      code: 'email_otp_delivery_not_allowed',
      message: `Email OTP delivery mode ${input.config.deliveryMode} is disabled in production`,
    };
  }

  const emailHint = maskEmailAddress(input.email);
  if (input.config.deliveryMode === 'email_provider') {
    return {
      ok: false,
      code: 'not_implemented',
      message: 'Email OTP email_provider delivery is not implemented yet',
    };
  }

  if (input.config.deliveryMode === 'memory') {
    storeMemoryOtp({
      memoryOutbox: input.memoryOutbox,
      challengeId: input.challengeId,
      walletId: input.walletId,
      userId: input.userId,
      otpChannel: input.otpChannel,
      email: input.email,
      emailHint,
      otpCode: input.otpCode,
      expiresAtMs: input.expiresAtMs,
    });
    logDevelopmentOtpDelivery({
      config: input.config,
      production: input.production,
      logger: input.logger,
      memoryOutbox: input.memoryOutbox,
      challengeId: input.challengeId,
      walletId: input.walletId,
      userId: input.userId,
      otpChannel: input.otpChannel,
      action: input.action,
      operation: input.operation,
      email: input.email,
      otpCode: input.otpCode,
      expiresAtMs: input.expiresAtMs,
      emailHint,
    });
    return { ok: true, deliveryMode: 'memory', emailHint };
  }

  logDevelopmentOtpDelivery({
    config: input.config,
    production: input.production,
    logger: input.logger,
    memoryOutbox: input.memoryOutbox,
    challengeId: input.challengeId,
    walletId: input.walletId,
    userId: input.userId,
    otpChannel: input.otpChannel,
    action: input.action,
    operation: input.operation,
    email: input.email,
    otpCode: input.otpCode,
    expiresAtMs: input.expiresAtMs,
    emailHint,
  });
  return { ok: true, deliveryMode: 'log', emailHint };
}

export function readEmailOtpOutboxEntry(input: {
  readonly config: EmailOtpConfig;
  readonly memoryOutbox: EmailOtpMemoryOutbox;
  readonly request: EmailOtpOutboxReadRequest;
  readonly nowMs: number;
}): EmailOtpOutboxReadResult {
  if (!input.config.devOutboxEnabled) {
    return {
      ok: false,
      code: 'not_found',
      message: 'Email OTP dev outbox is not enabled',
    };
  }

  const challengeId = toOptionalTrimmedString(input.request.challengeId);
  const userId = toOptionalTrimmedString(input.request.userId);
  const walletId = toOptionalTrimmedString(input.request.walletId);
  if (!challengeId) return { ok: false, code: 'invalid_body', message: 'Missing challengeId' };
  if (!userId) return { ok: false, code: 'invalid_body', message: 'Missing userId' };
  if (!walletId) return { ok: false, code: 'invalid_body', message: 'Missing walletId' };

  const entry = input.memoryOutbox.get(challengeId);
  if (!entry) {
    return { ok: false, code: 'not_found', message: 'Email OTP outbox entry was not found' };
  }
  if (entry.userId !== userId || entry.walletId !== walletId) {
    return { ok: false, code: 'not_found', message: 'Email OTP outbox entry was not found' };
  }
  if (input.nowMs > entry.expiresAtMs) {
    input.memoryOutbox.delete(challengeId);
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
