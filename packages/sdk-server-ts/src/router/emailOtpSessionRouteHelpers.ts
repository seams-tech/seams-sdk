import { alphabetizeStringify, sha256BytesUtf8 } from '@shared/utils/digests';
import { base64UrlEncode } from '@shared/utils/encoders';
import { toOptionalRecordString, toOptionalTrimmedString } from '@shared/utils/validation';
import { EMAIL_OTP_CHANNEL, type WalletEmailOtpChannel } from '@shared/utils/emailOtpDomain';

export type OidcAccountMode = 'register' | 'login';
const EMAIL_OTP_RESEND_RETRY_AFTER_MS = 10_000;

export type EmailOtpFailureAuditInput = {
  source:
    | 'registration_finalize'
    | 'login_challenge'
    | 'login_verify'
    | 'unlock_verify'
    | 'signing_session_challenge'
    | 'signing_session_verify';
  code: string;
  message: string;
  challengeId?: string;
  otpChannel?: WalletEmailOtpChannel;
  operation?: string;
  lockedUntilMs?: number;
};

export type EmailOtpWebhookEventDescriptor = {
  eventType: string;
  eventId?: string;
  payload: Record<string, unknown>;
};

export type EmailOtpRouteValidationError = {
  ok: false;
  status: number;
  body: Record<string, unknown>;
};

export type EmailOtpRouteValidationResult<T> = ({ ok: true } & T) | EmailOtpRouteValidationError;

function emailOtpRouteValidationError(
  status: number,
  code: string,
  message: string,
): EmailOtpRouteValidationError {
  return {
    ok: false,
    status,
    body: { ok: false, code, message },
  };
}

export function emailOtpStatusCode(code: string | undefined): number {
  if (code === 'internal') return 500;
  if (code === 'not_configured') return 503;
  if (code === 'not_found') return 404;
  if (code === 'rate_limited') return 429;
  if (code === 'stronger_auth_required') return 403;
  if (
    code === 'reenrollment_required' ||
    code === 'registration_attempt_missing' ||
    code === 'registration_attempt_expired'
  ) {
    return 409;
  }
  if (
    code === 'challenge_id_mismatch' ||
    code === 'challenge_purpose_mismatch' ||
    code === 'challenge_subject_mismatch' ||
    code === 'challenge_email_mismatch' ||
    code === 'challenge_wallet_mismatch' ||
    code === 'challenge_session_mismatch' ||
    code === 'challenge_org_mismatch' ||
    code === 'challenge_channel_mismatch' ||
    code === 'registration_reroll_disallowed' ||
    code === 'challenge_expired_or_invalid' ||
    code === 'invalid_otp'
  ) {
    return 401;
  }
  return 400;
}

export function emailOtpResultStatus(result: { ok: boolean; code?: string }): number {
  return result.ok ? 200 : emailOtpStatusCode(result.code);
}

export function emailOtpInternalErrorBody(error: unknown): {
  ok: false;
  code: 'internal';
  message: string;
} {
  return {
    ok: false,
    code: 'internal',
    message: error instanceof Error ? error.message || 'Internal error' : 'Internal error',
  };
}

export function emailOtpFailureAuditPayload(
  input: EmailOtpFailureAuditInput,
): Record<string, unknown> {
  return {
    source: input.source,
    code: input.code,
    message: input.message,
    ...(input.challengeId ? { challengeId: input.challengeId } : {}),
    ...(input.otpChannel ? { otpChannel: input.otpChannel } : {}),
    ...(input.operation ? { operation: input.operation } : {}),
    ...(typeof input.lockedUntilMs === 'number' ? { lockedUntilMs: input.lockedUntilMs } : {}),
  };
}

export function shouldEmitEmailOtpLockedWebhook(code: string): boolean {
  return code === 'otp_locked_out' || code === 'otp_attempts_exhausted';
}

export function emailOtpFailureWebhookEventDescriptors(
  input: EmailOtpFailureAuditInput,
): EmailOtpWebhookEventDescriptor[] {
  const payload = emailOtpFailureAuditPayload(input);
  const event = {
    eventType: 'wallet.email_otp.failed',
    ...(input.challengeId ? { eventId: input.challengeId } : {}),
    payload,
  };
  if (!shouldEmitEmailOtpLockedWebhook(input.code)) return [event];
  return [
    event,
    {
      eventType: 'wallet.email_otp.locked',
      ...(input.challengeId ? { eventId: input.challengeId } : {}),
      payload,
    },
  ];
}

export function emailOtpLoggedInWebhookEventDescriptor(input: {
  challengeId: string;
  otpChannel: WalletEmailOtpChannel;
  unlockBackend: string;
}): EmailOtpWebhookEventDescriptor {
  return {
    eventType: 'wallet.email_otp.logged_in',
    eventId: input.challengeId,
    payload: {
      otpChannel: input.otpChannel,
      unlockBackend: input.unlockBackend,
      challengeId: input.challengeId,
    },
  };
}

export function emailOtpEnrolledWebhookEventDescriptor(input: {
  challengeId: string;
  otpChannel: WalletEmailOtpChannel;
  enrollmentSealKeyVersion: string;
  unlockKeyVersion?: string;
}): EmailOtpWebhookEventDescriptor {
  return {
    eventType: 'wallet.email_otp.enrolled',
    eventId: input.challengeId,
    payload: {
      otpChannel: input.otpChannel,
      enrollmentSealKeyVersion: input.enrollmentSealKeyVersion,
      unlockKeyVersion: input.unlockKeyVersion,
    },
  };
}

export function validateEmailOtpJsonObjectBody(
  body: unknown,
): EmailOtpRouteValidationResult<{ body: Record<string, unknown> }> {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return emailOtpRouteValidationError(400, 'invalid_body', 'Expected JSON object body');
  }
  return { ok: true, body: body as Record<string, unknown> };
}

export function validateEmailOtpWalletId(input: {
  body: Record<string, unknown>;
  claims: unknown;
  userId: string;
}): EmailOtpRouteValidationResult<{ walletId: string }> {
  const walletId = toOptionalTrimmedString(input.body.walletId) || '';
  if (!walletId) {
    return emailOtpRouteValidationError(400, 'invalid_body', 'walletId is required');
  }
  if (walletId !== getSessionWalletId(input.claims, input.userId)) {
    return emailOtpRouteValidationError(
      403,
      'wallet_identity_mismatch',
      'walletId must match the current app session wallet',
    );
  }
  return { ok: true, walletId };
}

export function validateEmailOtpChannel(
  body: Record<string, unknown>,
): EmailOtpRouteValidationResult<{ otpChannel: WalletEmailOtpChannel }> {
  const otpChannel = toOptionalTrimmedString(body.otpChannel)?.toLowerCase() || '';
  if (otpChannel !== EMAIL_OTP_CHANNEL) {
    return emailOtpRouteValidationError(400, 'invalid_body', 'otpChannel must be email_otp');
  }
  return { ok: true, otpChannel: EMAIL_OTP_CHANNEL };
}

export function validateEmailOtpRequiredString(
  body: Record<string, unknown>,
  field: string,
): EmailOtpRouteValidationResult<{ value: string }> {
  const value = toOptionalTrimmedString(body[field]) || '';
  if (!value) {
    return emailOtpRouteValidationError(400, 'invalid_body', `${field} is required`);
  }
  return { ok: true, value };
}

export function getSessionWalletId(claims: unknown, userId: string): string {
  return toOptionalRecordString(claims, 'walletId') || toOptionalTrimmedString(userId) || '';
}

export function isGoogleOidcEmailOtpSession(claims: unknown): boolean {
  const provider = toOptionalRecordString(claims, 'provider')?.toLowerCase() || '';
  const oidcProvider = toOptionalRecordString(claims, 'oidcProvider')?.toLowerCase() || '';
  const providerSubject = toOptionalRecordString(claims, 'providerSubject')?.toLowerCase() || '';
  return (
    provider === 'oidc' && (oidcProvider === 'google' || providerSubject.startsWith('google:'))
  );
}

export function parseOidcAccountMode(raw: unknown): OidcAccountMode | undefined {
  const value = toOptionalTrimmedString(raw)?.toLowerCase() || '';
  if (value === 'register' || value === 'login') return value;
  return undefined;
}

export function stableEmailOtpSessionBindingClaims(
  claims: Record<string, unknown>,
): Record<string, unknown> {
  const stable: Record<string, unknown> = {};
  for (const key of [
    'kind',
    'sub',
    'appSessionVersion',
    'walletId',
    'orgId',
    'projectId',
    'environmentId',
    'provider',
    'oidcProvider',
    'providerSubject',
    'runtimePolicyScope',
  ]) {
    const value = claims[key];
    if (value !== undefined && value !== null && value !== '') {
      stable[key] = value;
    }
  }
  return stable;
}

export function stableEmailOtpSigningSessionBindingClaims(
  claims: Record<string, unknown>,
): Record<string, unknown> {
  const stable: Record<string, unknown> = {};
  for (const key of [
    'kind',
    'sub',
    'sessionId',
    'signingGrantId',
    'relayerKeyId',
    'rpId',
    'runtimePolicyScope',
    'thresholdExpiresAtMs',
    'participantIds',
  ]) {
    const value = claims[key];
    if (value !== undefined && value !== null && value !== '') {
      stable[key] = value;
    }
  }
  return stable;
}

export async function hashEmailOtpAppSessionClaims(
  claims: Record<string, unknown>,
): Promise<string> {
  const json = alphabetizeStringify(stableEmailOtpSessionBindingClaims(claims));
  return base64UrlEncode(await sha256BytesUtf8(json));
}

export async function hashEmailOtpSigningSessionClaims(
  claims: Record<string, unknown>,
): Promise<string> {
  const json = alphabetizeStringify(stableEmailOtpSigningSessionBindingClaims(claims));
  return base64UrlEncode(await sha256BytesUtf8(json));
}

export function emailOtpChallengeResponseBody(result: {
  ok: boolean;
  challenge?: {
    challengeId: string;
    issuedAtMs: number;
    expiresAtMs: number;
    userId: string;
    walletId: string;
    orgId?: string;
    sessionHash: string;
    appSessionVersion: string;
    otpChannel: string;
    action: string;
    operation: string;
  };
  delivery?: unknown;
  retryAfterMs?: number;
}): Record<string, unknown> {
  if (!result.ok || !result.challenge) return result as unknown as Record<string, unknown>;
  const challenge = result.challenge;
  return {
    ok: true,
    challenge: {
      challengeId: challenge.challengeId,
      issuedAt: new Date(challenge.issuedAtMs).toISOString(),
      issuedAtMs: challenge.issuedAtMs,
      expiresAt: new Date(challenge.expiresAtMs).toISOString(),
      expiresAtMs: challenge.expiresAtMs,
      userId: challenge.userId,
      walletId: challenge.walletId,
      ...(challenge.orgId ? { orgId: challenge.orgId } : {}),
      sessionHash: challenge.sessionHash,
      appSessionVersion: challenge.appSessionVersion,
      otpChannel: challenge.otpChannel,
      action: challenge.action,
      operation: challenge.operation,
    },
    delivery: result.delivery,
    retryAfterMs:
      typeof result.retryAfterMs === 'number'
        ? result.retryAfterMs
        : EMAIL_OTP_RESEND_RETRY_AFTER_MS,
  };
}

export function emailOtpServerSealResponseBody(
  result:
    | { ok: true; ciphertext: string; enrollmentSealKeyVersion: string }
    | ({ ok: false; code: string; message: string } & Record<string, unknown>),
  walletId: string,
): Record<string, unknown> {
  if (!result.ok) return result as unknown as Record<string, unknown>;
  return {
    ok: true,
    walletId,
    ciphertext: result.ciphertext,
    enrollmentSealKeyVersion: result.enrollmentSealKeyVersion,
  };
}

export function emailOtpEnrollmentFinalizeResponseBody(
  result:
    | {
        ok: true;
        walletId: string;
        otpChannel: string;
        enrollment: {
          createdAtMs: number;
          updatedAtMs: number;
          enrollmentSealKeyVersion: string;
          unlockKeyVersion?: string;
        };
      }
    | ({ ok: false; code: string; message: string } & Record<string, unknown>),
): Record<string, unknown> {
  if (!result.ok) return result as unknown as Record<string, unknown>;
  return {
    ok: true,
    walletId: result.walletId,
    otpChannel: result.otpChannel,
    enrollment: {
      createdAt: new Date(result.enrollment.createdAtMs).toISOString(),
      updatedAt: new Date(result.enrollment.updatedAtMs).toISOString(),
      enrollmentSealKeyVersion: result.enrollment.enrollmentSealKeyVersion,
      unlockKeyVersion: result.enrollment.unlockKeyVersion,
    },
  };
}

export function emailOtpLoginVerifyResponseBody(args: {
  result: {
    ok: true;
    challengeId: string;
    loginGrant: string;
    grantExpiresAtMs: number;
    otpChannel: string;
  };
  enrollment: {
    enrollment: {
      enrollmentSealKeyVersion?: unknown;
    };
  };
}): Record<string, unknown> {
  return {
    ok: true,
    challengeId: args.result.challengeId,
    loginGrant: args.result.loginGrant,
    grantExpiresAt: new Date(args.result.grantExpiresAtMs).toISOString(),
    otpChannel: args.result.otpChannel,
    enrollmentSealKeyVersion: args.enrollment.enrollment.enrollmentSealKeyVersion,
  };
}
