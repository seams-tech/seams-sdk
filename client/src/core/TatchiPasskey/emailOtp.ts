import {
  EMAIL_OTP_CHANNEL,
  type WalletEmailOtpChannel,
  type WalletEmailOtpLoginOperation,
} from '@shared/utils/emailOtpDomain';
import { joinNormalizedUrl } from '@shared/utils/normalize';
import {
  requireTrimmedString,
  toOptionalTrimmedNonEmptyString,
} from '@shared/utils/validation';
import type { WorkerOperationContext } from '../signingEngine/workerManager/executeWorkerOperation';
import {
  normalizeThresholdRuntimePolicyScope,
  type ThresholdRuntimePolicyScope,
} from '../signingEngine/threshold/session/sessionPolicy';
import {
  buildEmailOtpRoutePlan,
  resolveEmailOtpAuthLane,
  type EmailOtpRouteFamily,
} from '../signingEngine/emailOtp/authLane';

type FetchLike = typeof fetch;

type JsonObject = Record<string, unknown>;

export class EmailOtpRouteError extends Error {
  readonly code?: string;
  readonly status: number;
  readonly retryAfterMs?: number;
  readonly resetAtMs?: number;

  constructor(input: {
    message: string;
    status: number;
    code?: unknown;
    retryAfterMs?: unknown;
    resetAtMs?: unknown;
  }) {
    super(input.message);
    this.name = 'EmailOtpRouteError';
    const code = readOptionalString(input.code);
    if (code) this.code = code;
    this.status = input.status;
    const retryAfterMs = Number(input.retryAfterMs);
    if (Number.isFinite(retryAfterMs) && retryAfterMs >= 0) {
      this.retryAfterMs = Math.floor(retryAfterMs);
    }
    const resetAtMs = Number(input.resetAtMs);
    if (Number.isFinite(resetAtMs) && resetAtMs >= 0) {
      this.resetAtMs = Math.floor(resetAtMs);
    }
  }
}

export type EmailOtpEnrollmentResult = {
  thresholdEcdsaClientVerifyingShareB64u: string;
  challengeId: string;
  otpChannel: WalletEmailOtpChannel;
  enrollmentSealKeyVersion: string;
  clientUnlockPublicKeyB64u: string;
  unlockKeyVersion: string;
};

export type GoogleEmailOtpSessionExchangeResult = {
  jwt?: string;
  session: {
    userId: string;
    walletId: string;
    email?: string;
    name?: string;
    googleEmailOtpResolution?: {
      mode: 'existing_wallet' | 'register_started';
      registrationAttemptId?: string;
      expiresAt?: string;
    };
    runtimePolicyScope?: ThresholdRuntimePolicyScope;
  };
};

function requireFetchImpl(fetchImpl?: FetchLike): FetchLike {
  const resolved = fetchImpl || globalThis.fetch;
  if (typeof resolved !== 'function') {
    throw new Error('fetch is unavailable in this runtime');
  }
  return resolved;
}

function requireObjectJson(value: unknown, label: string): JsonObject {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} returned invalid JSON`);
  }
  return value as JsonObject;
}

function readString(value: unknown, label: string): string {
  return requireTrimmedString(value, label);
}

function readOptionalString(value: unknown): string | undefined {
  return toOptionalTrimmedNonEmptyString(value);
}

function zeroizeBytes(bytes?: Uint8Array | null): void {
  if (!(bytes instanceof Uint8Array)) return;
  bytes.fill(0);
}

function requireWorkerCtx(workerCtx?: WorkerOperationContext): WorkerOperationContext {
  if (!workerCtx || typeof workerCtx.requestWorkerOperation !== 'function') {
    throw new Error('Email OTP secret-bearing operations require the dedicated emailOtp worker');
  }
  return workerCtx;
}

function cloneFixed32Bytes(value: Uint8Array, label: string): Uint8Array {
  if (!(value instanceof Uint8Array)) {
    throw new Error(`${label} must be a Uint8Array`);
  }
  if (value.length !== 32) {
    throw new Error(`${label} must contain 32 bytes`);
  }
  return Uint8Array.from(value);
}

function buildAuthHeaders(args: { appSessionJwt?: string; publishableKey?: string }): HeadersInit {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  const token = String(args.appSessionJwt || args.publishableKey || '').trim();
  if (token) headers.Authorization = `Bearer ${token}`;
  return headers;
}

function buildWorkerEmailOtpRoutePlan(args: {
  routeFamily: EmailOtpRouteFamily;
  appSessionJwt?: string;
  operation?: WalletEmailOtpLoginOperation;
}) {
  const appSessionJwt = readOptionalString(args.appSessionJwt);
  return buildEmailOtpRoutePlan({
    routeFamily: args.routeFamily,
    authLane: resolveEmailOtpAuthLane({
      sessionKind: appSessionJwt ? 'jwt' : 'cookie',
      ...(appSessionJwt ? { appSessionJwt } : {}),
    }),
    ...(args.operation ? { operation: args.operation } : {}),
  });
}

async function postJson(args: {
  url: string;
  body: JsonObject;
  appSessionJwt?: string;
  publishableKey?: string;
  fetchImpl?: FetchLike;
}): Promise<JsonObject> {
  const fetchImpl = requireFetchImpl(args.fetchImpl);
  const response = await fetchImpl(args.url, {
    method: 'POST',
    headers: buildAuthHeaders({
      appSessionJwt: args.appSessionJwt,
      publishableKey: args.publishableKey,
    }),
    credentials: 'include',
    body: JSON.stringify(args.body),
  });
  const text = await response.text();
  let json: unknown = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    throw new Error(`${args.url} returned non-JSON response (HTTP ${response.status})`);
  }
  const objectJson = requireObjectJson(json, args.url);
  if (!response.ok || objectJson.ok === false) {
    const message =
      (typeof objectJson.message === 'string' && objectJson.message.trim()) ||
      `${args.url} failed (HTTP ${response.status})`;
    throw new EmailOtpRouteError({
      message,
      status: response.status,
      code: objectJson.code,
      retryAfterMs: objectJson.retryAfterMs,
      resetAtMs: objectJson.resetAtMs,
    });
  }
  return objectJson;
}

export async function requestEmailOtpChallenge(args: {
  relayUrl: string;
  walletId: string;
  appSessionJwt?: string;
  otpChannel?: WalletEmailOtpChannel;
  operation?: WalletEmailOtpLoginOperation;
  fetchImpl?: FetchLike;
  workerCtx?: WorkerOperationContext;
}): Promise<{
  challengeId: string;
  otpChannel: WalletEmailOtpChannel;
  emailHint?: string;
  expiresAtMs?: number;
}> {
  if (!args.fetchImpl && args.workerCtx) {
    return await args.workerCtx.requestWorkerOperation({
      kind: 'emailOtp',
      request: {
        type: 'requestEmailOtpChallenge',
        payload: {
          relayUrl: readString(args.relayUrl, 'relayUrl'),
          walletId: readString(args.walletId, 'walletId'),
          routePlan: buildWorkerEmailOtpRoutePlan({
            routeFamily: 'login',
            appSessionJwt: args.appSessionJwt,
            operation: args.operation,
          }),
          ...(args.operation ? { operation: args.operation } : {}),
          otpChannel: EMAIL_OTP_CHANNEL,
        },
      },
    });
  }
  const response = await postJson({
    url: joinNormalizedUrl(args.relayUrl, '/wallet/email-otp/login/challenge'),
    appSessionJwt: args.appSessionJwt,
    fetchImpl: args.fetchImpl,
    body: {
      walletId: readString(args.walletId, 'walletId'),
      otpChannel: args.otpChannel || EMAIL_OTP_CHANNEL,
      ...(args.operation ? { operation: args.operation } : {}),
    },
  });
  const challenge = requireObjectJson(response.challenge, 'wallet/email-otp/login/challenge');
  const delivery =
    response.delivery == null
      ? {}
      : requireObjectJson(response.delivery, 'wallet/email-otp/login/challenge delivery');
  const expiresAtMs = Number(challenge.expiresAtMs);
  const emailHint = readOptionalString(delivery.emailHint);
  return {
    challengeId: readString(challenge.challengeId, 'wallet/email-otp/login/challenge challengeId'),
    otpChannel: EMAIL_OTP_CHANNEL,
    ...(emailHint ? { emailHint } : {}),
    ...(Number.isFinite(expiresAtMs) ? { expiresAtMs } : {}),
  };
}

export async function requestEmailOtpEnrollmentChallenge(args: {
  relayUrl: string;
  walletId: string;
  appSessionJwt?: string;
  otpChannel?: WalletEmailOtpChannel;
  fetchImpl?: FetchLike;
  workerCtx?: WorkerOperationContext;
}): Promise<{
  challengeId: string;
  otpChannel: WalletEmailOtpChannel;
  emailHint?: string;
  expiresAtMs?: number;
}> {
  if (!args.fetchImpl && args.workerCtx) {
    return await args.workerCtx.requestWorkerOperation({
      kind: 'emailOtp',
      request: {
        type: 'requestEmailOtpEnrollmentChallenge',
        payload: {
          relayUrl: readString(args.relayUrl, 'relayUrl'),
          walletId: readString(args.walletId, 'walletId'),
          routePlan: buildWorkerEmailOtpRoutePlan({
            routeFamily: 'registration',
            appSessionJwt: args.appSessionJwt,
          }),
          otpChannel: EMAIL_OTP_CHANNEL,
        },
      },
    });
  }
  const response = await postJson({
    url: joinNormalizedUrl(args.relayUrl, '/wallet/email-otp/registration/challenge'),
    appSessionJwt: args.appSessionJwt,
    fetchImpl: args.fetchImpl,
    body: {
      walletId: readString(args.walletId, 'walletId'),
      otpChannel: args.otpChannel || EMAIL_OTP_CHANNEL,
    },
  });
  const challenge = requireObjectJson(response.challenge, 'wallet/email-otp/registration/challenge');
  const delivery =
    response.delivery == null
      ? {}
      : requireObjectJson(response.delivery, 'wallet/email-otp/registration/challenge delivery');
  const expiresAtMs = Number(challenge.expiresAtMs);
  const emailHint = readOptionalString(delivery.emailHint);
  return {
    challengeId: readString(
      challenge.challengeId,
      'wallet/email-otp/registration/challenge challengeId',
    ),
    otpChannel: EMAIL_OTP_CHANNEL,
    ...(emailHint ? { emailHint } : {}),
    ...(Number.isFinite(expiresAtMs) ? { expiresAtMs } : {}),
  };
}

export async function verifyEmailOtpCode(args: {
  relayUrl: string;
  walletId: string;
  challengeId: string;
  otpCode: string;
  appSessionJwt?: string;
  otpChannel?: WalletEmailOtpChannel;
  fetchImpl?: FetchLike;
  workerCtx?: WorkerOperationContext;
}): Promise<{
  loginGrant: string;
  otpChannel: WalletEmailOtpChannel;
  enrollmentEscrowCiphertextB64u: string;
}> {
  if (!args.fetchImpl && args.workerCtx) {
    return await args.workerCtx.requestWorkerOperation({
      kind: 'emailOtp',
      request: {
        type: 'verifyEmailOtpCode',
        payload: {
          relayUrl: readString(args.relayUrl, 'relayUrl'),
          walletId: readString(args.walletId, 'walletId'),
          challengeId: readString(args.challengeId, 'challengeId'),
          otpCode: readString(args.otpCode, 'otpCode'),
          routePlan: buildWorkerEmailOtpRoutePlan({
            routeFamily: 'login',
            appSessionJwt: args.appSessionJwt,
          }),
          otpChannel: EMAIL_OTP_CHANNEL,
        },
      },
    });
  }
  const response = await postJson({
    url: joinNormalizedUrl(args.relayUrl, '/wallet/email-otp/login/verify'),
    appSessionJwt: args.appSessionJwt,
    fetchImpl: args.fetchImpl,
    body: {
      walletId: readString(args.walletId, 'walletId'),
      challengeId: readString(args.challengeId, 'challengeId'),
      otpCode: readString(args.otpCode, 'otpCode'),
      otpChannel: args.otpChannel || EMAIL_OTP_CHANNEL,
    },
  });
  return {
    loginGrant: readString(response.loginGrant, 'wallet/email-otp/login/verify loginGrant'),
    otpChannel: EMAIL_OTP_CHANNEL,
    enrollmentEscrowCiphertextB64u: readString(
      response.enrollmentEscrowCiphertextB64u,
      'wallet/email-otp/login/verify enrollmentEscrowCiphertextB64u',
    ),
  };
}

export async function exchangeGoogleEmailOtpSession(args: {
  relayUrl: string;
  idToken: string;
  accountMode: 'register' | 'login';
  sessionKind?: 'jwt' | 'cookie';
  rerollRegistrationAttempt?: boolean;
  runtimeEnvironmentId?: string;
  publishableKey?: string;
  fetchImpl?: FetchLike;
}): Promise<GoogleEmailOtpSessionExchangeResult> {
  const sessionKind = args.sessionKind === 'jwt' ? 'jwt' : 'cookie';
  const accountMode = args.accountMode === 'register' ? 'register' : 'login';
  const runtimeEnvironmentId = String(args.runtimeEnvironmentId || '').trim();
  const response = await postJson({
    url: joinNormalizedUrl(args.relayUrl, '/session/exchange'),
    fetchImpl: args.fetchImpl,
    publishableKey: args.publishableKey,
    body: {
      session_kind: sessionKind,
      ...(runtimeEnvironmentId ? { runtimeEnvironmentId } : {}),
      exchange: {
        type: 'oidc_jwt',
        provider: 'google',
        account_mode: accountMode,
        ...(args.rerollRegistrationAttempt ? { reroll_registration_attempt: true } : {}),
        token: readString(args.idToken, 'idToken'),
      },
    },
  });
  const session = requireObjectJson(response.session, 'session/exchange session');
  const userId = readString(session.userId, 'session/exchange session.userId');
  const walletId = readOptionalString(session.walletId) || userId;
  const jwt = readOptionalString(response.jwt);
  const email = readOptionalString(session.email);
  const name = readOptionalString(session.name);
  const googleEmailOtpResolutionRaw =
    session.googleEmailOtpResolution &&
    typeof session.googleEmailOtpResolution === 'object' &&
    !Array.isArray(session.googleEmailOtpResolution)
      ? (session.googleEmailOtpResolution as JsonObject)
      : null;
  const googleEmailOtpResolutionMode = readOptionalString(googleEmailOtpResolutionRaw?.mode);
  const googleEmailOtpRegistrationAttemptId = readOptionalString(
    googleEmailOtpResolutionRaw?.registrationAttemptId,
  );
  const googleEmailOtpResolutionExpiresAt = readOptionalString(
    googleEmailOtpResolutionRaw?.expiresAt,
  );
  const runtimePolicyScope = normalizeThresholdRuntimePolicyScope(session.runtimePolicyScope);
  return {
    ...(jwt ? { jwt } : {}),
    session: {
      userId,
      walletId,
      ...(email ? { email } : {}),
      ...(name ? { name } : {}),
      ...(googleEmailOtpResolutionMode === 'existing_wallet' ||
      googleEmailOtpResolutionMode === 'register_started'
        ? {
            googleEmailOtpResolution: {
              mode: googleEmailOtpResolutionMode,
              ...(googleEmailOtpRegistrationAttemptId
                ? { registrationAttemptId: googleEmailOtpRegistrationAttemptId }
                : {}),
              ...(googleEmailOtpResolutionExpiresAt
                ? { expiresAt: googleEmailOtpResolutionExpiresAt }
                : {}),
            },
          }
        : {}),
      ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
    },
  };
}

export async function enrollEmailOtpWallet(args: {
  relayUrl: string;
  walletId: string;
  userId?: string;
  challengeId?: string;
  otpCode: string;
  shamirPrimeB64u: string;
  workerCtx: WorkerOperationContext;
  appSessionJwt?: string;
  otpChannel?: WalletEmailOtpChannel;
  clientSecret32?: Uint8Array;
}): Promise<EmailOtpEnrollmentResult> {
  const workerCtx = requireWorkerCtx(args.workerCtx);
  let workerClientSecret32: Uint8Array | null = null;
  try {
    workerClientSecret32 = args.clientSecret32
      ? cloneFixed32Bytes(args.clientSecret32, 'clientSecret32')
      : null;
    return await workerCtx.requestWorkerOperation({
      kind: 'emailOtp',
      request: {
        type: 'enrollEmailOtpWallet',
        payload: {
          relayUrl: readString(args.relayUrl, 'relayUrl'),
          walletId: readString(args.walletId, 'walletId'),
          ...(readOptionalString(args.userId) ? { userId: readOptionalString(args.userId) } : {}),
          ...(readOptionalString(args.challengeId)
            ? { challengeId: readOptionalString(args.challengeId) }
            : {}),
          otpCode: readString(args.otpCode, 'otpCode'),
          shamirPrimeB64u: readString(args.shamirPrimeB64u, 'shamirPrimeB64u'),
          routePlan: buildWorkerEmailOtpRoutePlan({
            routeFamily: 'registration',
            appSessionJwt: args.appSessionJwt,
          }),
          otpChannel: EMAIL_OTP_CHANNEL,
          ...(workerClientSecret32
            ? { clientSecret32: workerClientSecret32.buffer.slice(0) }
            : {}),
        },
      },
    });
  } finally {
    zeroizeBytes(workerClientSecret32);
  }
}
