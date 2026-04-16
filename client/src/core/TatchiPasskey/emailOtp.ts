import { joinNormalizedUrl } from '@shared/utils/normalize';
import type { WorkerOperationContext } from '../signingEngine/workerManager/executeWorkerOperation';

type FetchLike = typeof fetch;
type EmailOtpChannel = 'email_otp';

type JsonObject = Record<string, unknown>;

export type EmailOtpEnrollmentResult = {
  thresholdEcdsaClientVerifyingShareB64u: string;
  challengeId: string;
  otpChannel: EmailOtpChannel;
  emailOtpKeyVersion: string;
  unlockPublicKeyB64u: string;
  unlockKeyVersion: string;
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
  const parsed = typeof value === 'string' ? value.trim() : '';
  if (!parsed) throw new Error(`${label} is required`);
  return parsed;
}

function readOptionalString(value: unknown): string | undefined {
  const parsed = typeof value === 'string' ? value.trim() : '';
  return parsed || undefined;
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

function buildSessionHeaders(appSessionJwt?: string): HeadersInit {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  const token = String(appSessionJwt || '').trim();
  if (token) headers.Authorization = `Bearer ${token}`;
  return headers;
}

async function postJson(args: {
  url: string;
  body: JsonObject;
  appSessionJwt?: string;
  fetchImpl?: FetchLike;
}): Promise<JsonObject> {
  const fetchImpl = requireFetchImpl(args.fetchImpl);
  const response = await fetchImpl(args.url, {
    method: 'POST',
    headers: buildSessionHeaders(args.appSessionJwt),
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
    throw new Error(message);
  }
  return objectJson;
}

export async function requestEmailOtpChallenge(args: {
  relayUrl: string;
  walletId: string;
  appSessionJwt?: string;
  otpChannel?: EmailOtpChannel;
  fetchImpl?: FetchLike;
  workerCtx?: WorkerOperationContext;
}): Promise<{
  challengeId: string;
  otpChannel: EmailOtpChannel;
}> {
  if (!args.fetchImpl && args.workerCtx) {
    return await args.workerCtx.requestWorkerOperation({
      kind: 'emailOtp',
      request: {
        type: 'requestEmailOtpChallenge',
        payload: {
          relayUrl: readString(args.relayUrl, 'relayUrl'),
          walletId: readString(args.walletId, 'walletId'),
          ...(readOptionalString(args.appSessionJwt)
            ? { appSessionJwt: readOptionalString(args.appSessionJwt) }
            : {}),
          otpChannel: 'email_otp',
        },
      },
    });
  }
  const response = await postJson({
    url: joinNormalizedUrl(args.relayUrl, '/wallet/email-otp/challenge'),
    appSessionJwt: args.appSessionJwt,
    fetchImpl: args.fetchImpl,
    body: {
      walletId: readString(args.walletId, 'walletId'),
      otpChannel: args.otpChannel || 'email_otp',
    },
  });
  const challenge = requireObjectJson(response.challenge, 'wallet/email-otp/challenge');
  return {
    challengeId: readString(challenge.challengeId, 'wallet/email-otp/challenge challengeId'),
    otpChannel: 'email_otp',
  };
}

export async function requestEmailOtpEnrollmentChallenge(args: {
  relayUrl: string;
  walletId: string;
  appSessionJwt?: string;
  otpChannel?: EmailOtpChannel;
  fetchImpl?: FetchLike;
  workerCtx?: WorkerOperationContext;
}): Promise<{
  challengeId: string;
  otpChannel: EmailOtpChannel;
}> {
  if (!args.fetchImpl && args.workerCtx) {
    return await args.workerCtx.requestWorkerOperation({
      kind: 'emailOtp',
      request: {
        type: 'requestEmailOtpEnrollmentChallenge',
        payload: {
          relayUrl: readString(args.relayUrl, 'relayUrl'),
          walletId: readString(args.walletId, 'walletId'),
          ...(readOptionalString(args.appSessionJwt)
            ? { appSessionJwt: readOptionalString(args.appSessionJwt) }
            : {}),
          otpChannel: 'email_otp',
        },
      },
    });
  }
  const response = await postJson({
    url: joinNormalizedUrl(args.relayUrl, '/wallet/email-otp/enroll/challenge'),
    appSessionJwt: args.appSessionJwt,
    fetchImpl: args.fetchImpl,
    body: {
      walletId: readString(args.walletId, 'walletId'),
      otpChannel: args.otpChannel || 'email_otp',
    },
  });
  const challenge = requireObjectJson(response.challenge, 'wallet/email-otp/enroll/challenge');
  return {
    challengeId: readString(
      challenge.challengeId,
      'wallet/email-otp/enroll/challenge challengeId',
    ),
    otpChannel: 'email_otp',
  };
}

export async function verifyEmailOtpCode(args: {
  relayUrl: string;
  walletId: string;
  challengeId: string;
  otpCode: string;
  appSessionJwt?: string;
  otpChannel?: EmailOtpChannel;
  fetchImpl?: FetchLike;
  workerCtx?: WorkerOperationContext;
}): Promise<{
  loginGrant: string;
  otpChannel: EmailOtpChannel;
  emailOtpEscrowBlob: string;
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
          ...(readOptionalString(args.appSessionJwt)
            ? { appSessionJwt: readOptionalString(args.appSessionJwt) }
            : {}),
          otpChannel: 'email_otp',
        },
      },
    });
  }
  const response = await postJson({
    url: joinNormalizedUrl(args.relayUrl, '/wallet/email-otp/verify'),
    appSessionJwt: args.appSessionJwt,
    fetchImpl: args.fetchImpl,
    body: {
      walletId: readString(args.walletId, 'walletId'),
      challengeId: readString(args.challengeId, 'challengeId'),
      otpCode: readString(args.otpCode, 'otpCode'),
      otpChannel: args.otpChannel || 'email_otp',
    },
  });
  return {
    loginGrant: readString(response.loginGrant, 'wallet/email-otp/verify loginGrant'),
    otpChannel: 'email_otp',
    emailOtpEscrowBlob: readString(
      response.emailOtpEscrowBlob,
      'wallet/email-otp/verify emailOtpEscrowBlob',
    ),
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
  otpChannel?: EmailOtpChannel;
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
          ...(readOptionalString(args.appSessionJwt)
            ? { appSessionJwt: readOptionalString(args.appSessionJwt) }
            : {}),
          otpChannel: 'email_otp',
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
