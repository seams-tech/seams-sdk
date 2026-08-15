import {
  EMAIL_OTP_CHANNEL,
  WALLET_EMAIL_OTP_ACTIONS,
  WALLET_EMAIL_OTP_REGISTRATION_OPERATION,
  WALLET_EMAIL_OTP_UNLOCK_OPERATION,
  type WalletEmailOtpChannel,
  type WalletEmailOtpLoginOperation,
} from '@shared/utils/emailOtpDomain';
import { joinNormalizedUrl } from '@shared/utils/normalize';
import { requireTrimmedString, toOptionalTrimmedNonEmptyString } from '@shared/utils/validation';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import type {
  EmailOtpChallengeDelivery,
  EmailOtpEnrollmentResult,
  GoogleEmailOtpProviderResolution,
} from '@/core/signingEngine/session/emailOtp/publicTypes';
import {
  parseEmailOtpChallengeDelivery,
  parseEmailOtpProviderDelivery,
} from '@/core/signingEngine/session/emailOtp/challengeDelivery';
import { buildEmailOtpRoutePlan, type EmailOtpRouteFamily } from '@/core/signingEngine/stepUpConfirmation/otpPrompt/authLane';

export type FetchLike = typeof fetch;
export type { EmailOtpEnrollmentResult, WalletEmailOtpChannel };
export { EMAIL_OTP_CHANNEL };

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

export function parseEmailOtpEnrollmentResult(value: unknown): EmailOtpEnrollmentResult {
  const response = requireObjectJson(value, 'Email OTP enrollment result');
  return {
    challengeId: readString(response.challengeId, 'challengeId'),
    otpChannel: EMAIL_OTP_CHANNEL,
    enrollmentId: readString(response.enrollmentId, 'enrollmentId'),
    enrollmentSealKeyVersion: readString(
      response.enrollmentSealKeyVersion,
      'enrollmentSealKeyVersion',
    ),
    serverSealedFactorCiphertextB64u: readString(
      response.serverSealedFactorCiphertextB64u,
      'serverSealedFactorCiphertextB64u',
    ),
    clientUnlockPublicKeyB64u: readString(
      response.clientUnlockPublicKeyB64u,
      'clientUnlockPublicKeyB64u',
    ),
    unlockKeyVersion: readString(response.unlockKeyVersion, 'unlockKeyVersion'),
  };
}

export function readString(value: unknown, label: string): string {
  return requireTrimmedString(value, label);
}

export function readOptionalString(value: unknown): string | undefined {
  return toOptionalTrimmedNonEmptyString(value);
}

export function zeroizeBytes(bytes?: Uint8Array | null): void {
  if (!(bytes instanceof Uint8Array)) return;
  bytes.fill(0);
}

export function requireWorkerCtx(workerCtx?: WorkerOperationContext): WorkerOperationContext {
  if (!workerCtx || typeof workerCtx.requestWorkerOperation !== 'function') {
    throw new Error('Email OTP secret-bearing operations require the dedicated emailOtp worker');
  }
  return workerCtx;
}

export function cloneFixed32Bytes(value: Uint8Array, label: string): Uint8Array {
  if (!(value instanceof Uint8Array)) {
    throw new Error(`${label} must be a Uint8Array`);
  }
  if (value.length !== 32) {
    throw new Error(`${label} must contain 32 bytes`);
  }
  return Uint8Array.from(value);
}

function buildAuthHeaders(args: { publishableKey?: string }): HeadersInit {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  const token = String(args.publishableKey || '').trim();
  if (token) headers.Authorization = `Bearer ${token}`;
  return headers;
}

export function buildWorkerEmailOtpRoutePlan(args: {
  routeFamily: Extract<EmailOtpRouteFamily, 'login' | 'registration'>;
  operation?: WalletEmailOtpLoginOperation;
}) {
  if (args.routeFamily === 'registration') {
    return buildEmailOtpRoutePlan({
      routeFamily: 'registration',
      operation: WALLET_EMAIL_OTP_REGISTRATION_OPERATION,
    });
  }
  return buildEmailOtpRoutePlan({
    routeFamily: 'login',
    operation: args.operation ?? WALLET_EMAIL_OTP_UNLOCK_OPERATION,
  });
}

function requireEmailOtpChallengeAction(args: {
  challenge: JsonObject;
  expectedAction: string;
  context: string;
}): void {
  const action = readOptionalString(args.challenge.action);
  if (action && action !== args.expectedAction) {
    throw new Error(`${args.context} returned ${action}; expected ${args.expectedAction}`);
  }
}

export async function postJson(args: {
  url: string;
  body: JsonObject;
  publishableKey?: string;
  fetchImpl?: FetchLike;
}): Promise<JsonObject> {
  const fetchImpl = requireFetchImpl(args.fetchImpl);
  const response = await fetchImpl(args.url, {
    method: 'POST',
    headers: buildAuthHeaders({
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

export async function resolveGoogleEmailOtpProvider(args: {
  relayUrl: string;
  idToken: string;
  accountMode: 'login' | 'register';
  publishableKey: string;
  fetchImpl?: FetchLike;
}): Promise<GoogleEmailOtpProviderResolution> {
  const response = await postJson({
    url: joinNormalizedUrl(args.relayUrl, '/auth/google/verify'),
    fetchImpl: args.fetchImpl,
    publishableKey: readString(args.publishableKey, 'publishableKey'),
    body: {
      id_token: readString(args.idToken, 'idToken'),
      account_mode: args.accountMode,
    },
  });
  const mode = readString(response.mode, 'auth/google/verify mode');
  const walletId = readString(response.walletId, 'auth/google/verify walletId');
  const providerSubject = readString(
    response.providerSubject,
    'auth/google/verify providerSubject',
  );
  const email = readOptionalString(response.email);
  if (mode === 'existing_wallet') {
    if (response.hasEmailOtpEnrollment !== true) {
      throw new Error('auth/google/verify existing wallet is missing Email OTP enrollment');
    }
    return {
      mode,
      walletId,
      providerSubject,
      ...(email ? { email } : {}),
      hasEmailOtpEnrollment: true,
    };
  }
  if (mode !== 'register_started') {
    throw new Error(`auth/google/verify returned unsupported mode: ${mode}`);
  }
  if (!email) throw new Error('auth/google/verify registration is missing email');
  const offer = requireObjectJson(response.offer, 'auth/google/verify offer');
  const candidatesRaw = Array.isArray(offer.candidates) ? offer.candidates : [];
  const candidates = candidatesRaw.map(parseGoogleEmailOtpProviderCandidate);
  const firstCandidate = candidates[0];
  if (!firstCandidate) throw new Error('auth/google/verify offer has no wallet candidates');
  return {
    mode,
    walletId,
    providerSubject,
    email,
    registrationAttemptId: readString(
      response.registrationAttemptId,
      'auth/google/verify registrationAttemptId',
    ),
    expiresAtMs: requireFutureTimestamp(
      response.expiresAtMs,
      'auth/google/verify expiresAtMs',
    ),
    offer: {
      offerId: readString(offer.offerId, 'auth/google/verify offer.offerId'),
      selectedCandidateId: readString(
        offer.selectedCandidateId,
        'auth/google/verify offer.selectedCandidateId',
      ),
      candidates: [firstCandidate, ...candidates.slice(1)],
    },
  };
}

function parseGoogleEmailOtpProviderCandidate(value: unknown): {
  readonly candidateId: string;
  readonly walletId: string;
} {
  const candidate = requireObjectJson(value, 'auth/google/verify offer candidate');
  return {
    candidateId: readString(candidate.candidateId, 'offer candidate candidateId'),
    walletId: readString(candidate.walletId, 'offer candidate walletId'),
  };
}

function requireFutureTimestamp(value: unknown, label: string): number {
  const timestamp = Number(value);
  if (!Number.isSafeInteger(timestamp) || timestamp <= Date.now()) {
    throw new Error(`${label} must be a future timestamp`);
  }
  return timestamp;
}

export async function requestEmailOtpChallenge(args: {
  relayUrl: string;
  walletId: string;
  otpChannel?: WalletEmailOtpChannel;
  operation?: WalletEmailOtpLoginOperation;
  fetchImpl?: FetchLike;
  workerCtx?: WorkerOperationContext;
}): Promise<{
  challengeId: string;
  otpChannel: WalletEmailOtpChannel;
  delivery: EmailOtpChallengeDelivery;
  emailHint?: string;
  expiresAtMs?: number;
}> {
  const operation = args.operation ?? WALLET_EMAIL_OTP_UNLOCK_OPERATION;
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
            operation,
          }),
          otpChannel: EMAIL_OTP_CHANNEL,
        },
      },
    });
  }
  const response = await postJson({
    url: joinNormalizedUrl(args.relayUrl, '/wallet/email-otp/challenge'),
    fetchImpl: args.fetchImpl,
    body: {
      walletId: readString(args.walletId, 'walletId'),
      otpChannel: args.otpChannel || EMAIL_OTP_CHANNEL,
      operation,
    },
  });
  const challenge = requireObjectJson(response.challenge, 'wallet/email-otp/challenge');
  requireEmailOtpChallengeAction({
    challenge,
    expectedAction: WALLET_EMAIL_OTP_ACTIONS.login,
    context: 'wallet/email-otp/challenge',
  });
  const delivery = parseEmailOtpChallengeDelivery(
    response.delivery,
    'wallet/email-otp/challenge delivery',
  );
  const expiresAtMs = Number(challenge.expiresAtMs);
  const result: {
    challengeId: string;
    otpChannel: typeof EMAIL_OTP_CHANNEL;
    delivery: EmailOtpChallengeDelivery;
    emailHint?: string;
    expiresAtMs?: number;
  } = {
    challengeId: readString(challenge.challengeId, 'wallet/email-otp/challenge challengeId'),
    otpChannel: EMAIL_OTP_CHANNEL,
    delivery,
    emailHint: delivery.emailHint,
  };
  if (Number.isFinite(expiresAtMs)) {
    result.expiresAtMs = expiresAtMs;
  }
  return result;
}

export async function requestEmailOtpEnrollmentChallenge(args: {
  relayUrl: string;
  walletId: string;
  otpChannel?: WalletEmailOtpChannel;
  fetchImpl?: FetchLike;
  workerCtx?: WorkerOperationContext;
}): Promise<{
  challengeId: string;
  otpChannel: WalletEmailOtpChannel;
  delivery: EmailOtpChallengeDelivery;
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
          }),
          otpChannel: EMAIL_OTP_CHANNEL,
        },
      },
    });
  }
  const response = await postJson({
    url: joinNormalizedUrl(args.relayUrl, '/wallet/email-otp/registration/challenge'),
    fetchImpl: args.fetchImpl,
    body: {
      walletId: readString(args.walletId, 'walletId'),
      otpChannel: args.otpChannel || EMAIL_OTP_CHANNEL,
    },
  });
  const challenge = requireObjectJson(
    response.challenge,
    'wallet/email-otp/registration/challenge',
  );
  requireEmailOtpChallengeAction({
    challenge,
    expectedAction: WALLET_EMAIL_OTP_ACTIONS.registration,
    context: 'wallet/email-otp/registration/challenge',
  });
  const delivery = parseEmailOtpChallengeDelivery(
    response.delivery,
    'wallet/email-otp/registration/challenge delivery',
  );
  const expiresAtMs = Number(challenge.expiresAtMs);
  const result: {
    challengeId: string;
    otpChannel: typeof EMAIL_OTP_CHANNEL;
    delivery: EmailOtpChallengeDelivery;
    emailHint?: string;
    expiresAtMs?: number;
  } = {
    challengeId: readString(
      challenge.challengeId,
      'wallet/email-otp/registration/challenge challengeId',
    ),
    otpChannel: EMAIL_OTP_CHANNEL,
    delivery,
    emailHint: delivery.emailHint,
  };
  if (Number.isFinite(expiresAtMs)) {
    result.expiresAtMs = expiresAtMs;
  }
  return result;
}
