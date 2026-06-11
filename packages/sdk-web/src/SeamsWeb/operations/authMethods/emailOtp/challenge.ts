import {
  EMAIL_OTP_CHANNEL,
  WALLET_EMAIL_OTP_ACTIONS,
  type WalletEmailOtpChannel,
  type WalletEmailOtpLoginOperation,
} from '@shared/utils/emailOtpDomain';
import { joinNormalizedUrl } from '@shared/utils/normalize';
import {
  buildEmailOtpRecoveryCodeSet,
  type EmailOtpRecoveryCodeSet,
} from '@shared/utils/emailOtpRecoveryKey';
import { requireTrimmedString, toOptionalTrimmedNonEmptyString } from '@shared/utils/validation';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import {
  normalizeThresholdRuntimePolicyScope,
  type ThresholdRuntimePolicyScope,
} from '@/core/signingEngine/threshold/sessionPolicy';
import type {
  EmailOtpDeviceEnrollmentRemoveResult,
  EmailOtpDeviceEnrollmentRestoreResult,
  EmailOtpEnrollmentResult,
  EmailOtpRecoveryCodeBackupStatus,
  EmailOtpRecoveryCodeLifecycleStatus,
  EmailOtpRecoveryCodeStatus,
  GoogleEmailOtpSessionExchangeResult,
} from '@/core/signingEngine/session/emailOtp/publicTypes';
import {
  buildEmailOtpRoutePlan,
  resolveEmailOtpAuthLane,
  type EmailOtpRouteFamily,
} from '@/core/signingEngine/stepUpConfirmation/otpPrompt/authLane';

export type FetchLike = typeof fetch;
export type {
  EmailOtpDeviceEnrollmentRemoveResult,
  EmailOtpDeviceEnrollmentRestoreResult,
  EmailOtpEnrollmentResult,
  EmailOtpRecoveryCodeBackupStatus,
  EmailOtpRecoveryCodeLifecycleStatus,
  EmailOtpRecoveryCodeSet,
  EmailOtpRecoveryCodeStatus,
  GoogleEmailOtpSessionExchangeResult,
  WalletEmailOtpChannel,
};
export { EMAIL_OTP_CHANNEL };

type JsonObject = Record<string, unknown>;
type GoogleEmailOtpRegistrationOfferCandidateJson = {
  candidateId: string;
  walletId: string;
};
type NonEmptyGoogleEmailOtpRegistrationOfferCandidates = readonly [
  GoogleEmailOtpRegistrationOfferCandidateJson,
  ...GoogleEmailOtpRegistrationOfferCandidateJson[],
];

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

function requireFiniteTimestampMs(value: unknown, label: string): number {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    throw new Error(`${label} must be a positive timestamp`);
  }
  return Math.floor(parsed);
}

export function parseEmailOtpRecoveryCodeMaterial(value: unknown): {
  recoveryKeys: EmailOtpRecoveryCodeSet;
  recoveryCodesIssuedAtMs: number;
} {
  const response = requireObjectJson(value, 'Email OTP recovery-code material');
  return {
    recoveryKeys: buildEmailOtpRecoveryCodeSet(
      Array.isArray(response.recoveryKeys) ? response.recoveryKeys.map(String) : [],
    ),
    recoveryCodesIssuedAtMs: requireFiniteTimestampMs(
      response.recoveryCodesIssuedAtMs,
      'recoveryCodesIssuedAtMs',
    ),
  };
}

export function parseEmailOtpEnrollmentResult(value: unknown): EmailOtpEnrollmentResult {
  const response = requireObjectJson(value, 'Email OTP enrollment result');
  const recoveryCodeMaterial = parseEmailOtpRecoveryCodeMaterial(response);
  return {
    thresholdEcdsaClientVerifyingShareB64u: readString(
      response.thresholdEcdsaClientVerifyingShareB64u,
      'thresholdEcdsaClientVerifyingShareB64u',
    ),
    recoveryKeys: recoveryCodeMaterial.recoveryKeys,
    recoveryCodesIssuedAtMs: recoveryCodeMaterial.recoveryCodesIssuedAtMs,
    challengeId: readString(response.challengeId, 'challengeId'),
    otpChannel: EMAIL_OTP_CHANNEL,
    enrollmentId: readString(response.enrollmentId, 'enrollmentId'),
    enrollmentSealKeyVersion: readString(
      response.enrollmentSealKeyVersion,
      'enrollmentSealKeyVersion',
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

function buildAuthHeaders(args: { appSessionJwt?: string; publishableKey?: string }): HeadersInit {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  const token = String(args.appSessionJwt || args.publishableKey || '').trim();
  if (token) headers.Authorization = `Bearer ${token}`;
  return headers;
}

export function buildWorkerEmailOtpRoutePlan(args: {
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
  appSessionVersion?: string;
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
  requireEmailOtpChallengeAction({
    challenge,
    expectedAction: WALLET_EMAIL_OTP_ACTIONS.login,
    context: 'wallet/email-otp/login/challenge',
  });
  const delivery =
    response.delivery == null
      ? {}
      : requireObjectJson(response.delivery, 'wallet/email-otp/login/challenge delivery');
  const expiresAtMs = Number(challenge.expiresAtMs);
  const emailHint = readOptionalString(delivery.emailHint);
  const appSessionVersion = readOptionalString(challenge.appSessionVersion);
  const result: {
    challengeId: string;
    otpChannel: typeof EMAIL_OTP_CHANNEL;
    emailHint?: string;
    expiresAtMs?: number;
    appSessionVersion?: string;
  } = {
    challengeId: readString(challenge.challengeId, 'wallet/email-otp/login/challenge challengeId'),
    otpChannel: EMAIL_OTP_CHANNEL,
  };
  if (emailHint) {
    result.emailHint = emailHint;
  }
  if (Number.isFinite(expiresAtMs)) {
    result.expiresAtMs = expiresAtMs;
  }
  if (appSessionVersion) {
    result.appSessionVersion = appSessionVersion;
  }
  return result;
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
  appSessionVersion?: string;
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
  const challenge = requireObjectJson(
    response.challenge,
    'wallet/email-otp/registration/challenge',
  );
  requireEmailOtpChallengeAction({
    challenge,
    expectedAction: WALLET_EMAIL_OTP_ACTIONS.registration,
    context: 'wallet/email-otp/registration/challenge',
  });
  const delivery =
    response.delivery == null
      ? {}
      : requireObjectJson(response.delivery, 'wallet/email-otp/registration/challenge delivery');
  const expiresAtMs = Number(challenge.expiresAtMs);
  const emailHint = readOptionalString(delivery.emailHint);
  const appSessionVersion = readOptionalString(challenge.appSessionVersion);
  const result: {
    challengeId: string;
    otpChannel: typeof EMAIL_OTP_CHANNEL;
    emailHint?: string;
    expiresAtMs?: number;
    appSessionVersion?: string;
  } = {
    challengeId: readString(
      challenge.challengeId,
      'wallet/email-otp/registration/challenge challengeId',
    ),
    otpChannel: EMAIL_OTP_CHANNEL,
  };
  if (emailHint) {
    result.emailHint = emailHint;
  }
  if (Number.isFinite(expiresAtMs)) {
    result.expiresAtMs = expiresAtMs;
  }
  if (appSessionVersion) {
    result.appSessionVersion = appSessionVersion;
  }
  return result;
}

export async function requestEmailOtpDeviceRecoveryChallenge(args: {
  relayUrl: string;
  walletId: string;
  appSessionJwt?: string;
  otpChannel?: WalletEmailOtpChannel;
  fetchImpl?: FetchLike;
}): Promise<{
  challengeId: string;
  otpChannel: WalletEmailOtpChannel;
  emailHint?: string;
  expiresAtMs?: number;
}> {
  const response = await postJson({
    url: joinNormalizedUrl(args.relayUrl, '/wallet/email-otp/recovery-challenge'),
    appSessionJwt: args.appSessionJwt,
    fetchImpl: args.fetchImpl,
    body: {
      walletId: readString(args.walletId, 'walletId'),
      otpChannel: args.otpChannel || EMAIL_OTP_CHANNEL,
    },
  });
  const challenge = requireObjectJson(response.challenge, 'wallet/email-otp/recovery-challenge');
  const delivery =
    response.delivery == null
      ? {}
      : requireObjectJson(response.delivery, 'wallet/email-otp/recovery-challenge delivery');
  const expiresAtMs = Number(challenge.expiresAtMs);
  const emailHint = readOptionalString(delivery.emailHint);
  return {
    challengeId: readString(
      challenge.challengeId,
      'wallet/email-otp/recovery-challenge challengeId',
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
  enrollmentSealKeyVersion?: string;
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
    ...(readOptionalString(response.enrollmentSealKeyVersion)
      ? { enrollmentSealKeyVersion: readOptionalString(response.enrollmentSealKeyVersion) }
      : {}),
  };
}

export async function exchangeGoogleEmailOtpSession(args: {
  relayUrl: string;
  idToken: string;
  accountMode: 'register' | 'login';
  sessionKind?: 'jwt' | 'cookie';
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
  const googleEmailOtpResolutionExpiresAtMs = Number(googleEmailOtpResolutionRaw?.expiresAtMs);
  const googleEmailOtpRegistrationOfferRaw =
    googleEmailOtpResolutionRaw?.offer &&
    typeof googleEmailOtpResolutionRaw.offer === 'object' &&
    !Array.isArray(googleEmailOtpResolutionRaw.offer)
      ? (googleEmailOtpResolutionRaw.offer as JsonObject)
      : null;
  const googleEmailOtpRegistrationOfferCandidates = Array.isArray(
    googleEmailOtpRegistrationOfferRaw?.candidates,
  )
    ? googleEmailOtpRegistrationOfferRaw.candidates.map((candidateRaw, index) => {
        const candidate = requireObjectJson(
          candidateRaw,
          `session/exchange registration offer candidate ${index}`,
        );
        return {
          candidateId: readString(
            candidate.candidateId,
            `session/exchange registration offer candidate ${index}.candidateId`,
          ),
          walletId: readString(
            candidate.walletId,
            `session/exchange registration offer candidate ${index}.walletId`,
          ),
        };
      })
    : [];
  const [firstGoogleEmailOtpRegistrationOfferCandidate, ...remainingGoogleEmailOtpRegistrationOfferCandidates] =
    googleEmailOtpRegistrationOfferCandidates;
  const googleEmailOtpRegistrationOffer =
    googleEmailOtpRegistrationOfferRaw && firstGoogleEmailOtpRegistrationOfferCandidate
      ? (() => {
          const candidates: NonEmptyGoogleEmailOtpRegistrationOfferCandidates = [
            firstGoogleEmailOtpRegistrationOfferCandidate,
            ...remainingGoogleEmailOtpRegistrationOfferCandidates,
          ];
          return {
            offerId: readString(
              googleEmailOtpRegistrationOfferRaw.offerId,
              'session/exchange registration offer.offerId',
            ),
            selectedCandidateId: readString(
              googleEmailOtpRegistrationOfferRaw.selectedCandidateId,
              'session/exchange registration offer.selectedCandidateId',
            ),
            candidates,
          };
        })()
      : undefined;
  const loginChallengeRaw =
    googleEmailOtpResolutionRaw?.loginChallenge &&
    typeof googleEmailOtpResolutionRaw.loginChallenge === 'object' &&
    !Array.isArray(googleEmailOtpResolutionRaw.loginChallenge)
      ? (googleEmailOtpResolutionRaw.loginChallenge as JsonObject)
      : null;
  const loginChallengeDelivery = readOptionalString(loginChallengeRaw?.delivery);
  const activeLoginChallengeDelivery: 'sent' | 'reused' | null =
    loginChallengeDelivery === 'sent'
      ? 'sent'
      : loginChallengeDelivery === 'reused'
        ? 'reused'
        : null;
  const loginChallenge =
    activeLoginChallengeDelivery
      ? {
          delivery: activeLoginChallengeDelivery,
          challengeId: readString(
            loginChallengeRaw?.challengeId,
            'session/exchange loginChallenge.challengeId',
          ),
          ...(readOptionalString(loginChallengeRaw?.emailHint)
            ? { emailHint: readOptionalString(loginChallengeRaw?.emailHint) }
            : {}),
          ...(readOptionalString(loginChallengeRaw?.expiresAt)
            ? { expiresAt: readOptionalString(loginChallengeRaw?.expiresAt) }
            : {}),
          ...(Number.isFinite(Number(loginChallengeRaw?.expiresAtMs))
            ? { expiresAtMs: Math.floor(Number(loginChallengeRaw?.expiresAtMs)) }
            : {}),
        }
      : loginChallengeDelivery === 'rate_limited'
        ? {
            delivery: 'rate_limited' as const,
            ...(Number.isFinite(Number(loginChallengeRaw?.retryAfterMs))
              ? { retryAfterMs: Math.floor(Number(loginChallengeRaw?.retryAfterMs)) }
              : {}),
            ...(Number.isFinite(Number(loginChallengeRaw?.resetAtMs))
              ? { resetAtMs: Math.floor(Number(loginChallengeRaw?.resetAtMs)) }
              : {}),
          }
        : undefined;
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
              ...(Number.isFinite(googleEmailOtpResolutionExpiresAtMs)
                ? { expiresAtMs: Math.floor(googleEmailOtpResolutionExpiresAtMs) }
                : {}),
              ...(googleEmailOtpRegistrationOffer
                ? { offer: googleEmailOtpRegistrationOffer }
                : {}),
              ...(loginChallenge ? { loginChallenge } : {}),
            },
          }
        : {}),
      ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
    },
  };
}
