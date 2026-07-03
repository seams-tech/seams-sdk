import {
  EMAIL_OTP_CHANNEL,
  type WalletEmailOtpChannel,
} from '@shared/utils/emailOtpDomain';
import {
  buildEmailOtpRecoveryCodeSet,
  type EmailOtpRecoveryCodeSet,
} from '@shared/utils/emailOtpRecoveryKey';
import { requireTrimmedString, toOptionalTrimmedNonEmptyString } from '@shared/utils/validation';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import type {
  EmailOtpWalletRegistrationEcdsaPrepareHandleBinding,
  EmailOtpWalletRegistrationEcdsaPrepareHandlePayload,
} from '@/core/signingEngine/workerManager/workerTypes';
import {
  buildEmailOtpRoutePlan,
  requireEmailOtpAuthLane,
  resolveEmailOtpAuthLane,
  type EmailOtpRouteFamily,
} from '@/core/signingEngine/stepUpConfirmation/otpPrompt/authLane';
import type { EmailOtpEnrollmentResult } from './publicTypes';
import type { EmailOtpRecoveryCodeRotationMaterial } from './publicTypes';

type JsonObject = Record<string, unknown>;

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

function parseEmailOtpRecoveryCodeMaterial(value: unknown): {
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

function readString(value: unknown, label: string): string {
  return requireTrimmedString(value, label);
}

function readOptionalString(value: unknown): string | undefined {
  return toOptionalTrimmedNonEmptyString(value);
}

function readNonNegativeInteger(value: unknown, label: string): number {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed < 0) {
    throw new Error(`${label} must be a non-negative integer`);
  }
  return Math.floor(parsed);
}

function zeroizeBytes(bytes?: Uint8Array | null): void {
  if (!(bytes instanceof Uint8Array)) return;
  bytes.fill(0);
}

function toArrayBufferCopy(bytes: Uint8Array): ArrayBuffer {
  const out = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(out).set(bytes);
  return out;
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

function buildWorkerEmailOtpRoutePlan(args: {
  routeFamily: EmailOtpRouteFamily;
  appSessionJwt?: string;
}) {
  const appSessionJwt = readOptionalString(args.appSessionJwt);
  return buildEmailOtpRoutePlan({
    routeFamily: args.routeFamily,
    authLane: requireEmailOtpAuthLane(
      resolveEmailOtpAuthLane({
        sessionKind: appSessionJwt ? 'jwt' : 'cookie',
        ...(appSessionJwt ? { appSessionJwt } : {}),
      }),
      'worker route plan',
    ),
  });
}

function parseEmailOtpEnrollmentResult(value: unknown): EmailOtpEnrollmentResult {
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

function parseEmailOtpRecoveryCodeRotationMaterial(
  value: unknown,
): EmailOtpRecoveryCodeRotationMaterial {
  const response = requireObjectJson(value, 'Email OTP recovery-code rotation result');
  const recoveryCodeMaterial = parseEmailOtpRecoveryCodeMaterial(response);
  return {
    walletId: readString(response.walletId, 'walletId'),
    userId: readString(response.userId, 'userId'),
    providerUserId: readString(response.authSubjectId, 'authSubjectId'),
    enrollmentId: readString(response.enrollmentId, 'enrollmentId'),
    enrollmentVersion: readString(response.enrollmentVersion, 'enrollmentVersion'),
    enrollmentSealKeyVersion: readString(
      response.enrollmentSealKeyVersion,
      'enrollmentSealKeyVersion',
    ),
    recoveryKeys: recoveryCodeMaterial.recoveryKeys,
    recoveryCodesIssuedAtMs: recoveryCodeMaterial.recoveryCodesIssuedAtMs,
    activeRecoveryCodeCount: readNonNegativeInteger(
      response.activeRecoveryCodeCount,
      'activeRecoveryCodeCount',
    ),
    revokedRecoveryCodeCount: readNonNegativeInteger(
      response.revokedRecoveryCodeCount,
      'revokedRecoveryCodeCount',
    ),
    totalRecoveryCodeCount: readNonNegativeInteger(
      response.totalRecoveryCodeCount,
      'totalRecoveryCodeCount',
    ),
  };
}

export async function enrollEmailOtpWallet(args: {
  relayUrl: string;
  walletId: string;
  userId: string;
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
    return parseEmailOtpEnrollmentResult(
      await workerCtx.requestWorkerOperation({
        kind: 'emailOtp',
        request: {
            type: 'enrollEmailOtpWallet',
            payload: {
              relayUrl: readString(args.relayUrl, 'relayUrl'),
              walletId: readString(args.walletId, 'walletId'),
              userId: readString(args.userId, 'userId'),
            ...(readOptionalString(args.challengeId)
              ? { challengeId: readOptionalString(args.challengeId) }
              : {}),
            otpCode: readString(args.otpCode, 'otpCode'),
            shamirPrimeB64u: readString(args.shamirPrimeB64u, 'shamirPrimeB64u'),
            routePlan: buildWorkerEmailOtpRoutePlan({
              routeFamily: 'registration',
              appSessionJwt: args.appSessionJwt,
            }),
            otpChannel: args.otpChannel || EMAIL_OTP_CHANNEL,
            ...(workerClientSecret32
              ? { clientSecret32: toArrayBufferCopy(workerClientSecret32) }
              : {}),
          },
        },
      }),
    );
  } finally {
    zeroizeBytes(workerClientSecret32);
  }
}

export async function prepareEmailOtpRegistrationEnrollmentMaterial(args: {
  relayUrl: string;
  walletId: string;
  userId: string;
  shamirPrimeB64u: string;
  workerCtx: WorkerOperationContext;
  appSessionJwt?: string;
  otpChannel?: WalletEmailOtpChannel;
  clientSecret32?: Uint8Array;
  ecdsaClientRootHandleBinding: EmailOtpWalletRegistrationEcdsaPrepareHandleBinding;
}): Promise<{
  thresholdEcdsaClientVerifyingShareB64u: string;
  thresholdEd25519RecoveryCodeSecret32B64u: string;
  recoveryKeys: EmailOtpRecoveryCodeSet;
  recoveryCodesIssuedAtMs: number;
  otpChannel: WalletEmailOtpChannel;
  enrollmentId: string;
  enrollmentSealKeyVersion: string;
  clientUnlockPublicKeyB64u: string;
  unlockKeyVersion: string;
  clientRootShareHandle: EmailOtpWalletRegistrationEcdsaPrepareHandlePayload;
  emailOtpEnrollment: {
    recoveryWrappedEnrollmentEscrows: unknown[];
    enrollmentSealKeyVersion: string;
    clientUnlockPublicKeyB64u: string;
    unlockKeyVersion: string;
    thresholdEcdsaClientVerifyingShareB64u: string;
  };
}> {
  const workerCtx = requireWorkerCtx(args.workerCtx);
  let workerClientSecret32: Uint8Array | null = null;
  try {
    workerClientSecret32 = args.clientSecret32
      ? cloneFixed32Bytes(args.clientSecret32, 'clientSecret32')
      : null;
    const result = await workerCtx.requestWorkerOperation({
      kind: 'emailOtp',
      request: {
        type: 'prepareEmailOtpRegistrationEnrollmentMaterial',
        payload: {
          relayUrl: readString(args.relayUrl, 'relayUrl'),
          walletId: readString(args.walletId, 'walletId'),
          userId: readString(args.userId, 'userId'),
          shamirPrimeB64u: readString(args.shamirPrimeB64u, 'shamirPrimeB64u'),
          routePlan: buildWorkerEmailOtpRoutePlan({
            routeFamily: 'registration',
            appSessionJwt: args.appSessionJwt,
          }),
          otpChannel: args.otpChannel || EMAIL_OTP_CHANNEL,
          ecdsaClientRootHandleBinding: args.ecdsaClientRootHandleBinding,
          ...(workerClientSecret32
            ? { clientSecret32: toArrayBufferCopy(workerClientSecret32) }
            : {}),
        },
      },
    });
    const recoveryCodeMaterial = parseEmailOtpRecoveryCodeMaterial(result);
    return {
      ...result,
      recoveryKeys: recoveryCodeMaterial.recoveryKeys,
      recoveryCodesIssuedAtMs: recoveryCodeMaterial.recoveryCodesIssuedAtMs,
      thresholdEd25519RecoveryCodeSecret32B64u: readString(
        result.thresholdEd25519RecoveryCodeSecret32B64u,
        'thresholdEd25519RecoveryCodeSecret32B64u',
      ),
      clientRootShareHandle: result.clientRootShareHandle,
      emailOtpEnrollment: result.emailOtpEnrollment,
    };
  } finally {
    zeroizeBytes(workerClientSecret32);
  }
}

export async function rotateEmailOtpRecoveryCodesWithWorker(args: {
  relayUrl: string;
  walletId: string;
  userId: string;
  workerCtx: WorkerOperationContext;
  appSessionJwt?: string;
}): Promise<EmailOtpRecoveryCodeRotationMaterial> {
  const workerCtx = requireWorkerCtx(args.workerCtx);
  return parseEmailOtpRecoveryCodeRotationMaterial(
    await workerCtx.requestWorkerOperation({
      kind: 'emailOtp',
      request: {
        type: 'rotateEmailOtpRecoveryCodes',
        payload: {
          relayUrl: readString(args.relayUrl, 'relayUrl'),
          walletId: readString(args.walletId, 'walletId'),
          userId: readString(args.userId, 'userId'),
          routePlan: buildWorkerEmailOtpRoutePlan({
            routeFamily: 'login',
            appSessionJwt: args.appSessionJwt,
          }),
        },
      },
    }),
  );
}
