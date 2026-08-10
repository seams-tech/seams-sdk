import {
  EMAIL_OTP_CHANNEL,
  WALLET_EMAIL_OTP_REGISTRATION_OPERATION,
  WALLET_EMAIL_OTP_UNLOCK_OPERATION,
  type WalletEmailOtpChannel,
} from '@shared/utils/emailOtpDomain';
import { requireTrimmedString, toOptionalTrimmedNonEmptyString } from '@shared/utils/validation';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import type {
  EmailOtpWalletRegistrationEcdsaPrepareHandleRequest,
  EmailOtpWalletRegistrationEcdsaPrepareHandlePayload,
  EmailOtpWalletRegistrationEcdsaPrepareHandleResult,
} from '@/core/signingEngine/workerManager/workerTypes';
import {
  thresholdEcdsaChainTargetFromRequest,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  buildEmailOtpRoutePlan,
  requireEmailOtpAuthLane,
  resolveEmailOtpAuthLane,
  type EmailOtpRouteFamily,
} from '@/core/signingEngine/stepUpConfirmation/otpPrompt/authLane';
import type { EmailOtpEnrollmentResult } from './publicTypes';
import { zeroizeBytes } from './zeroize';

type JsonObject = Record<string, unknown>;

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
  routeFamily: Extract<EmailOtpRouteFamily, 'login' | 'registration'>;
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
    operation:
      args.routeFamily === 'registration'
        ? WALLET_EMAIL_OTP_REGISTRATION_OPERATION
        : WALLET_EMAIL_OTP_UNLOCK_OPERATION,
  });
}

function parseEmailOtpEnrollmentResult(value: unknown): EmailOtpEnrollmentResult {
  const response = requireObjectJson(value, 'Email OTP enrollment result');
  return {
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

function parseEmailOtpWalletRegistrationEcdsaPrepareHandle(
  value: unknown,
): EmailOtpWalletRegistrationEcdsaPrepareHandlePayload {
  const response = requireObjectJson(value, 'Email OTP registration ECDSA handle');
  const kind = readString(response.kind, 'emailOtpSessionHandle.handle.kind');
  if (kind !== 'email_otp_worker_session_handle_v1') {
    throw new Error(`Unsupported Email OTP worker handle kind: ${kind}`);
  }
  const action = readString(response.action, 'emailOtpSessionHandle.handle.action');
  if (action !== 'wallet_registration_ecdsa_prepare') {
    throw new Error(`Unsupported Email OTP worker handle action: ${action}`);
  }
  const operation = readString(response.operation, 'emailOtpSessionHandle.handle.operation');
  if (operation !== 'registration') {
    throw new Error('Email OTP registration ECDSA handle requires registration operation');
  }
  const keyScope = readString(response.keyScope, 'emailOtpSessionHandle.handle.keyScope');
  if (keyScope !== 'evm-family') {
    throw new Error('Email OTP registration ECDSA handle requires evm-family keyScope');
  }
  return {
    kind: 'email_otp_worker_session_handle_v1',
    sessionId: readString(response.sessionId, 'emailOtpSessionHandle.handle.sessionId'),
    walletId: readString(response.walletId, 'emailOtpSessionHandle.handle.walletId'),
    evmFamilySigningKeySlotId: readString(
      response.evmFamilySigningKeySlotId,
      'emailOtpSessionHandle.handle.evmFamilySigningKeySlotId',
    ),
    authSubjectId: readString(response.authSubjectId, 'emailOtpSessionHandle.handle.authSubjectId'),
    action: 'wallet_registration_ecdsa_prepare',
    operation: 'registration',
    keyScope: 'evm-family',
    chainTarget: parseThresholdEcdsaChainTargetForWorkerEnrollment(response.chainTarget),
  };
}

function parseThresholdEcdsaChainTargetForWorkerEnrollment(
  value: unknown,
): ThresholdEcdsaChainTarget {
  const target = value && typeof value === 'object' ? (value as Record<string, unknown>) : null;
  if (!target) {
    throw new Error('Email OTP registration ECDSA handle requires chainTarget');
  }
  return thresholdEcdsaChainTargetFromRequest(target);
}

function parseEmailOtpWalletRegistrationEcdsaPrepareHandleResult(
  value: unknown,
): EmailOtpWalletRegistrationEcdsaPrepareHandleResult {
  const response = requireObjectJson(value, 'Email OTP registration ECDSA handle result');
  const kind = readString(response.kind, 'emailOtpSessionHandle.kind');
  switch (kind) {
    case 'available':
      if (!Array.isArray(response.handles) || response.handles.length === 0) {
        throw new Error('Email OTP registration ECDSA handle result requires handles');
      }
      {
        const handles: EmailOtpWalletRegistrationEcdsaPrepareHandlePayload[] = [];
        for (const handle of response.handles) {
          handles.push(parseEmailOtpWalletRegistrationEcdsaPrepareHandle(handle));
        }
        const first = handles[0];
        if (!first) {
          throw new Error('Email OTP registration ECDSA handle result requires handles');
        }
        return {
          kind: 'available',
          handles: [first, ...handles.slice(1)],
        };
      }
    case 'not_requested':
      if ('handles' in response) {
        throw new Error('Email OTP unrequested registration ECDSA handle result forbids handles');
      }
      return { kind: 'not_requested' };
    default:
      throw new Error(`Unsupported Email OTP registration ECDSA handle result kind: ${kind}`);
  }
}

export async function enrollEmailOtpWallet(args: {
  relayUrl: string;
  walletId: string;
  userId: string;
  challengeId?: string;
  otpCode: string;
  groupId: string;
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
            groupId: readString(args.groupId, 'groupId'),
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
  groupId: string;
  workerCtx: WorkerOperationContext;
  appSessionJwt?: string;
  otpChannel?: WalletEmailOtpChannel;
  clientSecret32?: Uint8Array;
  ecdsaSessionHandle: EmailOtpWalletRegistrationEcdsaPrepareHandleRequest;
}): Promise<{
  otpChannel: WalletEmailOtpChannel;
  enrollmentId: string;
  enrollmentSealKeyVersion: string;
  clientUnlockPublicKeyB64u: string;
  unlockKeyVersion: string;
  emailOtpSessionHandle: EmailOtpWalletRegistrationEcdsaPrepareHandleResult;
  emailOtpEnrollment: {
    enrollmentSealKeyVersion: string;
    clientUnlockPublicKeyB64u: string;
    unlockKeyVersion: string;
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
          groupId: readString(args.groupId, 'groupId'),
          routePlan: buildWorkerEmailOtpRoutePlan({
            routeFamily: 'registration',
            appSessionJwt: args.appSessionJwt,
          }),
          otpChannel: args.otpChannel || EMAIL_OTP_CHANNEL,
          ecdsaSessionHandle: args.ecdsaSessionHandle,
          ...(workerClientSecret32
            ? { clientSecret32: toArrayBufferCopy(workerClientSecret32) }
            : {}),
        },
      },
    });
    return {
      ...result,
      emailOtpSessionHandle: parseEmailOtpWalletRegistrationEcdsaPrepareHandleResult(
        result.emailOtpSessionHandle,
      ),
      emailOtpEnrollment: result.emailOtpEnrollment,
    };
  } finally {
    zeroizeBytes(workerClientSecret32);
  }
}
