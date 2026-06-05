import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import type {
  EmailOtpWalletRegistrationEcdsaPrepareHandleBinding,
  EmailOtpWalletRegistrationEcdsaPrepareHandlePayload,
} from '@/core/signingEngine/workerManager/workerTypes';
import {
  EMAIL_OTP_CHANNEL,
  buildWorkerEmailOtpRoutePlan,
  cloneFixed32Bytes,
  parseEmailOtpEnrollmentResult,
  parseEmailOtpRecoveryCodeMaterial,
  readOptionalString,
  readString,
  requireWorkerCtx,
  zeroizeBytes,
  type EmailOtpEnrollmentResult,
  type WalletEmailOtpChannel,
  type EmailOtpRecoveryCodeSet,
} from './challenge';

export type { EmailOtpEnrollmentResult } from './challenge';

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
    return parseEmailOtpEnrollmentResult(
      await workerCtx.requestWorkerOperation({
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
          ...(workerClientSecret32 ? { clientSecret32: workerClientSecret32.buffer.slice(0) } : {}),
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
  userId?: string;
  shamirPrimeB64u: string;
  workerCtx: WorkerOperationContext;
  appSessionJwt?: string;
  otpChannel?: WalletEmailOtpChannel;
  clientSecret32?: Uint8Array;
  ecdsaClientRootHandleBinding: EmailOtpWalletRegistrationEcdsaPrepareHandleBinding;
}): Promise<{
  thresholdEcdsaClientVerifyingShareB64u: string;
  thresholdEd25519PrfFirstB64u: string;
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
          ...(readOptionalString(args.userId) ? { userId: readOptionalString(args.userId) } : {}),
          shamirPrimeB64u: readString(args.shamirPrimeB64u, 'shamirPrimeB64u'),
          routePlan: buildWorkerEmailOtpRoutePlan({
            routeFamily: 'registration',
            appSessionJwt: args.appSessionJwt,
          }),
          otpChannel: EMAIL_OTP_CHANNEL,
          ecdsaClientRootHandleBinding: args.ecdsaClientRootHandleBinding,
          ...(workerClientSecret32 ? { clientSecret32: workerClientSecret32.buffer.slice(0) } : {}),
        },
      },
    });
    const recoveryCodeMaterial = parseEmailOtpRecoveryCodeMaterial(result);
    return {
      ...result,
      recoveryKeys: recoveryCodeMaterial.recoveryKeys,
      recoveryCodesIssuedAtMs: recoveryCodeMaterial.recoveryCodesIssuedAtMs,
      thresholdEd25519PrfFirstB64u: readString(
        result.thresholdEd25519PrfFirstB64u,
        'thresholdEd25519PrfFirstB64u',
      ),
      clientRootShareHandle: result.clientRootShareHandle,
      emailOtpEnrollment: result.emailOtpEnrollment,
    };
  } finally {
    zeroizeBytes(workerClientSecret32);
  }
}
