import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import type {
  EmailOtpDeviceEnrollmentRemoveResult,
  EmailOtpDeviceEnrollmentRestoreResult,
} from '@/core/signingEngine/session/emailOtp/publicTypes';
import {
  EMAIL_OTP_CHANNEL,
  buildWorkerEmailOtpRoutePlan,
  readOptionalString,
  readString,
  requireWorkerCtx,
  type WalletEmailOtpChannel,
} from './challenge';

export type {
  EmailOtpDeviceEnrollmentRemoveResult,
  EmailOtpDeviceEnrollmentRestoreResult,
} from '@/core/signingEngine/session/emailOtp/publicTypes';

export async function restoreEmailOtpDeviceEnrollmentEscrow(args: {
  relayUrl: string;
  walletId: string;
  userId: string;
  challengeId: string;
  otpCode: string;
  recoveryKey: string;
  shamirPrimeB64u: string;
  workerCtx: WorkerOperationContext;
  appSessionJwt?: string;
  otpChannel?: WalletEmailOtpChannel;
}): Promise<EmailOtpDeviceEnrollmentRestoreResult> {
  const workerCtx = requireWorkerCtx(args.workerCtx);
  return await workerCtx.requestWorkerOperation({
    kind: 'emailOtp',
    request: {
      type: 'restoreEmailOtpDeviceEnrollmentEscrow',
      payload: {
        relayUrl: readString(args.relayUrl, 'relayUrl'),
        walletId: readString(args.walletId, 'walletId'),
        userId: readString(args.userId, 'userId'),
        challengeId: readString(args.challengeId, 'challengeId'),
        otpCode: readString(args.otpCode, 'otpCode'),
        recoveryKey: readString(args.recoveryKey, 'recoveryKey'),
        shamirPrimeB64u: readString(args.shamirPrimeB64u, 'shamirPrimeB64u'),
        routePlan: buildWorkerEmailOtpRoutePlan({
          routeFamily: 'login',
          appSessionJwt: args.appSessionJwt,
        }),
        otpChannel: EMAIL_OTP_CHANNEL,
      },
    },
  });
}

export async function removeEmailOtpDeviceEnrollmentEscrowFromDevice(args: {
  walletId: string;
  userId: string;
  enrollmentId?: string;
  workerCtx: WorkerOperationContext;
}): Promise<EmailOtpDeviceEnrollmentRemoveResult> {
  const workerCtx = requireWorkerCtx(args.workerCtx);
  return await workerCtx.requestWorkerOperation({
    kind: 'emailOtp',
    request: {
      type: 'removeEmailOtpDeviceEnrollmentEscrowFromDevice',
      payload: {
        walletId: readString(args.walletId, 'walletId'),
        userId: readString(args.userId, 'userId'),
        ...(readOptionalString(args.enrollmentId)
          ? { enrollmentId: readOptionalString(args.enrollmentId) }
          : {}),
      },
    },
  });
}
