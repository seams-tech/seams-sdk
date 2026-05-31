import type { EmailOtpEnrollmentResult } from '@/core/SeamsPasskey/emailOtp';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import type {
  EmailOtpEcdsaSessionBootstrapHandleBinding,
  EmailOtpEcdsaSessionBootstrapHandlePayload,
  EmailOtpWorkerProgressEvent,
} from '@/core/signingEngine/workerManager/workerTypes';
import type { WalletEmailOtpChannel } from '@shared/utils/emailOtpDomain';
import type { EmailOtpRoutePlan } from '../../stepUpConfirmation/otpPrompt/authLane';
import { EMAIL_OTP_CHANNEL } from '@shared/utils/emailOtpDomain';

export async function enrollEmailOtpWalletWithRoutePlan(args: {
  relayUrl: string;
  walletId: string;
  userId: string;
  challengeId?: string;
  otpCode: string;
  shamirPrimeB64u: string;
  routePlan: EmailOtpRoutePlan;
  workerCtx: WorkerOperationContext;
  googleEmailOtpRegistrationAttemptId?: string;
  clientSecret32?: Uint8Array;
  otpChannel?: WalletEmailOtpChannel;
  onProgress?: (progress: EmailOtpWorkerProgressEvent) => void;
  ecdsaClientRootHandleBinding: EmailOtpEcdsaSessionBootstrapHandleBinding;
}): Promise<
  EmailOtpEnrollmentResult & {
    thresholdEd25519PrfFirstB64u: string;
    clientRootShareHandle: EmailOtpEcdsaSessionBootstrapHandlePayload;
  }
> {
  let workerClientSecret32: Uint8Array | null = args.clientSecret32
    ? Uint8Array.from(args.clientSecret32)
    : null;
  try {
    const result = await args.workerCtx.requestWorkerOperation({
      kind: 'emailOtp',
      request: {
        type: 'enrollEmailOtpWallet',
        timeoutMs: 60_000,
        payload: {
          relayUrl: String(args.relayUrl).trim(),
          walletId: String(args.walletId).trim(),
          userId: String(args.userId).trim(),
          ...(args.challengeId ? { challengeId: args.challengeId } : {}),
          otpCode: args.otpCode,
          shamirPrimeB64u: args.shamirPrimeB64u,
          routePlan: args.routePlan,
          ...(args.googleEmailOtpRegistrationAttemptId
            ? { googleEmailOtpRegistrationAttemptId: args.googleEmailOtpRegistrationAttemptId }
            : {}),
          otpChannel: args.otpChannel || EMAIL_OTP_CHANNEL,
          ecdsaClientRootHandleBinding: args.ecdsaClientRootHandleBinding,
          ...(workerClientSecret32
            ? { clientSecret32: workerClientSecret32.buffer.slice(0) }
            : {}),
        },
        onEvent: args.onProgress,
      },
    });
    if (!result.clientRootShareHandle) {
      throw new Error('Email OTP enrollment did not return an ECDSA client-root worker handle');
    }
    return {
      ...result,
      clientRootShareHandle: result.clientRootShareHandle,
    };
  } finally {
    workerClientSecret32?.fill(0);
    workerClientSecret32 = null;
  }
}
