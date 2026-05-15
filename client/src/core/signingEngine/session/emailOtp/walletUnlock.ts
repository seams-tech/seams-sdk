import type { WalletSessionRef } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import type { EmailOtpWorkerProgressEvent } from '@/core/signingEngine/workerManager/workerTypes';
import type { EmailOtpRoutePlan } from '../../stepUpConfirmation/otpPrompt/authLane';
import { EMAIL_OTP_CHANNEL } from '@shared/utils/emailOtpDomain';

export type EmailOtpWalletUnlockRecovery = {
  challengeId: string;
  enrollmentSealKeyVersion: string;
  unlockChallengeId: string;
  unlockChallengeB64u: string;
  clientUnlockPublicKeyB64u: string;
  unlockSignatureB64u: string;
  thresholdEd25519PrfFirstB64u: string;
};

export type EmailOtpWalletUnlockResult = {
  recovery: EmailOtpWalletUnlockRecovery;
  clientRootShare32B64u: string;
};

export async function unlockEmailOtpWallet(args: {
  walletSession: WalletSessionRef;
  relayUrl: string;
  shamirPrimeB64u: string;
  otpCode: string;
  routePlan: EmailOtpRoutePlan;
  workerCtx: WorkerOperationContext;
  challengeId?: string;
  onProgress?: (progress: EmailOtpWorkerProgressEvent) => void;
  runtimePolicyScope?: {
    orgId: string;
    projectId: string;
    envId: string;
    signingRootVersion: string;
  };
}): Promise<EmailOtpWalletUnlockResult> {
  return await args.workerCtx.requestWorkerOperation({
    kind: 'emailOtp',
    request: {
      type: 'loginWithEmailOtpWallet',
      timeoutMs: 60_000,
      payload: {
        relayUrl: args.relayUrl,
        walletId: String(args.walletSession.walletId),
        userId: String(args.walletSession.walletSessionUserId),
        ...(args.challengeId ? { challengeId: args.challengeId } : {}),
        otpCode: args.otpCode,
        shamirPrimeB64u: args.shamirPrimeB64u,
        routePlan: args.routePlan,
        otpChannel: EMAIL_OTP_CHANNEL,
        ...(args.runtimePolicyScope ? { runtimePolicyScope: args.runtimePolicyScope } : {}),
      },
      onEvent: args.onProgress,
    },
  });
}
