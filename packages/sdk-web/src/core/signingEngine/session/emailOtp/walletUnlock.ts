import type { WalletSessionRef } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import type {
  EmailOtpEcdsaSessionBootstrapHandleBinding,
  EmailOtpEcdsaSessionBootstrapHandlePayload,
  EmailOtpWorkerProgressEvent,
} from '@/core/signingEngine/workerManager/workerTypes';
import type { EmailOtpRoutePlan } from '../../stepUpConfirmation/otpPrompt/authLane';
import type { ThresholdRuntimePolicyScope } from '../../threshold/sessionPolicy';
import { EMAIL_OTP_CHANNEL } from '@shared/utils/emailOtpDomain';

export type EmailOtpWalletUnlockRecovery = {
  challengeId: string;
  enrollmentSealKeyVersion: string;
  unlockChallengeId: string;
  unlockChallengeB64u: string;
  clientUnlockPublicKeyB64u: string;
  unlockSignatureB64u: string;
  thresholdEd25519RecoveryCodeSecret32B64u: string;
};

export type EmailOtpWalletUnlockResult = {
  recovery: EmailOtpWalletUnlockRecovery;
  clientRootShareHandle: EmailOtpEcdsaSessionBootstrapHandlePayload;
};

type EmailOtpWalletUnlockBaseArgs = {
  walletSession: WalletSessionRef;
  relayUrl: string;
  shamirPrimeB64u: string;
  otpCode: string;
  routePlan: EmailOtpRoutePlan;
  workerCtx: WorkerOperationContext;
  challengeId?: string;
  onProgress?: (progress: EmailOtpWorkerProgressEvent) => void;
  runtimePolicyScope: ThresholdRuntimePolicyScope;
};

export async function unlockEmailOtpWalletForEd25519Session(
  args: EmailOtpWalletUnlockBaseArgs,
): Promise<{ recovery: EmailOtpWalletUnlockRecovery }> {
  const result = await args.workerCtx.requestWorkerOperation({
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
        runtimePolicyScope: args.runtimePolicyScope,
      },
      onEvent: args.onProgress,
    },
  });
  const thresholdEd25519RecoveryCodeSecret32B64u = String(
    result.recovery?.thresholdEd25519RecoveryCodeSecret32B64u || '',
  ).trim();
  if (!thresholdEd25519RecoveryCodeSecret32B64u) {
    throw new Error('Email OTP wallet unlock did not return Ed25519 recovery-code material');
  }
  return {
    recovery: result.recovery,
  };
}

export async function unlockEmailOtpWallet(
  args: EmailOtpWalletUnlockBaseArgs & {
    ecdsaClientRootHandleBinding: EmailOtpEcdsaSessionBootstrapHandleBinding;
  },
): Promise<EmailOtpWalletUnlockResult> {
  const result = await args.workerCtx.requestWorkerOperation({
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
        ecdsaClientRootHandleBinding: args.ecdsaClientRootHandleBinding,
        runtimePolicyScope: args.runtimePolicyScope,
      },
      onEvent: args.onProgress,
    },
  });
  if (!result.clientRootShareHandle) {
    throw new Error('Email OTP wallet unlock did not return an ECDSA client-root worker handle');
  }
  return {
    recovery: result.recovery,
    clientRootShareHandle: result.clientRootShareHandle,
  };
}
