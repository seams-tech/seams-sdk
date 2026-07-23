import type { WalletSessionRef } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import type {
  EmailOtpEd25519YaoRecoveryBootstrapV1,
  EmailOtpEd25519YaoExactLocalSessionBootstrapV1,
  EmailOtpEcdsaSessionBootstrapHandleBinding,
  EmailOtpEcdsaSessionBootstrapHandlePayload,
  EmailOtpWorkerProgressEvent,
  EmailOtpWalletUnlockMaterialRequest,
} from '@/core/signingEngine/workerManager/workerTypes';
import type { RouterAbEd25519YaoActiveClientMetadataV1 } from '../../threshold/ed25519/yaoClient';
import type { EmailOtpRoutePlan } from '../../stepUpConfirmation/otpPrompt/authLane';
import type { ThresholdRuntimePolicyScope } from '../../threshold/sessionPolicy';
import { EMAIL_OTP_CHANNEL } from '@shared/utils/emailOtpDomain';
import { ROUTER_AB_ED25519_YAO_EMAIL_OTP_RECOVERY_BOOTSTRAP_KIND_V1 } from '@shared/utils/routerAbEd25519Yao';

export type EmailOtpWalletUnlockRecovery = {
  challengeId: string;
  enrollmentSealKeyVersion: string;
  unlockChallengeId: string;
  unlockChallengeB64u: string;
  clientUnlockPublicKeyB64u: string;
  unlockSignatureB64u: string;
};

export type EmailOtpWalletUnlockResult = {
  kind: 'ecdsa';
  recovery: EmailOtpWalletUnlockRecovery;
  clientRootShareHandle: EmailOtpEcdsaSessionBootstrapHandlePayload;
};

export type EmailOtpEd25519YaoUnlockResult =
  | {
      kind: 'ed25519_yao_recovery';
      recovery: EmailOtpWalletUnlockRecovery;
      pendingFactorHandle: import('./ed25519YaoRootVault').EmailOtpEd25519YaoPendingFactorHandle;
      ed25519YaoRecovery: EmailOtpEd25519YaoRecoveryBootstrapV1;
    }
  | {
      kind: 'ed25519_yao_local_session';
      recovery: EmailOtpWalletUnlockRecovery;
      activeClientHandle: string;
      metadata: RouterAbEd25519YaoActiveClientMetadataV1;
      ed25519YaoSession: EmailOtpEd25519YaoExactLocalSessionBootstrapV1;
    };

export type EmailOtpEd25519YaoExactLocalUnlockResult = {
  kind: 'ed25519_yao_local_session';
  recovery: EmailOtpWalletUnlockRecovery;
  activeClientHandle: string;
  metadata: RouterAbEd25519YaoActiveClientMetadataV1;
  ed25519YaoSession: EmailOtpEd25519YaoExactLocalSessionBootstrapV1;
};

export type EmailOtpMixedWalletUnlockResult =
  | {
      kind: 'ecdsa_and_ed25519_yao_recovery';
      recovery: EmailOtpWalletUnlockRecovery;
      clientRootShareHandle: EmailOtpEcdsaSessionBootstrapHandlePayload;
      pendingFactorHandle: import('./ed25519YaoRootVault').EmailOtpEd25519YaoPendingFactorHandle;
      ed25519YaoRecovery: EmailOtpEd25519YaoRecoveryBootstrapV1;
    }
  | {
      kind: 'ecdsa_and_ed25519_yao_local_session';
      recovery: EmailOtpWalletUnlockRecovery;
      clientRootShareHandle: EmailOtpEcdsaSessionBootstrapHandlePayload;
      activeClientHandle: string;
      metadata: RouterAbEd25519YaoActiveClientMetadataV1;
      ed25519YaoSession: EmailOtpEd25519YaoExactLocalSessionBootstrapV1;
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
};

async function requestEmailOtpWalletUnlock(args: {
  base: EmailOtpWalletUnlockBaseArgs;
  material: EmailOtpWalletUnlockMaterialRequest;
}) {
  return await args.base.workerCtx.requestWorkerOperation({
    kind: 'emailOtp',
    request: {
      type: 'loginWithEmailOtpWallet',
      timeoutMs: 60_000,
      payload: {
        relayUrl: args.base.relayUrl,
        walletId: String(args.base.walletSession.walletId),
        userId: String(args.base.walletSession.walletSessionUserId),
        ...(args.base.challengeId ? { challengeId: args.base.challengeId } : {}),
        otpCode: args.base.otpCode,
        shamirPrimeB64u: args.base.shamirPrimeB64u,
        routePlan: args.base.routePlan,
        otpChannel: EMAIL_OTP_CHANNEL,
        material: args.material,
      },
      onEvent: args.base.onProgress,
    },
  });
}

export async function unlockEmailOtpWallet(
  args: EmailOtpWalletUnlockBaseArgs & {
    ecdsaClientRootHandleBinding: EmailOtpEcdsaSessionBootstrapHandleBinding;
    runtimePolicyScope: ThresholdRuntimePolicyScope;
  },
): Promise<EmailOtpWalletUnlockResult> {
  const result = await requestEmailOtpWalletUnlock({
    base: args,
    material: {
      kind: 'ecdsa',
      ecdsaClientRootHandleBinding: args.ecdsaClientRootHandleBinding,
      runtimePolicyScope: args.runtimePolicyScope,
    },
  });
  if (result.kind !== 'ecdsa') {
    throw new Error('Email OTP wallet unlock returned the wrong material branch');
  }
  return {
    kind: 'ecdsa',
    recovery: result.recovery,
    clientRootShareHandle: result.clientRootShareHandle,
  };
}

export async function unlockEmailOtpEd25519YaoSession(
  args: EmailOtpWalletUnlockBaseArgs & {
    providerSubject: string;
    signerSlot: number;
    remainingUses: number;
    orgId: string;
    nearAccountId: string;
    expectedOperationalPublicKey: string;
    expectedThresholdSessionId: string;
  },
): Promise<EmailOtpEd25519YaoUnlockResult> {
  const result = await requestEmailOtpWalletUnlock({
    base: args,
    material: {
      kind: 'ed25519_yao_recovery',
      providerSubject: args.providerSubject,
      nearAccountId: args.nearAccountId,
      expectedOperationalPublicKey: args.expectedOperationalPublicKey,
      expectedThresholdSessionId: args.expectedThresholdSessionId,
      ed25519YaoRecovery: {
        kind: ROUTER_AB_ED25519_YAO_EMAIL_OTP_RECOVERY_BOOTSTRAP_KIND_V1,
        signerSlot: args.signerSlot,
        remainingUses: args.remainingUses,
        orgId: args.orgId,
      },
    },
  });
  if (result.kind === 'ed25519_yao_local_session') {
    return {
      kind: result.kind,
      recovery: result.recovery,
      activeClientHandle: result.activeClientHandle,
      metadata: result.metadata,
      ed25519YaoSession: result.ed25519YaoSession,
    };
  }
  if (result.kind !== 'ed25519_yao_recovery') {
    throw new Error('Email OTP Ed25519 Yao unlock returned the wrong material branch');
  }
  return {
    kind: 'ed25519_yao_recovery',
    recovery: result.recovery,
    pendingFactorHandle: result.pendingFactorHandle,
    ed25519YaoRecovery: result.ed25519YaoRecovery,
  };
}

export async function unlockEmailOtpEd25519YaoExactLocalSession(
  args: EmailOtpWalletUnlockBaseArgs & {
    providerSubject: string;
    signerSlot: number;
    remainingUses: number;
    orgId: string;
    nearAccountId: string;
    expectedOperationalPublicKey: string;
    expectedThresholdSessionId: string;
  },
): Promise<EmailOtpEd25519YaoExactLocalUnlockResult> {
  const result = await requestEmailOtpWalletUnlock({
    base: args,
    material: {
      kind: 'ed25519_yao_exact_local_session',
      providerSubject: args.providerSubject,
      nearAccountId: args.nearAccountId,
      expectedOperationalPublicKey: args.expectedOperationalPublicKey,
      expectedThresholdSessionId: args.expectedThresholdSessionId,
      ed25519YaoSession: {
        kind: 'exact_local_material_session_v1',
        signerSlot: args.signerSlot,
        remainingUses: args.remainingUses,
        orgId: args.orgId,
      },
    },
  });
  if (result.kind !== 'ed25519_yao_local_session') {
    throw new Error('Email OTP exact-local Ed25519 unlock returned the wrong material branch');
  }
  return {
    kind: 'ed25519_yao_local_session',
    recovery: result.recovery,
    activeClientHandle: result.activeClientHandle,
    metadata: result.metadata,
    ed25519YaoSession: result.ed25519YaoSession,
  };
}

export async function unlockEmailOtpMixedWallet(
  args: EmailOtpWalletUnlockBaseArgs & {
    ecdsaClientRootHandleBinding: EmailOtpEcdsaSessionBootstrapHandleBinding;
    runtimePolicyScope: ThresholdRuntimePolicyScope;
    providerSubject: string;
    signerSlot: number;
    remainingUses: number;
    nearAccountId: string;
    expectedOperationalPublicKey: string;
    expectedThresholdSessionId: string;
  },
): Promise<EmailOtpMixedWalletUnlockResult> {
  const result = await requestEmailOtpWalletUnlock({
    base: args,
    material: {
      kind: 'ecdsa_and_ed25519_yao_recovery',
      ecdsaClientRootHandleBinding: args.ecdsaClientRootHandleBinding,
      runtimePolicyScope: args.runtimePolicyScope,
      providerSubject: args.providerSubject,
      nearAccountId: args.nearAccountId,
      expectedOperationalPublicKey: args.expectedOperationalPublicKey,
      expectedThresholdSessionId: args.expectedThresholdSessionId,
      ed25519YaoRecovery: {
        kind: ROUTER_AB_ED25519_YAO_EMAIL_OTP_RECOVERY_BOOTSTRAP_KIND_V1,
        signerSlot: args.signerSlot,
        remainingUses: args.remainingUses,
        orgId: args.runtimePolicyScope.orgId,
      },
    },
  });
  if (result.kind === 'ecdsa_and_ed25519_yao_local_session') {
    return {
      kind: result.kind,
      recovery: result.recovery,
      clientRootShareHandle: result.clientRootShareHandle,
      activeClientHandle: result.activeClientHandle,
      metadata: result.metadata,
      ed25519YaoSession: result.ed25519YaoSession,
    };
  }
  if (result.kind !== 'ecdsa_and_ed25519_yao_recovery') {
    throw new Error('Mixed Email OTP unlock returned the wrong material branch');
  }
  return {
    kind: 'ecdsa_and_ed25519_yao_recovery',
    recovery: result.recovery,
    clientRootShareHandle: result.clientRootShareHandle,
    pendingFactorHandle: result.pendingFactorHandle,
    ed25519YaoRecovery: result.ed25519YaoRecovery,
  };
}
