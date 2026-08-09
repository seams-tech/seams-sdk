import type { WalletSessionRef } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import type {
  EmailOtpEcdsaWalletUnlockAuthorization,
  EmailOtpEd25519YaoRecoveryBootstrapV1,
  EmailOtpEcdsaSessionBootstrapHandleBinding,
  EmailOtpEcdsaSessionBootstrapHandlePayload,
  EmailOtpWorkerProgressEvent,
  EmailOtpWalletCustodyEd25519MaterialRequest,
  EmailOtpWalletUnlockMaterialRequest,
} from '@/core/signingEngine/workerManager/workerTypes';
import type { RouterAbEd25519YaoActiveClientMetadataV1 } from '../../threshold/ed25519/yaoClient';
import type { EmailOtpRoutePlan } from '../../stepUpConfirmation/otpPrompt/authLane';
import type { ThresholdRuntimePolicyScope } from '../../threshold/sessionPolicy';
import { EMAIL_OTP_CHANNEL } from '@shared/utils/emailOtpDomain';
import { ROUTER_AB_ED25519_YAO_EMAIL_OTP_RECOVERY_BOOTSTRAP_KIND_V1 } from '@shared/utils/routerAbEd25519Yao';
import type {
  RouterAbEcdsaPostRegistrationSessionActivationRequestV1,
  RouterAbEcdsaPostRegistrationSessionActivationResponseV1,
} from '@shared/utils/routerAbEcdsaDerivation';

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
  emailOtpSessionHandle: EmailOtpEcdsaSessionBootstrapHandlePayload;
} & (
  | {
      operation: 'wallet_unlock';
      ecdsaSession: RouterAbEcdsaPostRegistrationSessionActivationResponseV1;
    }
  | {
      operation: Exclude<
        EmailOtpEcdsaSessionBootstrapHandleBinding['operation'],
        'wallet_unlock'
      >;
      ecdsaSession?: never;
    }
);

export type EmailOtpEd25519YaoUnlockResult =
  | {
      kind: 'wallet_custody_cache_absent';
      recovery: EmailOtpWalletUnlockRecovery;
      ed25519YaoRecovery: EmailOtpEd25519YaoRecoveryBootstrapV1;
    }
  | {
      kind: 'ed25519_yao_capability';
      recovery: EmailOtpWalletUnlockRecovery;
      activeClientHandle: string;
      metadata: RouterAbEd25519YaoActiveClientMetadataV1;
      ed25519YaoCapability: EmailOtpEd25519YaoRecoveryBootstrapV1;
    };

export type EmailOtpWalletUnlockCapabilityResults = {
  kind: 'wallet_unlock_capabilities';
  recovery: EmailOtpWalletUnlockRecovery;
  ecdsa: Extract<EmailOtpWalletUnlockResult, { operation: 'wallet_unlock' }>;
  ed25519Yao: EmailOtpEd25519YaoUnlockResult;
};

type EmailOtpWalletUnlockVerification =
  | {
      kind: 'otp';
      challengeId?: string;
      otpCode: string;
    }
  | {
      kind: 'email_otp_unseal_grant';
      grant: string;
      challengeId: string;
    };

type EmailOtpWalletUnlockBaseArgs = {
  walletSession: WalletSessionRef;
  relayUrl: string;
  groupId: string;
  routePlan: EmailOtpRoutePlan;
  workerCtx: WorkerOperationContext;
  onProgress?: (progress: EmailOtpWorkerProgressEvent) => void;
  verification: EmailOtpWalletUnlockVerification;
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
        verification: args.base.verification,
        groupId: args.base.groupId,
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
    runtimePolicyScope: ThresholdRuntimePolicyScope;
  } & (
      | {
          ecdsaSessionHandleBinding: Extract<
            EmailOtpWalletUnlockMaterialRequest,
            { kind: 'ecdsa'; ecdsaSessionActivation: unknown }
          >['ecdsaSessionHandleBinding'];
          ecdsaSessionActivation: RouterAbEcdsaPostRegistrationSessionActivationRequestV1;
          walletSessionAuthorization: EmailOtpEcdsaWalletUnlockAuthorization;
        }
      | {
          ecdsaSessionHandleBinding: Extract<
            EmailOtpWalletUnlockMaterialRequest,
            { kind: 'ecdsa'; ecdsaSessionActivation?: never }
          >['ecdsaSessionHandleBinding'];
          ecdsaSessionActivation?: never;
        }
    ),
): Promise<EmailOtpWalletUnlockResult> {
  const result = await requestEmailOtpWalletUnlock({
    base: args,
    material: args.ecdsaSessionActivation
      ? {
          kind: 'ecdsa',
          ecdsaSessionHandleBinding: args.ecdsaSessionHandleBinding,
          runtimePolicyScope: args.runtimePolicyScope,
          ecdsaSessionActivation: args.ecdsaSessionActivation,
          walletSessionAuthorization: args.walletSessionAuthorization,
        }
      : {
          kind: 'ecdsa',
          ecdsaSessionHandleBinding: args.ecdsaSessionHandleBinding,
          runtimePolicyScope: args.runtimePolicyScope,
        },
  });
  if (result.kind !== 'ecdsa') {
    throw new Error('Email OTP wallet unlock returned the wrong material branch');
  }
  if (args.ecdsaSessionActivation) {
    if (result.operation !== 'wallet_unlock') {
      throw new Error('Email OTP wallet unlock returned a non-unlock ECDSA result');
    }
    return {
      kind: 'ecdsa',
      operation: 'wallet_unlock',
      recovery: result.recovery,
      emailOtpSessionHandle: result.emailOtpSessionHandle,
      ecdsaSession: result.ecdsaSession,
    };
  }
  if (result.operation !== args.ecdsaSessionHandleBinding.operation) {
    throw new Error('Email OTP ECDSA result operation does not match its request');
  }
  return {
    kind: 'ecdsa',
    operation: result.operation,
    recovery: result.recovery,
    emailOtpSessionHandle: result.emailOtpSessionHandle,
  };
}

export async function unlockEmailOtpEd25519YaoCapability(
  args: EmailOtpWalletUnlockBaseArgs & {
    providerSubject: string;
    signerSlot: number;
    remainingUses: number;
    orgId: string;
    nearAccountId: string;
    expectedOperationalPublicKey: string;
    expectedThresholdSessionId: string;
    walletCustodyEd25519Material: EmailOtpWalletCustodyEd25519MaterialRequest;
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
      walletCustodyEd25519Material: args.walletCustodyEd25519Material,
      ed25519YaoRecovery: {
        kind: ROUTER_AB_ED25519_YAO_EMAIL_OTP_RECOVERY_BOOTSTRAP_KIND_V1,
        signerSlot: args.signerSlot,
        remainingUses: args.remainingUses,
        orgId: args.orgId,
      },
    },
  });
  if (result.kind === 'ed25519_yao_capability') {
    return {
      kind: result.kind,
      recovery: result.recovery,
      activeClientHandle: result.activeClientHandle,
      metadata: result.metadata,
      ed25519YaoCapability: result.ed25519YaoCapability,
    };
  }
  if (result.kind !== 'wallet_custody_cache_absent') {
    throw new Error('Email OTP Ed25519 Yao unlock returned the wrong material branch');
  }
  return {
    kind: 'wallet_custody_cache_absent',
    recovery: result.recovery,
    ed25519YaoRecovery: result.ed25519YaoRecovery,
  };
}

export async function unlockEmailOtpWalletCapabilities(
  args: EmailOtpWalletUnlockBaseArgs & {
    ecdsaSessionHandleBinding: Extract<
      EmailOtpWalletUnlockMaterialRequest,
      { kind: 'wallet_unlock_capabilities' }
    >['ecdsa']['sessionHandleBinding'];
    runtimePolicyScope: ThresholdRuntimePolicyScope;
    providerSubject: string;
    signerSlot: number;
    remainingUses: number;
    nearAccountId: string;
    expectedOperationalPublicKey: string;
    expectedThresholdSessionId: string;
    walletCustodyEd25519Material: EmailOtpWalletCustodyEd25519MaterialRequest;
    ecdsaSessionActivation: RouterAbEcdsaPostRegistrationSessionActivationRequestV1;
  },
): Promise<EmailOtpWalletUnlockCapabilityResults> {
  const result = await requestEmailOtpWalletUnlock({
    base: args,
    material: {
      kind: 'wallet_unlock_capabilities',
      ecdsa: {
        sessionHandleBinding: args.ecdsaSessionHandleBinding,
        runtimePolicyScope: args.runtimePolicyScope,
        sessionActivation: args.ecdsaSessionActivation,
      },
      ed25519Yao: {
        providerSubject: args.providerSubject,
        nearAccountId: args.nearAccountId,
        expectedOperationalPublicKey: args.expectedOperationalPublicKey,
        expectedThresholdSessionId: args.expectedThresholdSessionId,
        walletCustodyEd25519Material: args.walletCustodyEd25519Material,
        recovery: {
          kind: ROUTER_AB_ED25519_YAO_EMAIL_OTP_RECOVERY_BOOTSTRAP_KIND_V1,
          signerSlot: args.signerSlot,
          remainingUses: args.remainingUses,
          orgId: args.runtimePolicyScope.orgId,
        },
      },
    },
  });
  if (result.kind !== 'wallet_unlock_capabilities') {
    throw new Error('Email OTP capability unlock returned the wrong material branch');
  }
  return {
    kind: 'wallet_unlock_capabilities',
    recovery: result.recovery,
    ecdsa: {
      kind: 'ecdsa',
      operation: 'wallet_unlock',
      recovery: result.recovery,
      emailOtpSessionHandle: result.ecdsa.emailOtpSessionHandle,
      ecdsaSession: result.ecdsa.session,
    },
    ed25519Yao:
      result.ed25519Yao.kind === 'wallet_custody_cache_absent'
        ? {
            kind: 'wallet_custody_cache_absent',
            recovery: result.recovery,
            ed25519YaoRecovery: result.ed25519Yao.bootstrap,
          }
        : {
            kind: 'ed25519_yao_capability',
            recovery: result.recovery,
            activeClientHandle: result.ed25519Yao.activeClientHandle,
            metadata: result.ed25519Yao.metadata,
            ed25519YaoCapability: result.ed25519Yao.bootstrap,
          },
  };
}
