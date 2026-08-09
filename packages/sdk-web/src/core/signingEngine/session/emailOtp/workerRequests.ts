import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdRuntimePolicyScope } from '@/core/signingEngine/threshold/sessionPolicy';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import type {
  EmailOtpEd25519YaoIssuedOperationAuthorizationV1,
  EmailOtpEd25519YaoOperationStepUpProofV1,
  EmailOtpWarmMaterialTarget,
  SignerWorkerOperationResult,
} from '@/core/signingEngine/workerManager/workerTypes';
import type { SigningSessionSealKeyVersion } from '../keyMaterialBrands';
import type { WalletRegistrationEd25519YaoBootstrapSession } from '@/core/rpcClients/relayer/walletRegistration';
import type { RouterAbNormalSigningPrepareRequestV2Wire } from '@/core/rpcClients/relayer/routerAbNormalSigning';
import type {
  MpcMaterialActivationRef,
  ThresholdEd25519SessionId,
} from '@shared/utils/domainIds';
import type { RouterAbEd25519YaoActiveClientMetadataV1 } from '../../threshold/ed25519/yaoClient';

type EmailOtpWorkerRequester = Pick<WorkerOperationContext, 'requestWorkerOperation'>;

export type EmailOtpWarmSessionTransport = {
  relayerUrl: string;
  walletSessionJwt?: string;
  signingSessionSealKeyVersion?: SigningSessionSealKeyVersion;
  groupId?: string;
};

export type EmailOtpEcdsaWarmSessionRestore = {
  thresholdSessionId: string;
  walletId: string;
  keyHandle: string;
  chainTarget: ThresholdEcdsaChainTarget;
  authSubjectId: string;
};

export type EmailOtpEd25519YaoLocalMaterialRestore = {
  session: WalletRegistrationEd25519YaoBootstrapSession;
  providerSubject: string;
  signerSlot: number;
  expectedOperationalPublicKey: string;
};

export async function requestSealEmailOtpWarmSessionMaterial(args: {
  workerCtx: WorkerOperationContext;
  target: EmailOtpWarmMaterialTarget;
  transport: EmailOtpWarmSessionTransport;
}): Promise<SignerWorkerOperationResult<'emailOtp', 'sealEmailOtpWarmSessionMaterial'>> {
  return await args.workerCtx.requestWorkerOperation({
    kind: 'emailOtp',
    request: {
      type: 'sealEmailOtpWarmSessionMaterial',
      timeoutMs: 30_000,
      payload: {
        target: args.target,
        transport: args.transport,
      },
    },
  });
}

export async function requestGetEmailOtpWarmSessionStatus(args: {
  worker: EmailOtpWorkerRequester;
  target: EmailOtpWarmMaterialTarget;
}): Promise<SignerWorkerOperationResult<'emailOtp', 'getEmailOtpWarmSessionStatus'>> {
  return await args.worker.requestWorkerOperation({
    kind: 'emailOtp',
    request: {
      type: 'getEmailOtpWarmSessionStatus',
      timeoutMs: 5_000,
      payload: { target: args.target },
    },
  });
}

export async function requestConsumeEmailOtpWarmSessionUses(args: {
  worker: EmailOtpWorkerRequester;
  target: EmailOtpWarmMaterialTarget;
  uses?: number;
}): Promise<SignerWorkerOperationResult<'emailOtp', 'consumeEmailOtpWarmSessionUses'>> {
  return await args.worker.requestWorkerOperation({
    kind: 'emailOtp',
    request: {
      type: 'consumeEmailOtpWarmSessionUses',
      timeoutMs: 5_000,
      payload: {
        target: args.target,
        ...(typeof args.uses === 'number' ? { uses: args.uses } : {}),
      },
    },
  });
}

export async function requestClearEmailOtpWarmSessionMaterial(args: {
  worker: EmailOtpWorkerRequester;
  target: EmailOtpWarmMaterialTarget;
}): Promise<SignerWorkerOperationResult<'emailOtp', 'clearEmailOtpWarmSessionMaterial'>> {
  return await args.worker.requestWorkerOperation({
    kind: 'emailOtp',
    request: {
      type: 'clearEmailOtpWarmSessionMaterial',
      timeoutMs: 5_000,
      payload: { target: args.target },
    },
  });
}

export async function requestRehydrateEmailOtpEcdsaWarmSessionMaterial(args: {
  workerCtx: WorkerOperationContext;
  target: Extract<EmailOtpWarmMaterialTarget, { kind: 'ecdsa' }>;
  sealedSecretB64u: string;
  remainingUses: number;
  expiresAtMs: number;
  transport: EmailOtpWarmSessionTransport;
  restore: EmailOtpEcdsaWarmSessionRestore;
}): Promise<SignerWorkerOperationResult<'emailOtp', 'rehydrateEmailOtpEcdsaWarmSessionMaterial'>> {
  return await args.workerCtx.requestWorkerOperation({
    kind: 'emailOtp',
    request: {
      type: 'rehydrateEmailOtpEcdsaWarmSessionMaterial',
      timeoutMs: 60_000,
      payload: {
        target: args.target,
        sealedSecretB64u: args.sealedSecretB64u,
        remainingUses: args.remainingUses,
        expiresAtMs: args.expiresAtMs,
        transport: args.transport,
        restore: args.restore,
      },
    },
  });
}

export async function requestRehydrateEmailOtpEd25519YaoLocalMaterial(args: {
  workerCtx: WorkerOperationContext;
  target: Extract<EmailOtpWarmMaterialTarget, { kind: 'ed25519_yao' }>;
  sealedSecretB64u: string;
  remainingUses: number;
  expiresAtMs: number;
  transport: Required<EmailOtpWarmSessionTransport>;
  restore: EmailOtpEd25519YaoLocalMaterialRestore;
}): Promise<SignerWorkerOperationResult<'emailOtp', 'rehydrateEmailOtpEd25519YaoLocalMaterial'>> {
  return await args.workerCtx.requestWorkerOperation({
    kind: 'emailOtp',
    request: {
      type: 'rehydrateEmailOtpEd25519YaoLocalMaterial',
      timeoutMs: 60_000,
      payload: {
        target: args.target,
        sealedSecretB64u: args.sealedSecretB64u,
        remainingUses: args.remainingUses,
        expiresAtMs: args.expiresAtMs,
        transport: args.transport,
        restore: args.restore,
      },
    },
  });
}

export async function requestRehydrateEmailOtpEd25519YaoOperationMaterial(args: {
  workerContext: WorkerOperationContext;
  relayUrl: string;
  walletId: string;
  nearAccountId: string;
  signerSlot: number;
  providerSubjectId: string;
  expectedOperationalPublicKey: string;
  expectedThresholdSessionId: ThresholdEd25519SessionId;
  expectedMaterialActivation: MpcMaterialActivationRef;
  normalSigningRequest: RouterAbNormalSigningPrepareRequestV2Wire;
  displayDigest: string;
  proof: EmailOtpEd25519YaoOperationStepUpProofV1;
}): Promise<{
  activeClientHandle: string;
  metadata: RouterAbEd25519YaoActiveClientMetadataV1;
  issuedAuthorization: EmailOtpEd25519YaoIssuedOperationAuthorizationV1;
}> {
  return await args.workerContext.requestWorkerOperation({
    kind: 'emailOtp',
    request: {
      type: 'rehydrateEmailOtpEd25519YaoOperationMaterial',
      timeoutMs: 60_000,
      payload: {
        relayUrl: args.relayUrl,
        walletId: args.walletId,
        nearAccountId: args.nearAccountId,
        signerSlot: args.signerSlot,
        providerSubjectId: args.providerSubjectId,
        expectedOperationalPublicKey: args.expectedOperationalPublicKey,
        expectedThresholdSessionId: args.expectedThresholdSessionId,
        expectedMaterialActivation: args.expectedMaterialActivation,
        normalSigningRequest: args.normalSigningRequest,
        displayDigest: args.displayDigest,
        proof: args.proof,
      },
    },
  });
}
