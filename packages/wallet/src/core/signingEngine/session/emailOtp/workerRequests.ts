import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdRuntimePolicyScope } from '@/core/signingEngine/threshold/sessionPolicy';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import type {
  EmailOtpWarmMaterialTarget,
  EmailOtpEd25519YaoOperationMaterialRequest,
  SignerWorkerOperationResult,
} from '@/core/signingEngine/workerManager/workerTypes';
import type { SigningSessionSealKeyVersion } from '../keyMaterialBrands';
import type { WalletSessionOperationCredentialV1 } from '@shared/device-linking';

type EmailOtpWorkerRequester = Pick<WorkerOperationContext, 'requestWorkerOperation'>;

export type EmailOtpWarmSessionTransport = {
  relayerUrl: string;
  operationCredential?: WalletSessionOperationCredentialV1;
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

export async function requestRehydrateEmailOtpEd25519YaoOperationMaterial(args: {
  workerCtx: WorkerOperationContext;
  payload: EmailOtpEd25519YaoOperationMaterialRequest;
}): Promise<
  SignerWorkerOperationResult<'emailOtp', 'rehydrateEmailOtpEd25519YaoOperationMaterial'>
> {
  return await args.workerCtx.requestWorkerOperation({
    kind: 'emailOtp',
    request: {
      type: 'rehydrateEmailOtpEd25519YaoOperationMaterial',
      timeoutMs: 120_000,
      payload: args.payload,
    },
  });
}
