import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdRuntimePolicyScope } from '@/core/signingEngine/threshold/sessionPolicy';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import type { SignerWorkerOperationResult } from '@/core/signingEngine/workerManager/workerTypes';
import type { SigningSessionSealKeyVersion } from '../keyMaterialBrands';
import { zeroizeBytes } from './zeroize';

type EmailOtpWorkerRequester = Pick<WorkerOperationContext, 'requestWorkerOperation'>;

export type EmailOtpWarmSessionTransport = {
  relayerUrl: string;
  walletSessionJwt?: string;
  signingSessionSealKeyVersion?: SigningSessionSealKeyVersion;
  shamirPrimeB64u?: string;
};

export type EmailOtpEcdsaWarmSessionRestore = {
  sessionId: string;
  walletId: string;
  evmFamilySigningKeySlotId: string;
  chainTarget: ThresholdEcdsaChainTarget;
  signingGrantId: string;
  keyHandle: string;
  relayerKeyId: string;
  participantIds: number[];
  sessionKind: 'jwt';
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
};

export type EmailOtpEd25519YaoFactorRestore = {
  sessionId: string;
  walletId: string;
  providerSubject: string;
};

export async function requestSealEmailOtpWarmSessionMaterial(args: {
  workerCtx: WorkerOperationContext;
  sessionId: string;
  transport: EmailOtpWarmSessionTransport;
}): Promise<SignerWorkerOperationResult<'emailOtp', 'sealEmailOtpWarmSessionMaterial'>> {
  return await args.workerCtx.requestWorkerOperation({
    kind: 'emailOtp',
    request: {
      type: 'sealEmailOtpWarmSessionMaterial',
      timeoutMs: 30_000,
      payload: {
        sessionId: args.sessionId,
        transport: args.transport,
      },
    },
  });
}

export async function requestGetEmailOtpWarmSessionStatus(args: {
  worker: EmailOtpWorkerRequester;
  sessionId: string;
}): Promise<SignerWorkerOperationResult<'emailOtp', 'getEmailOtpWarmSessionStatus'>> {
  return await args.worker.requestWorkerOperation({
    kind: 'emailOtp',
    request: {
      type: 'getEmailOtpWarmSessionStatus',
      timeoutMs: 5_000,
      payload: { sessionId: args.sessionId },
    },
  });
}

export async function requestClaimEmailOtpWarmSessionMaterial(args: {
  worker: EmailOtpWorkerRequester;
  sessionId: string;
  uses?: number;
  consume?: boolean;
}): Promise<SignerWorkerOperationResult<'emailOtp', 'claimEmailOtpWarmSessionMaterial'>> {
  return await args.worker.requestWorkerOperation({
    kind: 'emailOtp',
    request: {
      type: 'claimEmailOtpWarmSessionMaterial',
      timeoutMs: 5_000,
      payload: {
        sessionId: args.sessionId,
        ...(typeof args.uses === 'number' ? { uses: args.uses } : {}),
        ...(typeof args.consume === 'boolean' ? { consume: args.consume } : {}),
      },
    },
  });
}

export async function claimEmailOtpEcdsaSigningShare32(args: {
  workerCtx: WorkerOperationContext;
  sessionId: string;
}): Promise<Uint8Array> {
  const result = await args.workerCtx.requestWorkerOperation({
    kind: 'emailOtp',
    request: {
      type: 'claimEmailOtpEcdsaSigningShare',
      timeoutMs: 5_000,
      payload: { sessionId: args.sessionId },
    },
  });
  if (!result.ok) {
    throw new Error(
      result.message ||
        result.code ||
        'Email OTP ECDSA signing material is unavailable; verify Email OTP again',
    );
  }
  const clientSigningShare32 = new Uint8Array(result.clientSigningShare32);
  if (clientSigningShare32.length !== 32) {
    zeroizeBytes(clientSigningShare32);
    throw new Error('Email OTP ECDSA signing material must contain 32 bytes');
  }
  return clientSigningShare32;
}

export async function requestConsumeEmailOtpWarmSessionUses(args: {
  worker: EmailOtpWorkerRequester;
  sessionId: string;
  uses?: number;
}): Promise<SignerWorkerOperationResult<'emailOtp', 'consumeEmailOtpWarmSessionUses'>> {
  return await args.worker.requestWorkerOperation({
    kind: 'emailOtp',
    request: {
      type: 'consumeEmailOtpWarmSessionUses',
      timeoutMs: 5_000,
      payload: {
        sessionId: args.sessionId,
        ...(typeof args.uses === 'number' ? { uses: args.uses } : {}),
      },
    },
  });
}

export async function requestClearEmailOtpWarmSessionMaterial(args: {
  worker: EmailOtpWorkerRequester;
  sessionId: string;
}): Promise<SignerWorkerOperationResult<'emailOtp', 'clearEmailOtpWarmSessionMaterial'>> {
  return await args.worker.requestWorkerOperation({
    kind: 'emailOtp',
    request: {
      type: 'clearEmailOtpWarmSessionMaterial',
      timeoutMs: 5_000,
      payload: { sessionId: args.sessionId },
    },
  });
}

export async function requestRehydrateEmailOtpEcdsaWarmSessionMaterial(args: {
  workerCtx: WorkerOperationContext;
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
        sealedSecretB64u: args.sealedSecretB64u,
        remainingUses: args.remainingUses,
        expiresAtMs: args.expiresAtMs,
        transport: args.transport,
        restore: args.restore,
      },
    },
  });
}

export async function requestRehydrateEmailOtpEd25519YaoFactor(args: {
  workerCtx: WorkerOperationContext;
  sealedSecretB64u: string;
  remainingUses: number;
  expiresAtMs: number;
  transport: Required<EmailOtpWarmSessionTransport>;
  restore: EmailOtpEd25519YaoFactorRestore;
}): Promise<SignerWorkerOperationResult<'emailOtp', 'rehydrateEmailOtpEd25519YaoFactor'>> {
  return await args.workerCtx.requestWorkerOperation({
    kind: 'emailOtp',
    request: {
      type: 'rehydrateEmailOtpEd25519YaoFactor',
      timeoutMs: 60_000,
      payload: {
        sealedSecretB64u: args.sealedSecretB64u,
        remainingUses: args.remainingUses,
        expiresAtMs: args.expiresAtMs,
        transport: args.transport,
        restore: args.restore,
      },
    },
  });
}
