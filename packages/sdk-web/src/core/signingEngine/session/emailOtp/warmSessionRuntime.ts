import type {
  WarmSessionClaimResult,
  WarmSessionStatusResult,
} from '@/core/signingEngine/uiConfirm/uiConfirm.types';
import type { SignerWorkerManager } from '@/core/signingEngine/workerManager/SignerWorkerManager';
import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  requestClaimEmailOtpWarmSessionMaterial,
  requestClearEmailOtpWarmSessionMaterial,
  requestConsumeEmailOtpWarmSessionUses,
  requestGetEmailOtpWarmSessionStatus,
} from './workerRequests';
import {
  claimEmailOtpWarmSessionMaterial,
  clearEmailOtpWarmSessionMaterial,
  consumeEmailOtpWarmSessionUses,
  readEmailOtpWarmSessionStatusOnly,
} from './status';
import type { EmailOtpSealedRefreshPolicy } from './sealedRefreshPolicy';
import type { EmailOtpSealedRestoreOrchestrator } from './sealedRestoreOrchestrator';

export type EmailOtpWarmSessionWorkerClient = {
  readStatus: (sessionId: string) => Promise<WarmSessionStatusResult>;
  claimMaterial: (args: {
    sessionId: string;
    uses?: number;
    consume?: boolean;
  }) => Promise<WarmSessionClaimResult>;
  consumeUses: (args: {
    sessionId: string;
    uses?: number;
  }) => Promise<WarmSessionStatusResult>;
  clearMaterial: (sessionId: string) => Promise<void>;
};

export function createEmailOtpWarmSessionWorkerClient(args: {
  worker: SignerWorkerManager;
}): EmailOtpWarmSessionWorkerClient {
  return {
    async readStatus(sessionId) {
      return await requestGetEmailOtpWarmSessionStatus({
        worker: args.worker,
        sessionId,
      });
    },
    async claimMaterial(request) {
      return await requestClaimEmailOtpWarmSessionMaterial({
        worker: args.worker,
        sessionId: request.sessionId,
        ...(typeof request.uses === 'number' ? { uses: request.uses } : {}),
        ...(typeof request.consume === 'boolean' ? { consume: request.consume } : {}),
      });
    },
    async consumeUses(request) {
      return await requestConsumeEmailOtpWarmSessionUses({
        worker: args.worker,
        sessionId: request.sessionId,
        ...(typeof request.uses === 'number' ? { uses: request.uses } : {}),
      });
    },
    async clearMaterial(sessionId) {
      await requestClearEmailOtpWarmSessionMaterial({
        worker: args.worker,
        sessionId,
      });
    },
  };
}

export class EmailOtpWarmSessionRuntime {
  constructor(
    private readonly ports: {
      workerClient: EmailOtpWarmSessionWorkerClient;
      sealedRefreshPolicy: EmailOtpSealedRefreshPolicy;
      sealedRestoreOrchestrator: EmailOtpSealedRestoreOrchestrator;
    },
  ) {}

  async readWarmSessionStatusOnly(sessionId: string): Promise<WarmSessionStatusResult> {
    return await readEmailOtpWarmSessionStatusOnly({
      sessionId,
      readWarmSessionStatusFromWorker: (normalizedSessionId) =>
        this.ports.workerClient.readStatus(normalizedSessionId),
    });
  }

  async claimWarmSessionMaterial(args: {
    sessionId: string;
    uses?: number;
    consume?: boolean;
    curve?: 'ed25519' | 'ecdsa';
    chain?: 'near';
    chainTarget?: ThresholdEcdsaChainTarget;
  }): Promise<WarmSessionClaimResult> {
    return await claimEmailOtpWarmSessionMaterial({
      sessionId: args.sessionId,
      ...(typeof args.uses === 'number' ? { uses: args.uses } : {}),
      ...(typeof args.consume === 'boolean' ? { consume: args.consume } : {}),
      claimWarmSessionMaterialFromWorker: (claimArgs) =>
        this.ports.workerClient.claimMaterial(claimArgs),
      shouldAttemptEcdsaSealedRestoreForSessionId: (sessionId) =>
        this.ports.sealedRestoreOrchestrator.shouldAttemptEcdsaSealedRestoreForSessionId(
          sessionId,
        ),
      tryRestoreEcdsaWarmSessionStatusFromSealedRecord: (sessionId) =>
        this.ports.sealedRestoreOrchestrator.tryRestoreEcdsaWarmSessionStatusFromSealedRecord(
          sessionId,
        ),
      recordSessionMaterialClaimed: (sessionId, result) =>
        this.ports.sealedRefreshPolicy.recordSessionMaterialClaimed(sessionId, result),
      recordSessionMaterialRestored: (sessionId, result) =>
        this.ports.sealedRefreshPolicy.recordSessionMaterialRestored(sessionId, result),
    });
  }

  async consumeWarmSessionUses(args: {
    sessionId: string;
    uses?: number;
    curve?: 'ed25519' | 'ecdsa';
    chain?: 'near';
    chainTarget?: ThresholdEcdsaChainTarget;
  }): Promise<WarmSessionStatusResult> {
    return await consumeEmailOtpWarmSessionUses({
      sessionId: args.sessionId,
      ...(typeof args.uses === 'number' ? { uses: args.uses } : {}),
      consumeWarmSessionUsesFromWorker: (consumeArgs) =>
        this.ports.workerClient.consumeUses(consumeArgs),
      shouldAttemptEcdsaSealedRestoreForSessionId: (sessionId) =>
        this.ports.sealedRestoreOrchestrator.shouldAttemptEcdsaSealedRestoreForSessionId(
          sessionId,
        ),
      tryRestoreEcdsaWarmSessionStatusFromSealedRecord: (sessionId) =>
        this.ports.sealedRestoreOrchestrator.tryRestoreEcdsaWarmSessionStatusFromSealedRecord(
          sessionId,
        ),
      recordSessionUseConsumed: (sessionId, result) =>
        this.ports.sealedRefreshPolicy.recordSessionUseConsumed(sessionId, result),
      recordSessionMaterialRestored: (sessionId, result) =>
        this.ports.sealedRefreshPolicy.recordSessionMaterialRestored(sessionId, result),
    });
  }

  async clearVolatileWarmSessionMaterial(sessionId: string): Promise<void> {
    await clearEmailOtpWarmSessionMaterial({
      sessionId,
      clearVolatileWarmSessionMaterialFromWorker: (normalizedSessionId) =>
        this.ports.workerClient.clearMaterial(normalizedSessionId),
    });
  }
}
