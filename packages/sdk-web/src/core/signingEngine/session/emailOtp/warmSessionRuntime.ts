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
import {
  ecdsaSealedRuntimePurpose,
  type WarmSessionLanePurpose,
} from './sealedRuntimePurpose';
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
    purpose: WarmSessionLanePurpose;
    uses?: number;
    consume?: boolean;
  }): Promise<WarmSessionClaimResult> {
    return await claimEmailOtpWarmSessionMaterial({
      sessionId: args.purpose.thresholdSessionId,
      ...(typeof args.uses === 'number' ? { uses: args.uses } : {}),
      ...(typeof args.consume === 'boolean' ? { consume: args.consume } : {}),
      claimWarmSessionMaterialFromWorker: (claimArgs) =>
        this.ports.workerClient.claimMaterial(claimArgs),
      ecdsaPurpose: ecdsaSealedRuntimePurpose(args.purpose),
      tryRestoreEcdsaWarmSessionStatusFromSealedRecord: (purpose) =>
        this.ports.sealedRestoreOrchestrator.tryRestoreEcdsaWarmSessionStatusFromSealedRecord(
          purpose,
        ),
      recordSessionMaterialClaimed: (purpose, result) =>
        this.ports.sealedRefreshPolicy.recordSessionMaterialClaimed(purpose, result),
      recordSessionMaterialRestored: (purpose, result) =>
        this.ports.sealedRefreshPolicy.recordSessionMaterialRestored(purpose, result),
    });
  }

  async consumeWarmSessionUses(args: {
    purpose: WarmSessionLanePurpose;
    uses?: number;
  }): Promise<WarmSessionStatusResult> {
    return await consumeEmailOtpWarmSessionUses({
      sessionId: args.purpose.thresholdSessionId,
      ...(typeof args.uses === 'number' ? { uses: args.uses } : {}),
      consumeWarmSessionUsesFromWorker: (consumeArgs) =>
        this.ports.workerClient.consumeUses(consumeArgs),
      ecdsaPurpose: ecdsaSealedRuntimePurpose(args.purpose),
      tryRestoreEcdsaWarmSessionStatusFromSealedRecord: (purpose) =>
        this.ports.sealedRestoreOrchestrator.tryRestoreEcdsaWarmSessionStatusFromSealedRecord(
          purpose,
        ),
      recordSessionUseConsumed: (purpose, result) =>
        this.ports.sealedRefreshPolicy.recordSessionUseConsumed(purpose, result),
      recordSessionMaterialRestored: (purpose, result) =>
        this.ports.sealedRefreshPolicy.recordSessionMaterialRestored(purpose, result),
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
