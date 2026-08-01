import type { WarmSessionStatusResult } from '@/core/signingEngine/uiConfirm/uiConfirm.types';
import type { SignerWorkerManager } from '@/core/signingEngine/workerManager/SignerWorkerManager';
import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  requestClearEmailOtpWarmSessionMaterial,
  requestConsumeEmailOtpWarmSessionUses,
  requestGetEmailOtpWarmSessionStatus,
} from './workerRequests';
import {
  clearEmailOtpWarmSessionMaterial,
  consumeEmailOtpWarmSessionUses,
  readEmailOtpWarmSessionStatusOnly,
} from './status';
import type { EmailOtpSealedRefreshPolicy } from './sealedRefreshPolicy';
import {
  ecdsaSealedRuntimePurpose,
  warmSessionProtocolSessionId,
  type WarmSessionMaterialOperationTarget,
} from './sealedRuntimePurpose';
import type { EmailOtpSealedRestoreOrchestrator } from './sealedRestoreOrchestrator';

export type EmailOtpWarmSessionWorkerClient = {
  readStatus: (sessionId: string) => Promise<WarmSessionStatusResult>;
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

  async consumeWarmSessionUses(args: WarmSessionMaterialOperationTarget & {
    uses?: number;
  }): Promise<WarmSessionStatusResult> {
    return await consumeEmailOtpWarmSessionUses({
      sessionId: warmSessionProtocolSessionId(args),
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
