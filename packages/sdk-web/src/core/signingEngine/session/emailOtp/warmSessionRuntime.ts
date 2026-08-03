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
import type { EmailOtpWarmMaterialTarget } from '@/core/signingEngine/workerManager/workerTypes';

export type EmailOtpWarmSessionWorkerClient = {
  readStatus: (target: EmailOtpWarmMaterialTarget) => Promise<WarmSessionStatusResult>;
  consumeUses: (args: {
    target: EmailOtpWarmMaterialTarget;
    uses?: number;
  }) => Promise<WarmSessionStatusResult>;
  clearMaterial: (target: EmailOtpWarmMaterialTarget) => Promise<void>;
};

export function createEmailOtpWarmSessionWorkerClient(args: {
  worker: SignerWorkerManager;
}): EmailOtpWarmSessionWorkerClient {
  return {
    async readStatus(target) {
      return await requestGetEmailOtpWarmSessionStatus({
        worker: args.worker,
        target,
      });
    },
    async consumeUses(request) {
      return await requestConsumeEmailOtpWarmSessionUses({
        worker: args.worker,
        target: request.target,
        ...(typeof request.uses === 'number' ? { uses: request.uses } : {}),
      });
    },
    async clearMaterial(target) {
      await requestClearEmailOtpWarmSessionMaterial({
        worker: args.worker,
        target,
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

  async readWarmSessionStatusOnly(target: EmailOtpWarmMaterialTarget): Promise<WarmSessionStatusResult> {
    return await readEmailOtpWarmSessionStatusOnly({
      target,
      readWarmSessionStatusFromWorker: (workerTarget) =>
        this.ports.workerClient.readStatus(workerTarget),
    });
  }

  async consumeWarmSessionUses(args: WarmSessionMaterialOperationTarget & {
    uses?: number;
  }): Promise<WarmSessionStatusResult> {
    return await consumeEmailOtpWarmSessionUses({
      target: warmSessionMaterialTarget(args),
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

  async clearVolatileWarmSessionMaterial(target: EmailOtpWarmMaterialTarget): Promise<void> {
    await clearEmailOtpWarmSessionMaterial({
      target,
      clearVolatileWarmSessionMaterialFromWorker: (workerTarget) =>
        this.ports.workerClient.clearMaterial(workerTarget),
    });
  }
}

function warmSessionMaterialTarget(
  target: WarmSessionMaterialOperationTarget,
): EmailOtpWarmMaterialTarget {
  const thresholdSessionId = warmSessionProtocolSessionId(target);
  return target.purpose.curve === 'ecdsa'
    ? { kind: 'ecdsa', thresholdSessionId }
    : {
        kind: 'ed25519_yao',
        thresholdSessionId,
        materialActivation: target.purpose.materialActivation,
      };
}
