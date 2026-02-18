import { IndexedDBManager } from '../../../IndexedDBManager';
import type { AccountId } from '../../../types/accountIds';
import { toAccountId } from '../../../types/accountIds';
import type { SigningSessionStatus } from '../../../types/tatchi';
import type { SecureConfirmWorkerManager } from '../../secureConfirm';
import type {
  ThresholdEcdsaActivationChain,
  ThresholdEcdsaSessionBootstrapResult,
} from '../../orchestration/activation';
import {
  getWarmSigningSessionStatusSurface as getWarmSigningSessionStatusSurfaceValue,
  type FacadeConvenienceDeps,
} from '../facade/facadeConvenience';
import {
  bootstrapThresholdEcdsaSessionLiteValue,
  connectThresholdEd25519SessionLiteValue,
  type ThresholdSessionActivationDeps,
} from '../thresholdSessionActivation';
import {
  persistThresholdEcdsaBootstrapChainAccount as persistThresholdEcdsaBootstrapChainAccountValue,
  type ThresholdEcdsaSmartAccountBootstrapInput,
} from '../thresholdEcdsaBootstrapPersistence';

export type ThresholdSessionSurfaceDeps = {
  thresholdSessionActivationDeps: ThresholdSessionActivationDeps;
  getFacadeConvenienceDeps: () => FacadeConvenienceDeps;
  secureConfirmWorkerManager: SecureConfirmWorkerManager;
  activeSigningSessionIds: Map<string, string>;
  withThresholdEcdsaBootstrapQueue: <T>(
    nearAccountId: AccountId,
    task: () => Promise<T>,
  ) => Promise<T>;
};

export type ThresholdSessionSurface = {
  connectThresholdEd25519SessionLite(args: {
    nearAccountId: AccountId | string;
    relayerKeyId: string;
    participantIds?: number[];
    sessionKind?: 'jwt' | 'cookie';
    relayerUrl?: string;
    ttlMs?: number;
    remainingUses?: number;
  }): Promise<Awaited<ReturnType<typeof connectThresholdEd25519SessionLiteValue>>>;
  bootstrapThresholdEcdsaSessionLite(args: {
    nearAccountId: AccountId | string;
    chain?: ThresholdEcdsaActivationChain;
    relayerUrl?: string;
    participantIds?: number[];
    sessionKind?: 'jwt' | 'cookie';
    ttlMs?: number;
    remainingUses?: number;
    smartAccount?: ThresholdEcdsaSmartAccountBootstrapInput;
  }): Promise<ThresholdEcdsaSessionBootstrapResult>;
  persistThresholdEcdsaBootstrapChainAccount(args: {
    nearAccountId: AccountId | string;
    chain: ThresholdEcdsaActivationChain;
    bootstrap: ThresholdEcdsaSessionBootstrapResult;
    smartAccount?: ThresholdEcdsaSmartAccountBootstrapInput;
  }): Promise<void>;
  getWarmSigningSessionStatus(
    nearAccountId: AccountId | string,
  ): Promise<SigningSessionStatus | null>;
  setActiveSigningSessionId(nearAccountId: AccountId | string, sessionId: string): void;
  putPrfFirstForThresholdSession(args: {
    sessionId: string;
    prfFirstB64u: string;
    expiresAtMs: number;
    remainingUses: number;
  }): Promise<void>;
  clearWarmSigningSessions(nearAccountId?: AccountId | string): Promise<void>;
};

export function createThresholdSessionSurface(
  deps: ThresholdSessionSurfaceDeps,
): ThresholdSessionSurface {
  return {
    async connectThresholdEd25519SessionLite(args): Promise<
      Awaited<ReturnType<typeof connectThresholdEd25519SessionLiteValue>>
    > {
      return await connectThresholdEd25519SessionLiteValue(
        deps.thresholdSessionActivationDeps,
        args,
      );
    },
    async bootstrapThresholdEcdsaSessionLite(args): Promise<ThresholdEcdsaSessionBootstrapResult> {
      const nearAccountId = toAccountId(args.nearAccountId);
      return await deps.withThresholdEcdsaBootstrapQueue(nearAccountId, async () => {
        return await bootstrapThresholdEcdsaSessionLiteValue(
          deps.thresholdSessionActivationDeps,
          {
            ...args,
            nearAccountId,
          },
        );
      });
    },
    async persistThresholdEcdsaBootstrapChainAccount(args): Promise<void> {
      await persistThresholdEcdsaBootstrapChainAccountValue({
        indexedDB: IndexedDBManager,
        nearAccountId: toAccountId(args.nearAccountId),
        chain: args.chain,
        bootstrap: args.bootstrap,
        smartAccount: args.smartAccount,
      });
    },
    async getWarmSigningSessionStatus(
      nearAccountId: AccountId | string,
    ): Promise<SigningSessionStatus | null> {
      return await getWarmSigningSessionStatusSurfaceValue(
        deps.getFacadeConvenienceDeps(),
        nearAccountId,
      );
    },
    setActiveSigningSessionId(nearAccountId: AccountId | string, sessionId: string): void {
      const accountKey = String(toAccountId(nearAccountId));
      const normalizedSessionId = String(sessionId || '').trim();
      if (!normalizedSessionId) {
        deps.activeSigningSessionIds.delete(accountKey);
        return;
      }
      deps.activeSigningSessionIds.set(accountKey, normalizedSessionId);
    },
    async putPrfFirstForThresholdSession(args: {
      sessionId: string;
      prfFirstB64u: string;
      expiresAtMs: number;
      remainingUses: number;
    }): Promise<void> {
      await deps.secureConfirmWorkerManager.putPrfFirstForThresholdSession(args);
    },
    async clearWarmSigningSessions(nearAccountId?: AccountId | string): Promise<void> {
      const sessionIds: string[] = [];
      if (nearAccountId != null) {
        const accountKey = String(toAccountId(nearAccountId));
        const sessionId = String(deps.activeSigningSessionIds.get(accountKey) || '').trim();
        if (sessionId) sessionIds.push(sessionId);
        deps.activeSigningSessionIds.delete(accountKey);
      } else {
        for (const sessionIdRaw of deps.activeSigningSessionIds.values()) {
          const sessionId = String(sessionIdRaw || '').trim();
          if (sessionId) sessionIds.push(sessionId);
        }
        deps.activeSigningSessionIds.clear();
      }

      await Promise.all(
        sessionIds.map((sessionId) =>
          deps.secureConfirmWorkerManager
            .clearPrfFirstForThresholdSession({ sessionId })
            .catch(() => undefined)),
      );
    },
  };
}
