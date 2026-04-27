import type { AccountId } from '@/core/types/accountIds';
import type { SigningSessionStatus } from '@/core/types/tatchi';
import {
  deleteSigningSessionSealedRecord,
  updateSigningSessionSealedRecordPolicy,
} from '../api/session/signingSessionSealedStore';
import type { WarmSessionPrfClaim } from './warmSessionTypes';
import type { SigningOperationIntent } from './signingSessionTypes';
import {
  clearWalletSigningSession,
  consumeWalletSigningSessionUse,
  discoverLanesForAccount,
  getLanesForWalletSession as getLanesForWalletSessionHelper,
  normalizeNonEmpty,
  readClaimsForLanes,
  statusFromClaim,
  walletScopedClaimsForLanes,
  type DiscoveredSigningSessionLane,
  type SigningSessionLane,
  type WalletSigningSessionReadinessDeps,
  type WalletSigningSessionStatusOverride,
} from './signingSession/readiness';

export type { SigningSessionLane };

export type WalletSigningSessionConsumeUseArgs = {
  nearAccountId: AccountId | string;
  walletSigningSessionId: string;
  uses: number;
  reason: SigningOperationIntent;
  targetBackingMaterialSessionIds?: string[];
  targetThresholdSessionIds?: string[];
  alreadyConsumedBackingMaterialSessionIds?: string[];
  alreadyConsumedThresholdSessionIds?: string[];
};

export type WalletSigningSessionCoordinator = {
  getStatus(args: {
    nearAccountId: AccountId | string;
    walletSigningSessionId?: string;
    targetBackingMaterialSessionIds?: string[];
    targetThresholdSessionIds?: string[];
  }): Promise<SigningSessionStatus | null>;
  getLaneClaimsForAccount(
    nearAccountId: AccountId | string,
  ): Promise<Map<string, WarmSessionPrfClaim | null>>;
  consumeUse(args: WalletSigningSessionConsumeUseArgs): Promise<SigningSessionStatus>;
  clear(args: { nearAccountId: AccountId | string; walletSigningSessionId: string }): Promise<void>;
};

export type WalletSigningSessionCoordinatorDeps = WalletSigningSessionReadinessDeps;

export type WalletSigningSessionCoordinatorState = {
  statusOverrides: Map<string, WalletSigningSessionStatusOverride>;
};

export function createWalletSigningSessionCoordinator(
  deps: WalletSigningSessionCoordinatorDeps = {},
  state: WalletSigningSessionCoordinatorState,
): WalletSigningSessionCoordinator {
  const effectiveDeps: WalletSigningSessionCoordinatorDeps = {
    ...deps,
    updateSigningSessionSealedRecordPolicy:
      deps.updateSigningSessionSealedRecordPolicy || updateSigningSessionSealedRecordPolicy,
    deleteSigningSessionSealedRecord:
      deps.deleteSigningSessionSealedRecord || deleteSigningSessionSealedRecord,
  };
  const { statusOverrides } = state;
  const getLanesForWalletSession = (args: {
    nearAccountId: AccountId | string;
    walletSigningSessionId?: string;
  }): DiscoveredSigningSessionLane[] => {
    return getLanesForWalletSessionHelper({
      deps: effectiveDeps,
      nearAccountId: args.nearAccountId,
      ...(args.walletSigningSessionId
        ? { walletSigningSessionId: args.walletSigningSessionId }
        : {}),
    });
  };

  const coordinator: WalletSigningSessionCoordinator = {
    async getLaneClaimsForAccount(
      nearAccountId: AccountId | string,
    ): Promise<Map<string, WarmSessionPrfClaim | null>> {
      const lanes = discoverLanesForAccount(effectiveDeps, nearAccountId);
      const rawClaims = await readClaimsForLanes({ deps: effectiveDeps, lanes });
      return walletScopedClaimsForLanes({
        lanes,
        claimsByThresholdSessionId: rawClaims,
        statusOverrides,
      });
    },

    async getStatus(args: {
      nearAccountId: AccountId | string;
      walletSigningSessionId?: string;
      targetBackingMaterialSessionIds?: string[];
      targetThresholdSessionIds?: string[];
    }): Promise<SigningSessionStatus | null> {
      const lanes = getLanesForWalletSession(args);
      if (!lanes.length) return null;
      const walletSigningSessionId =
        normalizeNonEmpty(args.walletSigningSessionId) || lanes[0].walletSigningSessionId;
      const targetBacking = new Set(
        (args.targetBackingMaterialSessionIds || []).map(normalizeNonEmpty).filter(Boolean),
      );
      const targetThreshold = new Set(
        (args.targetThresholdSessionIds || []).map(normalizeNonEmpty).filter(Boolean),
      );
      const hasExplicitTarget = targetBacking.size > 0 || targetThreshold.size > 0;
      const statusLanes = hasExplicitTarget
        ? lanes.filter(
            (lane) =>
              targetBacking.has(lane.backingMaterialSessionId) ||
              targetThreshold.has(lane.thresholdSessionId),
          )
        : lanes;
      if (hasExplicitTarget && !statusLanes.length) {
        return {
          sessionId: walletSigningSessionId,
          status: 'not_found',
        };
      }
      const rawClaims = await readClaimsForLanes({ deps: effectiveDeps, lanes: statusLanes });
      const scopedClaims = walletScopedClaimsForLanes({
        lanes: statusLanes,
        claimsByThresholdSessionId: rawClaims,
        statusOverrides,
      });
      const claims = statusLanes
        .map((lane) => scopedClaims.get(lane.thresholdSessionId) || null)
        .filter(Boolean);
      const claim =
        claims.find((candidate) => candidate?.state === 'expired') ||
        claims.find((candidate) => candidate?.state === 'exhausted') ||
        claims.find((candidate) => candidate?.state === 'unavailable') ||
        claims.find((candidate) => candidate?.state === 'warm') ||
        null;
      return statusFromClaim({ walletSigningSessionId, lanes: statusLanes, claim });
    },

    async consumeUse(args: WalletSigningSessionConsumeUseArgs): Promise<SigningSessionStatus> {
      return await consumeWalletSigningSessionUse({
        deps: effectiveDeps,
        statusOverrides,
        readStatus: (statusArgs) => coordinator.getStatus(statusArgs),
        input: args,
      });
    },

    async clear(args: {
      nearAccountId: AccountId | string;
      walletSigningSessionId: string;
    }): Promise<void> {
      await clearWalletSigningSession({
        deps: effectiveDeps,
        statusOverrides,
        nearAccountId: args.nearAccountId,
        walletSigningSessionId: args.walletSigningSessionId,
      });
    },
  };
  return coordinator;
}
