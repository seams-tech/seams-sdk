import { toAccountId, type AccountId } from '@/core/types/accountIds';
import type { SigningSessionStatus } from '@/core/types/seams';
import type { WarmSessionSealTransportInput } from '@/core/types/secure-confirm-worker';
import type {
  ThresholdEcdsaChainTarget,
  WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  buildWalletBudgetStatusCheckForSession,
  getWalletSigningBudgetAvailableStatus as getWalletSigningBudgetAvailableStatusValue,
  mergeWalletSigningBudgetStatus,
  type WalletSigningBudgetAvailableStatusDeps,
} from '../budget/budgetStatusReader';
import {
  buildEcdsaLaneBudgetStatusCheck,
  ed25519WalletBudgetOwner,
} from '../budget/budget';
import {
  getStoredThresholdEd25519SessionRecordForAccount as getStoredThresholdEd25519SessionRecordForAccountValue,
} from '../persistence/records';
import {
  scheduleThresholdEcdsaLoginPresignPrefill as scheduleThresholdEcdsaLoginPresignPrefillValue,
  type ThresholdEcdsaLoginPrefillResult,
} from './ecdsaLoginPrefill';
import type { ThresholdEcdsaSessionBootstrapResult } from '../../threshold/ecdsa/activation';
import type { ThresholdEcdsaSessionRecord } from '../persistence/records';
import type {
  WarmEcdsaRecordBackedSigningSessionStatus,
  WarmEcdsaSigningSessionStatus,
  ThresholdWarmSessionStatusReader,
} from './types';

export type PersistThresholdEcdsaBootstrapForWalletTargetInput = {
  walletId: WalletId;
  chainTarget: ThresholdEcdsaChainTarget;
  bootstrap: ThresholdEcdsaSessionBootstrapResult;
  ensureEmailOtpNearAccountMapping?: boolean;
};

export type HydrateSigningSessionInput = {
  sessionId: string;
  prfFirstB64u: string;
  expiresAtMs: number;
  remainingUses: number;
  transport?: WarmSessionSealTransportInput;
};

export type WarmCapabilitiesPublicDeps = {
  statusReader: Pick<
    ThresholdWarmSessionStatusReader,
    'getEd25519SigningSessionStatus' | 'getEcdsaSigningSessionStatus' | 'listEcdsaSigningSessionStatuses'
  >;
  persistThresholdEcdsaBootstrapForWalletTarget: (
    args: PersistThresholdEcdsaBootstrapForWalletTargetInput,
  ) => Promise<void>;
  hydrateSigningSession: (args: HydrateSigningSessionInput) => Promise<void>;
  clearVolatileWarmSigningMaterial: (walletId?: WalletId) => Promise<void>;
  getWalletSigningBudgetStatus: WalletSigningBudgetAvailableStatusDeps['getAvailableStatus'];
  resolveCanonicalThresholdEcdsaSessionIdForWalletTarget: (
    walletId: WalletId,
    chainTarget: ThresholdEcdsaChainTarget,
  ) => string | null;
  getSignerWorkerContext: Parameters<
    typeof scheduleThresholdEcdsaLoginPresignPrefillValue
  >[0]['getSignerWorkerContext'];
  resolveClientSigningShare32: Parameters<
    typeof scheduleThresholdEcdsaLoginPresignPrefillValue
  >[0]['resolveClientSigningShare32'];
  thresholdEcdsaPresignPoolPolicy?: Parameters<
    typeof scheduleThresholdEcdsaLoginPresignPrefillValue
  >[0]['thresholdEcdsaPresignPoolPolicy'];
};

export async function persistThresholdEcdsaBootstrapForWalletTarget(
  deps: WarmCapabilitiesPublicDeps,
  args: PersistThresholdEcdsaBootstrapForWalletTargetInput,
): Promise<void> {
  await deps.persistThresholdEcdsaBootstrapForWalletTarget(args);
}

export async function getWarmThresholdEd25519SessionStatus(
  deps: WarmCapabilitiesPublicDeps,
  nearAccountId: AccountId,
): Promise<SigningSessionStatus | null> {
  const status = await deps.statusReader.getEd25519SigningSessionStatus(nearAccountId);
  const record = getStoredThresholdEd25519SessionRecordForAccountValue(nearAccountId);
  const walletSigningSessionId = String(record?.walletSigningSessionId || '').trim();
  const budgetStatusCheck = walletSigningSessionId
    ? buildWalletBudgetStatusCheckForSession({
        owner: ed25519WalletBudgetOwner(toAccountId(nearAccountId)),
        walletSigningSessionId,
      })
    : null;
  const walletBudgetStatus = budgetStatusCheck
    ? await getWalletSigningBudgetAvailableStatusValue(
        {
          getAvailableStatus: deps.getWalletSigningBudgetStatus,
        },
        budgetStatusCheck,
      )
    : null;
  if (!status) return walletBudgetStatus;
  return mergeWalletSigningBudgetStatus(status, walletBudgetStatus);
}

export async function getWarmThresholdEcdsaSessionStatus(
  deps: WarmCapabilitiesPublicDeps,
  walletId: WalletId,
  chainTarget: ThresholdEcdsaChainTarget,
  thresholdSessionId: string,
): Promise<WarmEcdsaSigningSessionStatus | null> {
  const status = await deps.statusReader.getEcdsaSigningSessionStatus({
    walletId,
    chainTarget,
    thresholdSessionId,
  });
  const walletBudgetStatus = isRecordBackedEcdsaStatus(status)
    ? await getWalletSigningBudgetAvailableStatusValue(
        {
          getAvailableStatus: deps.getWalletSigningBudgetStatus,
        },
        buildEcdsaLaneBudgetStatusCheck({
          key: status.key,
          keyHandle: status.lane.keyHandle,
          chainTarget: status.chainTarget,
          walletSigningSessionId: status.walletSigningSessionId,
          thresholdSessionId,
        }),
      )
    : null;
  if (!status) return walletBudgetStatus as WarmEcdsaSigningSessionStatus | null;
  return mergeWalletSigningBudgetStatus(status, walletBudgetStatus);
}

export async function listWarmThresholdEcdsaSessionStatuses(
  deps: WarmCapabilitiesPublicDeps,
  walletId: WalletId,
  chainTarget: ThresholdEcdsaChainTarget,
): Promise<WarmEcdsaSigningSessionStatus[]> {
  const statuses = await deps.statusReader.listEcdsaSigningSessionStatuses({
    walletId,
    chainTarget,
  });
  return await Promise.all(
    statuses.map(async (status) => {
      const walletBudgetStatus = await getWalletSigningBudgetAvailableStatusValue(
        {
          getAvailableStatus: deps.getWalletSigningBudgetStatus,
        },
        buildEcdsaLaneBudgetStatusCheck({
          key: status.key,
          keyHandle: status.lane.keyHandle,
          chainTarget: status.chainTarget,
          walletSigningSessionId: status.walletSigningSessionId,
          thresholdSessionId: status.sessionId,
        }),
      );
      return mergeWalletSigningBudgetStatus(status, walletBudgetStatus);
    }),
  );
}

function isRecordBackedEcdsaStatus(
  status: WarmEcdsaSigningSessionStatus | null,
): status is WarmEcdsaRecordBackedSigningSessionStatus {
  return Boolean(status && typeof status.walletSigningSessionId === 'string');
}

export async function scheduleThresholdEcdsaLoginPresignPrefill(
  deps: WarmCapabilitiesPublicDeps,
  args: {
    walletId: WalletId;
    chainTarget: ThresholdEcdsaChainTarget;
    thresholdEcdsaSessionRecord: ThresholdEcdsaSessionRecord;
    minRemainingUsesBeforePrefill?: number;
  },
): Promise<ThresholdEcdsaLoginPrefillResult> {
  return await scheduleThresholdEcdsaLoginPresignPrefillValue(
    {
      getWarmThresholdEcdsaSessionStatus: async (
        walletIdArg: WalletId,
        thresholdSessionId: string,
        chainTargetArg: ThresholdEcdsaChainTarget,
      ) => {
        const canonicalSessionId = deps.resolveCanonicalThresholdEcdsaSessionIdForWalletTarget(
          args.walletId,
          chainTargetArg,
        );
        if (canonicalSessionId && canonicalSessionId !== String(thresholdSessionId || '').trim()) {
          return {
            sessionId: canonicalSessionId,
            status: 'not_found',
          };
        }
        return await deps.statusReader.getEcdsaSigningSessionStatus({
          walletId: walletIdArg,
          chainTarget: chainTargetArg,
          thresholdSessionId,
        });
      },
      getSignerWorkerContext: deps.getSignerWorkerContext,
      resolveClientSigningShare32: deps.resolveClientSigningShare32,
      thresholdEcdsaPresignPoolPolicy: deps.thresholdEcdsaPresignPoolPolicy,
    },
    args,
  );
}

export async function hydrateSigningSession(
  deps: WarmCapabilitiesPublicDeps,
  args: HydrateSigningSessionInput,
): Promise<void> {
  await deps.hydrateSigningSession(args);
}

export async function clearVolatileWarmSigningMaterial(
  deps: WarmCapabilitiesPublicDeps,
  walletId?: WalletId,
): Promise<void> {
  await deps.clearVolatileWarmSigningMaterial(walletId);
}

export type { ThresholdEcdsaLoginPrefillResult };

export function createWarmCapabilitiesPublicApi(deps: WarmCapabilitiesPublicDeps) {
  return {
    persistThresholdEcdsaBootstrapForWalletTarget: (
      args: PersistThresholdEcdsaBootstrapForWalletTargetInput,
    ) => persistThresholdEcdsaBootstrapForWalletTarget(deps, args),
    getWarmThresholdEd25519SessionStatus: (nearAccountId: AccountId | string) =>
      getWarmThresholdEd25519SessionStatus(deps, toAccountId(nearAccountId)),
    getWarmThresholdEcdsaSessionStatus: (
      walletId: WalletId,
      chainTarget: ThresholdEcdsaChainTarget,
      thresholdSessionId: string,
    ) => getWarmThresholdEcdsaSessionStatus(deps, walletId, chainTarget, thresholdSessionId),
    listWarmThresholdEcdsaSessionStatuses: (
      walletId: WalletId,
      chainTarget: ThresholdEcdsaChainTarget,
    ) => listWarmThresholdEcdsaSessionStatuses(deps, walletId, chainTarget),
    scheduleThresholdEcdsaLoginPresignPrefill: (args: {
      walletId: WalletId;
      chainTarget: ThresholdEcdsaChainTarget;
      thresholdEcdsaSessionRecord: ThresholdEcdsaSessionRecord;
      minRemainingUsesBeforePrefill?: number;
    }) => scheduleThresholdEcdsaLoginPresignPrefill(deps, args),
    hydrateSigningSession: (args: HydrateSigningSessionInput) => hydrateSigningSession(deps, args),
    clearVolatileWarmSigningMaterial: (walletId?: WalletId) =>
      clearVolatileWarmSigningMaterial(deps, walletId),
  };
}

export type WarmCapabilitiesPublicApi = ReturnType<typeof createWarmCapabilitiesPublicApi>;
