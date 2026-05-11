import type { AccountId } from '@/core/types/accountIds';
import type { SigningSessionStatus } from '@/core/types/seams';
import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdEcdsaSecp256k1KeyRef } from '../../interfaces/signing';
import {
  buildWalletBudgetStatusCheckForSession,
  getWalletSigningBudgetAvailableStatus as getWalletSigningBudgetAvailableStatusValue,
  mergeWalletSigningBudgetStatus,
  type WalletSigningBudgetAvailableStatusDeps,
} from '../budget/budgetStatusReader';
import { buildThresholdBudgetStatusCheck } from '../budget/budget';
import {
  getStoredThresholdEd25519SessionRecordForAccount as getStoredThresholdEd25519SessionRecordForAccountValue,
} from '../persistence/records';
import {
  scheduleThresholdEcdsaLoginPresignPrefill as scheduleThresholdEcdsaLoginPresignPrefillValue,
  type ThresholdEcdsaLoginPrefillResult,
} from './ecdsaLoginPrefill';
import type { ThresholdEcdsaSessionBootstrapResult } from '../../threshold/ecdsa/activation';
import type { ThresholdEcdsaSmartAccountBootstrapInput } from './ecdsaBootstrapPersistence';
import type {
  WarmEcdsaRecordBackedSigningSessionStatus,
  WarmEcdsaSigningSessionStatus,
  ThresholdWarmSessionStatusReader,
} from './types';

export type PersistThresholdEcdsaBootstrapChainAccountInput = {
  nearAccountId: AccountId | string;
  chainTarget: ThresholdEcdsaChainTarget;
  bootstrap: ThresholdEcdsaSessionBootstrapResult;
  smartAccount?: ThresholdEcdsaSmartAccountBootstrapInput;
  deployment?: {
    deployed: boolean;
    deploymentTxHash?: string;
  };
  ensureEmailOtpNearAccountMapping?: boolean;
};

export type HydrateSigningSessionInput = {
  sessionId: string;
  prfFirstB64u: string;
  expiresAtMs: number;
  remainingUses: number;
  transport?: {
    curve?: 'ed25519' | 'ecdsa';
    relayerUrl?: string;
    thresholdSessionAuthToken?: string;
    keyVersion?: string;
    shamirPrimeB64u?: string;
  };
};

export type WarmCapabilitiesPublicDeps = {
  statusReader: Pick<
    ThresholdWarmSessionStatusReader,
    'getEd25519SigningSessionStatus' | 'getEcdsaSigningSessionStatus' | 'listEcdsaSigningSessionStatuses'
  >;
  persistThresholdEcdsaBootstrapChainAccount: (
    args: PersistThresholdEcdsaBootstrapChainAccountInput,
  ) => Promise<void>;
  hydrateSigningSession: (args: HydrateSigningSessionInput) => Promise<void>;
  clearWarmSigningSessions: (nearAccountId?: AccountId | string) => Promise<void>;
  getWalletSigningBudgetStatus: WalletSigningBudgetAvailableStatusDeps['getAvailableStatus'];
  resolveCanonicalThresholdEcdsaSessionIdForChain: (
    nearAccountId: AccountId | string,
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

export async function persistThresholdEcdsaBootstrapChainAccount(
  deps: WarmCapabilitiesPublicDeps,
  args: PersistThresholdEcdsaBootstrapChainAccountInput,
): Promise<void> {
  await deps.persistThresholdEcdsaBootstrapChainAccount(args);
}

export async function getWarmThresholdEd25519SessionStatus(
  deps: WarmCapabilitiesPublicDeps,
  nearAccountId: AccountId | string,
): Promise<SigningSessionStatus | null> {
  const status = await deps.statusReader.getEd25519SigningSessionStatus(nearAccountId);
  const record = getStoredThresholdEd25519SessionRecordForAccountValue(nearAccountId);
  const walletSigningSessionId = String(record?.walletSigningSessionId || '').trim();
  const budgetStatusCheck = walletSigningSessionId
    ? buildWalletBudgetStatusCheckForSession({
        nearAccountId,
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
  nearAccountId: AccountId | string,
  chainTarget: ThresholdEcdsaChainTarget,
  thresholdSessionId: string,
): Promise<WarmEcdsaSigningSessionStatus | null> {
  const status = await deps.statusReader.getEcdsaSigningSessionStatus({
    nearAccountId,
    chainTarget,
    thresholdSessionId,
  });
  const walletBudgetStatus = isRecordBackedEcdsaStatus(status)
    ? await getWalletSigningBudgetAvailableStatusValue(
        {
          getAvailableStatus: deps.getWalletSigningBudgetStatus,
        },
        buildThresholdBudgetStatusCheck({
          nearAccountId,
          walletSigningSessionId: status.walletSigningSessionId,
          targetThresholdSessionIds: [thresholdSessionId],
        }),
      )
    : null;
  if (!status) return walletBudgetStatus as WarmEcdsaSigningSessionStatus | null;
  return mergeWalletSigningBudgetStatus(status, walletBudgetStatus);
}

export async function listWarmThresholdEcdsaSessionStatuses(
  deps: WarmCapabilitiesPublicDeps,
  nearAccountId: AccountId | string,
  chainTarget: ThresholdEcdsaChainTarget,
): Promise<WarmEcdsaSigningSessionStatus[]> {
  const statuses = await deps.statusReader.listEcdsaSigningSessionStatuses({
    nearAccountId,
    chainTarget,
  });
  return await Promise.all(
    statuses.map(async (status) => {
      const walletBudgetStatus = await getWalletSigningBudgetAvailableStatusValue(
        {
          getAvailableStatus: deps.getWalletSigningBudgetStatus,
        },
        buildThresholdBudgetStatusCheck({
          nearAccountId,
          walletSigningSessionId: status.walletSigningSessionId,
          targetThresholdSessionIds: [status.sessionId],
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
    nearAccountId: AccountId | string;
    chainTarget: ThresholdEcdsaChainTarget;
    thresholdEcdsaKeyRef: ThresholdEcdsaSecp256k1KeyRef;
    minRemainingUsesBeforePrefill?: number;
  },
): Promise<ThresholdEcdsaLoginPrefillResult> {
  return await scheduleThresholdEcdsaLoginPresignPrefillValue(
    {
      getWarmThresholdEcdsaSessionStatus: async (
        nearAccountIdArg: AccountId | string,
        thresholdSessionId: string,
        chainTargetArg: ThresholdEcdsaChainTarget,
      ) => {
        const canonicalSessionId = deps.resolveCanonicalThresholdEcdsaSessionIdForChain(
          nearAccountIdArg,
          chainTargetArg,
        );
        if (canonicalSessionId && canonicalSessionId !== String(thresholdSessionId || '').trim()) {
          return {
            sessionId: canonicalSessionId,
            status: 'not_found',
          };
        }
        return await deps.statusReader.getEcdsaSigningSessionStatus({
          nearAccountId: nearAccountIdArg,
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

export async function clearWarmSigningSessions(
  deps: WarmCapabilitiesPublicDeps,
  nearAccountId?: AccountId | string,
): Promise<void> {
  await deps.clearWarmSigningSessions(nearAccountId);
}

export type { ThresholdEcdsaLoginPrefillResult };

export function createWarmCapabilitiesPublicApi(deps: WarmCapabilitiesPublicDeps) {
  return {
    persistThresholdEcdsaBootstrapChainAccount: (
      args: PersistThresholdEcdsaBootstrapChainAccountInput,
    ) => persistThresholdEcdsaBootstrapChainAccount(deps, args),
    getWarmThresholdEd25519SessionStatus: (nearAccountId: AccountId | string) =>
      getWarmThresholdEd25519SessionStatus(deps, nearAccountId),
    getWarmThresholdEcdsaSessionStatus: (
      nearAccountId: AccountId | string,
      chainTarget: ThresholdEcdsaChainTarget,
      thresholdSessionId: string,
    ) => getWarmThresholdEcdsaSessionStatus(deps, nearAccountId, chainTarget, thresholdSessionId),
    listWarmThresholdEcdsaSessionStatuses: (
      nearAccountId: AccountId | string,
      chainTarget: ThresholdEcdsaChainTarget,
    ) => listWarmThresholdEcdsaSessionStatuses(deps, nearAccountId, chainTarget),
    scheduleThresholdEcdsaLoginPresignPrefill: (args: {
      nearAccountId: AccountId | string;
      chainTarget: ThresholdEcdsaChainTarget;
      thresholdEcdsaKeyRef: ThresholdEcdsaSecp256k1KeyRef;
      minRemainingUsesBeforePrefill?: number;
    }) => scheduleThresholdEcdsaLoginPresignPrefill(deps, args),
    hydrateSigningSession: (args: HydrateSigningSessionInput) => hydrateSigningSession(deps, args),
    clearWarmSigningSessions: (nearAccountId?: AccountId | string) =>
      clearWarmSigningSessions(deps, nearAccountId),
  };
}

export type WarmCapabilitiesPublicApi = ReturnType<typeof createWarmCapabilitiesPublicApi>;
