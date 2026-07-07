import type { AccountId } from '@/core/types/accountIds';
import type { SigningSessionStatus } from '@/core/types/seams';
import type { WarmSessionSealTransportInput } from '@/core/types/secure-confirm-worker';
import type { WarmSessionMaterialWriteDiagnostics } from './types';
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
import { buildEcdsaLaneBudgetStatusCheck, ed25519WalletBudgetOwner } from '../budget/budget';
import { getStoredThresholdEd25519SessionRecordForAccount as getStoredThresholdEd25519SessionRecordForAccountValue } from '../persistence/records';
import {
  scheduleRouterAbEcdsaHssLoginPresignaturePrefill as scheduleRouterAbEcdsaHssLoginPresignaturePrefillValue,
  type RouterAbEcdsaHssLoginPresignaturePrefillResult,
} from './ecdsaLoginPrefill';
import type { ThresholdEcdsaSessionBootstrapResult } from '../../threshold/ecdsa/activation';
import type { ThresholdEcdsaBootstrapSignerAuth } from './ecdsaBootstrapPersistence';
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
  signerAuth: ThresholdEcdsaBootstrapSignerAuth;
};

export type HydrateSigningSessionInput = {
  sessionId: string;
  prfFirstB64u: string;
  expiresAtMs: number;
  remainingUses: number;
  transport?: WarmSessionSealTransportInput;
  diagnostics?: WarmSessionMaterialWriteDiagnostics;
};

export type WarmCapabilitiesPublicDeps = {
  statusReader: Pick<
    ThresholdWarmSessionStatusReader,
    | 'getEd25519SigningSessionStatus'
    | 'getEcdsaSigningSessionStatus'
    | 'listEcdsaSigningSessionStatuses'
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
    typeof scheduleRouterAbEcdsaHssLoginPresignaturePrefillValue
  >[0]['getSignerWorkerContext'];
  resolveClientSigningMaterialSource: Parameters<
    typeof scheduleRouterAbEcdsaHssLoginPresignaturePrefillValue
  >[0]['resolveClientSigningMaterialSource'];
  routerAbEcdsaHssPresignaturePoolPolicy?: Parameters<
    typeof scheduleRouterAbEcdsaHssLoginPresignaturePrefillValue
  >[0]['routerAbEcdsaHssPresignaturePoolPolicy'];
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
  const signingGrantId = String(record?.signingGrantId || '').trim();
  const recordWalletId = String(record?.walletId || '').trim();
  const budgetStatusCheck =
    signingGrantId && recordWalletId
      ? buildWalletBudgetStatusCheckForSession({
          owner: ed25519WalletBudgetOwner(recordWalletId),
          signingGrantId,
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
          keyHandle: status.lane.identity.signer.keyHandle,
          auth: status.lane.auth,
          chainTarget: status.chainTarget,
          signingGrantId: status.signingGrantId,
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
          keyHandle: status.lane.identity.signer.keyHandle,
          auth: status.lane.auth,
          chainTarget: status.chainTarget,
          signingGrantId: status.signingGrantId,
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
  return Boolean(status && typeof status.signingGrantId === 'string');
}

export async function scheduleRouterAbEcdsaHssLoginPresignaturePrefill(
  deps: WarmCapabilitiesPublicDeps,
  args: {
    walletId: WalletId;
    chainTarget: ThresholdEcdsaChainTarget;
    thresholdEcdsaSessionRecord: ThresholdEcdsaSessionRecord;
    minRemainingUsesBeforePrefill?: number;
  },
): Promise<RouterAbEcdsaHssLoginPresignaturePrefillResult> {
  return await scheduleRouterAbEcdsaHssLoginPresignaturePrefillValue(
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
      resolveClientSigningMaterialSource: deps.resolveClientSigningMaterialSource,
      routerAbEcdsaHssPresignaturePoolPolicy: deps.routerAbEcdsaHssPresignaturePoolPolicy,
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

export type { RouterAbEcdsaHssLoginPresignaturePrefillResult };
