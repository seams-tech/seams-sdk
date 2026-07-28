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
import { ed25519WalletBudgetOwner } from '../budget/budget';
import { getStoredThresholdEd25519SessionRecordForAccount as getStoredThresholdEd25519SessionRecordForAccountValue } from '../persistence/records';
import {
  scheduleRouterAbEcdsaDerivationLoginPresignaturePrefill as scheduleRouterAbEcdsaDerivationLoginPresignaturePrefillValue,
  type RouterAbEcdsaDerivationLoginPresignaturePrefillResult,
} from './ecdsaLoginPrefill';
import type { ThresholdEcdsaSessionBootstrapResult } from '../../threshold/ecdsa/activation';
import type { ThresholdEcdsaBootstrapSignerAuth } from './ecdsaBootstrapPersistence';
import type { ExactEcdsaSealedRuntime } from '../material/ecdsaSealedRuntime';
import type { ActiveEcdsaCapabilityManifest } from '../material/ecdsaCapabilityManifest';
import type { ThresholdWarmSessionStatusReader } from './types';

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
    'getEd25519SigningSessionStatus'
  >;
  persistThresholdEcdsaBootstrapForWalletTarget: (
    args: PersistThresholdEcdsaBootstrapForWalletTargetInput,
  ) => Promise<void>;
  hydrateSigningSession: (args: HydrateSigningSessionInput) => Promise<void>;
  clearVolatileWarmSigningMaterial: (walletId?: WalletId) => Promise<void>;
  getWalletSigningBudgetStatus: WalletSigningBudgetAvailableStatusDeps['getAvailableStatus'];
  getSignerWorkerContext: Parameters<
    typeof scheduleRouterAbEcdsaDerivationLoginPresignaturePrefillValue
  >[0]['getSignerWorkerContext'];
  resolveClientSigningMaterialSource: Parameters<
    typeof scheduleRouterAbEcdsaDerivationLoginPresignaturePrefillValue
  >[0]['resolveClientSigningMaterialSource'];
  routerAbEcdsaDerivationPresignaturePoolPolicy?: Parameters<
    typeof scheduleRouterAbEcdsaDerivationLoginPresignaturePrefillValue
  >[0]['routerAbEcdsaDerivationPresignaturePoolPolicy'];
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

export async function scheduleRouterAbEcdsaDerivationLoginPresignaturePrefill(
  deps: WarmCapabilitiesPublicDeps,
  args: {
    walletId: WalletId;
    chainTarget: ThresholdEcdsaChainTarget;
    manifest: ActiveEcdsaCapabilityManifest;
    runtime: ExactEcdsaSealedRuntime;
    minRemainingUsesBeforePrefill?: number;
  },
): Promise<RouterAbEcdsaDerivationLoginPresignaturePrefillResult> {
  return await scheduleRouterAbEcdsaDerivationLoginPresignaturePrefillValue(
    {
      getSignerWorkerContext: deps.getSignerWorkerContext,
      resolveClientSigningMaterialSource: deps.resolveClientSigningMaterialSource,
      routerAbEcdsaDerivationPresignaturePoolPolicy: deps.routerAbEcdsaDerivationPresignaturePoolPolicy,
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

export type { RouterAbEcdsaDerivationLoginPresignaturePrefillResult };
