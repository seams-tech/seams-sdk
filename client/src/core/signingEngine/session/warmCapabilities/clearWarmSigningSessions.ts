import type { AccountId } from '@/core/types/accountIds';
import type {
  WarmSessionMaterialClearAll,
  WarmSessionMaterialClearer,
} from '../../uiConfirm/types';
import {
  getStoredThresholdEd25519SessionRecordForAccount,
  listThresholdEcdsaRuntimeLanesForWallet,
  type ThresholdEcdsaSessionStoreDeps,
} from '../persistence/records';

export type ClearWarmSigningSessionsDeps = {
  touchConfirm: WarmSessionMaterialClearer | WarmSessionMaterialClearAll;
  ecdsaSessions: ThresholdEcdsaSessionStoreDeps;
  clearThresholdSessionMaterial: (sessionId: string) => Promise<void>;
};

function hasWarmSessionMaterialClearAll(
  value: unknown,
): value is WarmSessionMaterialClearer & WarmSessionMaterialClearAll {
  return (
    typeof (value as { clearAllWarmSessionMaterial?: unknown })?.clearAllWarmSessionMaterial ===
    'function'
  );
}

function hasWarmSessionMaterialClearer(value: unknown): value is WarmSessionMaterialClearer {
  return (
    typeof (value as { clearWarmSessionMaterial?: unknown })?.clearWarmSessionMaterial ===
    'function'
  );
}

function collectWarmSigningSessionIdsForWallet(
  deps: Pick<ClearWarmSigningSessionsDeps, 'ecdsaSessions'>,
  walletId: AccountId | string,
): string[] {
  const sessionIds = new Set<string>();
  const ed25519SessionId = String(
    getStoredThresholdEd25519SessionRecordForAccount(walletId)?.thresholdSessionId || '',
  ).trim();
  if (ed25519SessionId) {
    sessionIds.add(ed25519SessionId);
  }
  for (const runtimeLane of listThresholdEcdsaRuntimeLanesForWallet(
    deps.ecdsaSessions,
    walletId,
  )) {
    const ecdsaSessionId = String(runtimeLane.thresholdSessionId || '').trim();
    if (ecdsaSessionId) {
      sessionIds.add(ecdsaSessionId);
    }
  }
  return [...sessionIds];
}

export async function clearWarmSigningSessions(
  deps: ClearWarmSigningSessionsDeps,
  walletId?: AccountId | string,
): Promise<void> {
  if (walletId == null && hasWarmSessionMaterialClearAll(deps.touchConfirm)) {
    await deps.touchConfirm.clearAllWarmSessionMaterial().catch(() => undefined);
    return;
  }

  const sessionIds = walletId != null ? collectWarmSigningSessionIdsForWallet(deps, walletId) : [];
  if (!hasWarmSessionMaterialClearer(deps.touchConfirm)) return;
  const touchConfirm = deps.touchConfirm;

  await Promise.all(
    sessionIds.map((sessionId) => deps.clearThresholdSessionMaterial(sessionId).catch(() => undefined)),
  );
}
