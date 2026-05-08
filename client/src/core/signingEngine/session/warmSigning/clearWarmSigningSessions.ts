import type { AccountId } from '@/core/types/accountIds';
import type {
  WarmSessionMaterialClearAll,
  WarmSessionMaterialClearer,
} from '../../uiConfirm/types';
import {
  getStoredThresholdEd25519SessionRecordForAccount,
  listThresholdEcdsaRuntimeLanesForSubject,
  type ThresholdEcdsaSessionStoreDeps,
} from '../persistence/records';
import { toWalletSubjectId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { clearSigningSessionPrfFirstBestEffort } from './prfCache';

export type ClearWarmSigningSessionsDeps = {
  touchConfirm: WarmSessionMaterialClearer | WarmSessionMaterialClearAll;
  ecdsaSessions: ThresholdEcdsaSessionStoreDeps;
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

function collectWarmSigningSessionIdsForAccount(
  deps: Pick<ClearWarmSigningSessionsDeps, 'ecdsaSessions'>,
  nearAccountId: AccountId | string,
): string[] {
  const sessionIds = new Set<string>();
  const ed25519SessionId = String(
    getStoredThresholdEd25519SessionRecordForAccount(nearAccountId)?.thresholdSessionId || '',
  ).trim();
  if (ed25519SessionId) {
    sessionIds.add(ed25519SessionId);
  }
  for (const runtimeLane of listThresholdEcdsaRuntimeLanesForSubject(deps.ecdsaSessions, {
    subjectId: toWalletSubjectId(nearAccountId),
  })) {
    const ecdsaSessionId = String(runtimeLane.thresholdSessionId || '').trim();
    if (ecdsaSessionId) {
      sessionIds.add(ecdsaSessionId);
    }
  }
  return [...sessionIds];
}

export async function clearWarmSigningSessions(
  deps: ClearWarmSigningSessionsDeps,
  nearAccountId?: AccountId | string,
): Promise<void> {
  if (nearAccountId == null && hasWarmSessionMaterialClearAll(deps.touchConfirm)) {
    await deps.touchConfirm.clearAllWarmSessionMaterial().catch(() => undefined);
    return;
  }

  const sessionIds =
    nearAccountId != null ? collectWarmSigningSessionIdsForAccount(deps, nearAccountId) : [];
  if (!hasWarmSessionMaterialClearer(deps.touchConfirm)) return;
  const touchConfirm = deps.touchConfirm;

  await Promise.all(
    sessionIds.map((sessionId) =>
      clearSigningSessionPrfFirstBestEffort(touchConfirm, sessionId),
    ),
  );
}
