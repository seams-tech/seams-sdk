import type { WalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type {
  ClearVolatileWarmSessionMaterialCommand,
  VolatileWarmSessionMaterialClearAll,
  VolatileWarmSessionMaterialClearer,
} from '../../uiConfirm/uiConfirm.types';
import {
  getStoredThresholdEd25519SessionRecordForAccount,
  listThresholdEcdsaRuntimeLanesForWallet,
  type ThresholdEcdsaSessionStoreDeps,
} from '../persistence/records';
import {
  createClearAllVolatileWarmSessionMaterialCommand,
  createClearVolatileWarmSessionMaterialCommand,
} from './volatileWarmMaterialCommands';
import {
  parseVolatileWarmSessionId,
  type VolatileWarmSessionId,
} from './volatileWarmSessionId';

export type ClearVolatileWarmSigningMaterialDeps = {
  touchConfirm: VolatileWarmSessionMaterialClearer | VolatileWarmSessionMaterialClearAll;
  ecdsaSessions: ThresholdEcdsaSessionStoreDeps;
  clearVolatileThresholdSessionMaterial: (
    command: ClearVolatileWarmSessionMaterialCommand,
  ) => Promise<void>;
};

function hasVolatileWarmSessionMaterialClearAll(
  value: unknown,
): value is VolatileWarmSessionMaterialClearer & VolatileWarmSessionMaterialClearAll {
  return (
    typeof (value as { clearAllVolatileWarmSessionMaterial?: unknown })
      ?.clearAllVolatileWarmSessionMaterial === 'function'
  );
}

function hasVolatileWarmSessionMaterialClearer(
  value: unknown,
): value is VolatileWarmSessionMaterialClearer {
  return (
    typeof (value as { clearVolatileWarmSessionMaterial?: unknown })
      ?.clearVolatileWarmSessionMaterial === 'function'
  );
}

function collectWarmSigningSessionIdsForWallet(
  deps: Pick<ClearVolatileWarmSigningMaterialDeps, 'ecdsaSessions'>,
  walletId: WalletId,
): VolatileWarmSessionId[] {
  const sessionIds = new Set<VolatileWarmSessionId>();
  const ed25519SessionId = parseVolatileWarmSessionId(
    getStoredThresholdEd25519SessionRecordForAccount(walletId)?.thresholdSessionId,
  );
  if (ed25519SessionId) {
    sessionIds.add(ed25519SessionId);
  }
  for (const runtimeLane of listThresholdEcdsaRuntimeLanesForWallet(
    deps.ecdsaSessions,
    walletId,
  )) {
    const ecdsaSessionId = parseVolatileWarmSessionId(runtimeLane.thresholdSessionId);
    if (ecdsaSessionId) {
      sessionIds.add(ecdsaSessionId);
    }
  }
  return [...sessionIds];
}

export async function clearVolatileWarmSigningMaterial(
  deps: ClearVolatileWarmSigningMaterialDeps,
  walletId?: WalletId,
): Promise<void> {
  if (walletId == null && hasVolatileWarmSessionMaterialClearAll(deps.touchConfirm)) {
    await deps.touchConfirm
      .clearAllVolatileWarmSessionMaterial(createClearAllVolatileWarmSessionMaterialCommand())
      .catch(() => undefined);
    return;
  }

  const sessionIds = walletId != null ? collectWarmSigningSessionIdsForWallet(deps, walletId) : [];
  if (!hasVolatileWarmSessionMaterialClearer(deps.touchConfirm)) return;

  await Promise.all(
    sessionIds.map((sessionId) =>
      deps
        .clearVolatileThresholdSessionMaterial(
          createClearVolatileWarmSessionMaterialCommand(sessionId),
        )
        .catch(() => undefined),
    ),
  );
}
