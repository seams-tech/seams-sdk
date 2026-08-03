import type { WalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type {
  ClearVolatileWarmSessionMaterialCommand,
  VolatileWarmSessionMaterialClearAll,
  VolatileWarmSessionMaterialClearer,
} from '../../uiConfirm/uiConfirm.types';
import { listExactSealedSessionsForWallet } from '../persistence/sealedSessionStore';
import {
  createClearAllVolatileWarmSessionMaterialCommand,
  createClearVolatileWarmSessionMaterialCommand,
} from './volatileWarmMaterialCommands';
import {
  parseThresholdEd25519SessionId,
  type ThresholdEd25519SessionId,
} from '@shared/utils/domainIds';

export type ClearVolatileWarmSigningMaterialDeps = {
  touchConfirm: VolatileWarmSessionMaterialClearer | VolatileWarmSessionMaterialClearAll;
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

async function collectWarmSigningSessionIdsForWallet(
  walletId: WalletId,
): Promise<ThresholdEd25519SessionId[]> {
  const thresholdSessionIds = new Set<ThresholdEd25519SessionId>();
  const records = await Promise.all([
    listExactSealedSessionsForWallet({
      walletId,
      filter: { authMethod: 'passkey', curve: 'ed25519' },
    }),
    listExactSealedSessionsForWallet({
      walletId,
      filter: { authMethod: 'email_otp', curve: 'ed25519' },
    }),
  ]);
  for (const record of records.flat()) {
    const thresholdSessionId = parseThresholdEd25519SessionId(
      record.thresholdSessionIds.ed25519,
    );
    if (thresholdSessionId.ok) thresholdSessionIds.add(thresholdSessionId.value);
  }
  return [...thresholdSessionIds];
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

  const thresholdSessionIds =
    walletId != null ? await collectWarmSigningSessionIdsForWallet(walletId) : [];
  if (!hasVolatileWarmSessionMaterialClearer(deps.touchConfirm)) return;

  await Promise.all(
    thresholdSessionIds.map((thresholdSessionId) =>
      deps
        .clearVolatileThresholdSessionMaterial(
          createClearVolatileWarmSessionMaterialCommand(thresholdSessionId),
        )
        .catch(() => undefined),
    ),
  );
}
