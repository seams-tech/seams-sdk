import { getNearThresholdKeyMaterial } from '@/core/accountData/near/keyMaterial';
import type { AccountKeyMaterialStorePort } from '@/core/indexedDB/accountKeyMaterial';
import type { LastProfileState } from '@/core/indexedDB/passkeyClientDB.types';
import type { ProfileAccountContextPort } from '@/core/indexedDB/profileAccountProjection';
import type { NearClient } from '@/core/rpcClients/near/NearClient';
import type { NonceCoordinator } from '../nonce/NonceCoordinator';
import { toAccountId, type AccountId } from '@/core/types/accountIds';
import { getLastLoggedInSignerSlot } from '../webauthnAuth/device/signerSlot';

export type WorkerResourceWarmupStorePort = ProfileAccountContextPort &
  AccountKeyMaterialStorePort & {
    getLastProfileState: () => Promise<LastProfileState | null>;
  };

export type WorkerResourceWarmupDeps = {
  workerBaseOrigin: string;
  store: WorkerResourceWarmupStorePort;
  nearClient: NearClient;
  nonceCoordinator: Pick<NonceCoordinator, 'prefetchNearContext'>;
  prewarmWorkers: () => Promise<void>;
  shouldPrewarmWorkers: (workerBaseOrigin: string) => boolean;
  prewarmUiConfirmUi: () => Promise<void>;
  initializeCurrentUser: (nearAccountId: AccountId, nearClient?: NearClient) => Promise<void>;
};

export function prewarmSignerWorkers(deps: WorkerResourceWarmupDeps): void {
  if (!deps.shouldPrewarmWorkers(deps.workerBaseOrigin)) return;
  deps.prewarmWorkers().catch(() => {});
}

export async function warmCriticalResources(
  deps: WorkerResourceWarmupDeps,
  nearAccountId?: string,
): Promise<void> {
  // Initialize current user first (best-effort).
  if (nearAccountId) {
    await deps.initializeCurrentUser(toAccountId(nearAccountId), deps.nearClient).catch(() => null);
  }

  // Prefetch latest block/nonce context through the coordinator (best-effort).
  await deps.nonceCoordinator
    .prefetchNearContext({ nearClient: deps.nearClient })
    .catch(() => null);

  // Best-effort: open IndexedDB and warm key data for the account.
  if (nearAccountId) {
    const accountId = toAccountId(nearAccountId);
    const signerSlot = await getLastLoggedInSignerSlot(
      accountId,
      deps.store,
    ).catch(() => 1);
    await getNearThresholdKeyMaterial(
      {
        clientDB: deps.store,
        keyMaterialStore: deps.store,
      },
      accountId,
      signerSlot,
    ).catch(() => null);
  }

  const warmupTasks: Promise<unknown>[] = [deps.prewarmUiConfirmUi().catch(() => null)];
  if (deps.shouldPrewarmWorkers(deps.workerBaseOrigin)) {
    warmupTasks.push(deps.prewarmWorkers().catch(() => null));
  }
  await Promise.all(warmupTasks);
}
