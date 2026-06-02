import type { UnifiedIndexedDBManager } from '@/core/indexedDB';
import { getNearThresholdKeyMaterial } from '@/core/accountData/near/keyMaterial';
import type { NearClient } from '@/core/rpcClients/near/NearClient';
import type { NonceCoordinator } from '../nonce/NonceCoordinator';
import { toAccountId, type AccountId } from '@/core/types/accountIds';
import { getLastLoggedInSignerSlot } from '../webauthnAuth/device/signerSlot';

export type WorkerResourceWarmupDeps = {
  workerBaseOrigin: string;
  indexedDB: UnifiedIndexedDBManager;
  nearClient: NearClient;
  nonceCoordinator: Pick<NonceCoordinator, 'prefetchNearContext'>;
  prewarmWorkers: () => Promise<void>;
  prewarmUiConfirmUi: () => Promise<void>;
  initializeCurrentUser: (nearAccountId: AccountId, nearClient?: NearClient) => Promise<void>;
};

function shouldPrewarmBrowserWorkers(deps: WorkerResourceWarmupDeps): boolean {
  if (typeof window === 'undefined' || typeof window.Worker === 'undefined') return false;
  // Avoid noisy SecurityError in cross-origin dev: only prewarm when same-origin.
  if (deps.workerBaseOrigin && deps.workerBaseOrigin !== window.location.origin) return false;
  return true;
}

export function prewarmSignerWorkers(deps: WorkerResourceWarmupDeps): void {
  if (!shouldPrewarmBrowserWorkers(deps)) return;
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
      deps.indexedDB,
    ).catch(() => 1);
    await getNearThresholdKeyMaterial(
      {
        clientDB: deps.indexedDB,
        keyMaterialStore: deps.indexedDB,
      },
      accountId,
      signerSlot,
    ).catch(() => null);
  }

  const warmupTasks: Promise<unknown>[] = [deps.prewarmUiConfirmUi().catch(() => null)];
  if (shouldPrewarmBrowserWorkers(deps)) {
    warmupTasks.push(deps.prewarmWorkers().catch(() => null));
  }
  await Promise.all(warmupTasks);
}
