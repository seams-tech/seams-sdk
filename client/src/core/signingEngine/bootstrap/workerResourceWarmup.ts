import type { UnifiedIndexedDBManager } from '@/core/indexedDB';
import type { NearClient } from '@/core/rpcClients/near/NearClient';
import type { NonceManager } from '@/core/rpcClients/near/nonceManager';
import { toAccountId, type AccountId } from '@/core/types/accountIds';
import { getLastLoggedInDeviceNumber } from '../signers/webauthn/device/getDeviceNumber';

export type WorkerResourceWarmupDeps = {
  workerBaseOrigin: string;
  indexedDB: UnifiedIndexedDBManager;
  nearClient: NearClient;
  nonceManager: Pick<NonceManager, 'prefetchBlockheight'>;
  prewarmWorkers: () => Promise<void>;
  initializeTouchConfirm: () => Promise<void>;
  prewarmTouchConfirmUi: () => Promise<void>;
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

  // Prefetch latest block/nonce context (best-effort).
  await deps.nonceManager.prefetchBlockheight(deps.nearClient).catch(() => null);

  // Best-effort: open IndexedDB and warm key data for the account.
  if (nearAccountId) {
    const accountId = toAccountId(nearAccountId);
    const deviceNumber = await getLastLoggedInDeviceNumber(
      accountId,
      deps.indexedDB.clientDB,
    ).catch(() => 1);
    await Promise.all([
      deps.indexedDB.getNearLocalKeyMaterial(accountId, deviceNumber),
      deps.indexedDB.getNearThresholdKeyMaterial(accountId, deviceNumber),
    ]).catch(() => null);
  }

  const warmupTasks: Promise<unknown>[] = [deps.prewarmTouchConfirmUi().catch(() => null)];
  if (shouldPrewarmBrowserWorkers(deps)) {
    warmupTasks.push(deps.prewarmWorkers().catch(() => null));
    warmupTasks.push(deps.initializeTouchConfirm().catch(() => null));
  }
  await Promise.all(warmupTasks);
}
