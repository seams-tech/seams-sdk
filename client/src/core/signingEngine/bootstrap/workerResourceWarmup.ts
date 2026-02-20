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
  initializeCurrentUser: (nearAccountId: AccountId, nearClient?: NearClient) => Promise<void>;
};

export function prewarmSignerWorkers(deps: WorkerResourceWarmupDeps): void {
  if (typeof window === 'undefined' || typeof window.Worker === 'undefined') return;
  // Avoid noisy SecurityError in cross-origin dev: only prewarm when same-origin.
  if (deps.workerBaseOrigin && deps.workerBaseOrigin !== window.location.origin) return;
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
    const deviceNumber = await getLastLoggedInDeviceNumber(accountId, deps.indexedDB.clientDB).catch(
      () => 1,
    );
    await Promise.all([
      deps.indexedDB.getNearLocalKeyMaterial(accountId, deviceNumber),
      deps.indexedDB.getNearThresholdKeyMaterial(accountId, deviceNumber),
    ]).catch(() => null);
  }

  // Warm signer workers in the background.
  prewarmSignerWorkers(deps);
}
