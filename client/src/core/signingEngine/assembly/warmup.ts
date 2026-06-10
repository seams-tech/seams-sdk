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
  activateAuthenticatedWalletState: (
    nearAccountId: AccountId,
    nearClient?: NearClient,
  ) => Promise<void>;
};

export type WorkerResourceWarmupDiagnostics = {
  kind: 'worker_resource_warmup_diagnostics_v1';
  authenticatedWalletStateMs: number;
  noncePrefetchMs: number;
  keyMaterialReadMs: number;
  uiConfirmPrewarmMs: number;
  signerWorkerPrewarmMs: number;
};

function roundWarmupDurationMs(startedAt: number): number {
  return Math.max(0, Math.round(performance.now() - startedAt));
}

async function measureBestEffortWarmupStep(operation: () => Promise<unknown>): Promise<number> {
  const startedAt = performance.now();
  try {
    await operation();
  } catch {
    // Warmup is observational and must not influence registration control flow.
  }
  return roundWarmupDurationMs(startedAt);
}

export function prewarmSignerWorkers(deps: WorkerResourceWarmupDeps): void {
  if (!deps.shouldPrewarmWorkers(deps.workerBaseOrigin)) return;
  deps.prewarmWorkers().catch(() => {});
}

export async function warmCriticalResources(
  deps: WorkerResourceWarmupDeps,
  nearAccountId?: string,
): Promise<WorkerResourceWarmupDiagnostics> {
  const accountId = nearAccountId ? toAccountId(nearAccountId) : null;
  const authenticatedWalletStateMs = accountId
    ? await measureBestEffortWarmupStep(() =>
        deps.activateAuthenticatedWalletState(accountId, deps.nearClient),
      )
    : 0;

  const noncePrefetchMs = await measureBestEffortWarmupStep(() =>
    deps.nonceCoordinator.prefetchNearContext({ nearClient: deps.nearClient }),
  );

  const keyMaterialReadMs = accountId
    ? await measureBestEffortWarmupStep(async () => {
        const signerSlot = await getLastLoggedInSignerSlot(accountId, deps.store).catch(() => 1);
        await getNearThresholdKeyMaterial(
          {
            clientDB: deps.store,
            keyMaterialStore: deps.store,
          },
          accountId,
          signerSlot,
        ).catch(() => null);
      })
    : 0;

  const shouldPrewarmWorkers = deps.shouldPrewarmWorkers(deps.workerBaseOrigin);
  const [uiConfirmPrewarmMs, signerWorkerPrewarmMs] = await Promise.all([
    measureBestEffortWarmupStep(() => deps.prewarmUiConfirmUi()),
    shouldPrewarmWorkers
      ? measureBestEffortWarmupStep(() => deps.prewarmWorkers())
      : Promise.resolve(0),
  ]);

  return {
    kind: 'worker_resource_warmup_diagnostics_v1',
    authenticatedWalletStateMs,
    noncePrefetchMs,
    keyMaterialReadMs,
    uiConfirmPrewarmMs,
    signerWorkerPrewarmMs,
  };
}
