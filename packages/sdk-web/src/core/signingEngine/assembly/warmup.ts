import { getNearThresholdKeyMaterial } from '@/core/accountData/near/keyMaterial';
import type { AccountKeyMaterialStorePort } from '@/core/indexedDB/accountKeyMaterial';
import type { LastProfileState } from '@/core/indexedDB/passkeyClientDB.types';
import type { ProfileAccountContextPort } from '@/core/indexedDB/profileAccountProjection';
import type { NearClient } from '@/core/rpcClients/near/NearClient';
import type { NonceCoordinator } from '../nonce/NonceCoordinator';
import { toAccountId, type AccountId } from '@/core/types/accountIds';
import type { WalletId } from '../interfaces/ecdsaChainTarget';
import { getLastLoggedInSignerSlot } from '../webauthnAuth/device/signerSlot';
import type { NearAccountBinding } from '@shared/utils/walletCapabilityBindings';

export type WorkerResourceWarmupStorePort = ProfileAccountContextPort &
  AccountKeyMaterialStorePort & {
    getLastProfileState: () => Promise<LastProfileState | null>;
  };

export type WorkerResourceWarmupPredicate = (workerBaseOrigin: string) => boolean;

export type WorkerResourceWarmupPolicy =
  | {
      kind: 'local_worker_warmup_disabled';
      shouldPrewarmWorkers: WorkerResourceWarmupPredicate;
      shouldPrewarmUiConfirmUi: WorkerResourceWarmupPredicate;
    }
  | {
      kind: 'local_worker_warmup_enabled';
      shouldPrewarmWorkers: WorkerResourceWarmupPredicate;
      shouldPrewarmUiConfirmUi: WorkerResourceWarmupPredicate;
    };

export type WorkerResourceWarmupDeps = {
  workerBaseOrigin: string;
  store: WorkerResourceWarmupStorePort;
  nearClient: NearClient;
  nonceCoordinator: Pick<NonceCoordinator, 'prefetchNearContext'>;
  prewarmWorkers: () => Promise<void>;
  workerWarmupPolicy: WorkerResourceWarmupPolicy;
  prewarmUiConfirmUi: () => Promise<void>;
  activateAuthenticatedWalletState: (args: {
    walletId: WalletId;
    nearAccountId: AccountId;
    nearClient?: NearClient;
  }) => Promise<void>;
};

export type WorkerResourceWarmupDiagnostics = {
  kind: 'worker_resource_warmup_diagnostics_v1';
  authenticatedWalletStateMs: number;
  noncePrefetchMs: number;
  keyMaterialReadMs: number;
  uiConfirmPrewarmMs: number;
  signerWorkerPrewarmMs: number;
};

export type WorkerResourceWarmupAccountContext =
  | {
      kind: 'none';
      account?: never;
    }
  | {
      kind: 'near_account_bound';
      account: NearAccountBinding;
};

function shouldPrewarmWorkers(deps: WorkerResourceWarmupDeps): boolean {
  return deps.workerWarmupPolicy.shouldPrewarmWorkers(deps.workerBaseOrigin);
}

function shouldPrewarmUiConfirmUi(deps: WorkerResourceWarmupDeps): boolean {
  return deps.workerWarmupPolicy.shouldPrewarmUiConfirmUi(deps.workerBaseOrigin);
}

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
  if (!shouldPrewarmWorkers(deps)) return;
  deps.prewarmWorkers().catch(() => {});
}

export async function warmCriticalResources(
  deps: WorkerResourceWarmupDeps,
  accountContext: WorkerResourceWarmupAccountContext = { kind: 'none' },
): Promise<WorkerResourceWarmupDiagnostics> {
  const accountBinding =
    accountContext.kind === 'near_account_bound'
      ? accountContext.account
      : null;
  const accountId = accountBinding ? toAccountId(accountBinding.nearAccountId) : null;
  const authenticatedWalletStateMs = accountBinding && accountId
    ? await measureBestEffortWarmupStep(() =>
        deps.activateAuthenticatedWalletState({
          walletId: accountBinding.wallet.walletId,
          nearAccountId: accountId,
          nearClient: deps.nearClient,
        }),
      )
    : 0;

  const noncePrefetchMs = await measureBestEffortWarmupStep(() =>
    deps.nonceCoordinator.prefetchNearContext({
      kind: 'initialized_state',
      nearClient: deps.nearClient,
    }),
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

  const canPrewarmUiConfirmUi = shouldPrewarmUiConfirmUi(deps);
  const canPrewarmSignerWorkers = shouldPrewarmWorkers(deps);
  const [uiConfirmPrewarmMs, signerWorkerPrewarmMs] = await Promise.all([
    canPrewarmUiConfirmUi
      ? measureBestEffortWarmupStep(() => deps.prewarmUiConfirmUi())
      : Promise.resolve(0),
    canPrewarmSignerWorkers
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
