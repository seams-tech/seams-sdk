import { __isWalletIframeHostMode } from '@/core/browser/walletIframe/host-mode';
import type {
  WorkerResourceWarmupPolicy,
  WorkerResourceWarmupPredicate,
} from '@/core/signingEngine/assembly/warmup';
import type { SeamsConfigsReadonly } from '@/core/types/seams';

function shouldSkipBrowserWorkerWarmup(_workerBaseOrigin: string): boolean {
  return false;
}

export function shouldPrewarmBrowserWorkers(workerBaseOrigin: string): boolean {
  if (typeof window === 'undefined' || typeof window.Worker === 'undefined') return false;
  if (workerBaseOrigin && workerBaseOrigin !== window.location.origin) return false;
  return true;
}

const DISABLED_BROWSER_WORKER_WARMUP_POLICY: WorkerResourceWarmupPolicy = {
  kind: 'local_worker_warmup_disabled',
  shouldPrewarmWorkers: shouldSkipBrowserWorkerWarmup,
  shouldPrewarmUiConfirmUi: shouldSkipBrowserWorkerWarmup,
};

const SAME_ORIGIN_BROWSER_WORKER_WARMUP_POLICY: WorkerResourceWarmupPolicy = {
  kind: 'local_worker_warmup_enabled',
  shouldPrewarmWorkers: shouldPrewarmBrowserWorkers,
  shouldPrewarmUiConfirmUi: shouldPrewarmBrowserWorkers,
};

function isAppOriginIframeClient(configs: SeamsConfigsReadonly): boolean {
  return configs.wallet.mode === 'iframe' && !__isWalletIframeHostMode();
}

export function resolveBrowserWorkerWarmupPolicy(
  configs: SeamsConfigsReadonly,
): WorkerResourceWarmupPolicy {
  if (isAppOriginIframeClient(configs)) return DISABLED_BROWSER_WORKER_WARMUP_POLICY;
  return SAME_ORIGIN_BROWSER_WORKER_WARMUP_POLICY;
}

export type BrowserWorkerWarmupPredicate = WorkerResourceWarmupPredicate;
