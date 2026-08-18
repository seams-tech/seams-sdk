import { resolveWorkerBaseOrigin } from './workers';

/**
 * The wallet custody ceremony worker's URL.
 *
 * Registration-only: this worker loads a wasm module that links both protocol
 * crates, so nothing on the recurring signing path should resolve it.
 */
export function resolveWalletCustodyCeremonyWorkerUrl(opts?: { baseOrigin?: string }): string {
  const baseOrigin =
    opts?.baseOrigin ||
    resolveWorkerBaseOrigin() ||
    (typeof window !== 'undefined' ? window.location.origin : '') ||
    'https://invalid.local';

  const override =
    typeof window !== 'undefined' &&
    typeof (window as { __W3A_WALLET_CUSTODY_CEREMONY_WORKER_URL__?: unknown })
      .__W3A_WALLET_CUSTODY_CEREMONY_WORKER_URL__ === 'string'
      ? String(
          (window as { __W3A_WALLET_CUSTODY_CEREMONY_WORKER_URL__?: string })
            .__W3A_WALLET_CUSTODY_CEREMONY_WORKER_URL__,
        )
      : '';
  const candidate = override || '/sdk/workers/wallet-custody-ceremony.worker.js';
  if (/^https?:\/\//i.test(candidate)) return candidate;
  return new URL(candidate, baseOrigin).toString();
}
