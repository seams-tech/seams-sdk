import { __isWalletIframeHostMode } from '@/core/WalletIframe/host-mode';
import { onEmbeddedBaseChange, resolveWorkerBaseOrigin } from '@/core/walletRuntimePaths';
import type { SeamsConfigsReadonly } from '@/core/types/seams';
import type { UserPreferencesManager } from '../api/userPreferences';

export type RuntimeBootstrapDeps = {
  seamsPasskeyConfigs: SeamsConfigsReadonly;
  userPreferencesManager: Pick<UserPreferencesManager, 'initFromIndexedDB'>;
  getWorkerBaseOrigin: () => string;
  setWorkerBaseOrigin: (origin: string) => void;
};

function resolveInitialWorkerBaseOrigin(): string {
  return resolveWorkerBaseOrigin() || (typeof window !== 'undefined' ? window.location.origin : '');
}

export function initializeRuntimeBootstrap(deps: RuntimeBootstrapDeps): void {
  deps.setWorkerBaseOrigin(resolveInitialWorkerBaseOrigin());

  // Keep base origin updated if the wallet sets a new embedded base.
  if (typeof window !== 'undefined') {
    onEmbeddedBaseChange(() => {
      // Re-resolve through resolveWorkerBaseOrigin so cross-origin embedded bases
      // don't force worker URLs to an inaccessible origin.
      const origin = resolveInitialWorkerBaseOrigin();
      if (origin !== deps.getWorkerBaseOrigin()) {
        deps.setWorkerBaseOrigin(origin);
      }
    });
  }

  // Best-effort: load persisted preferences unless we are in app-origin iframe mode,
  // where the wallet origin owns persistence and the app should avoid IndexedDB.
  const shouldAvoidAppOriginIndexedDB =
    deps.seamsPasskeyConfigs.wallet.mode === 'iframe' && !__isWalletIframeHostMode();
  if (!shouldAvoidAppOriginIndexedDB) {
    void deps.userPreferencesManager.initFromIndexedDB().catch(() => undefined);
  }
}
