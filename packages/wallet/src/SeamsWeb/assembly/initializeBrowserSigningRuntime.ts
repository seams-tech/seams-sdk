import { __isWalletIframeHostMode } from '@/core/browser/walletIframe/host-mode';
import type { UserPreferencesManager } from '@/core/signingEngine/session/userPreferences';
import type { SeamsConfigsReadonly } from '@/core/types/seams';
import { onEmbeddedBaseChange, resolveWorkerBaseOrigin } from '@/core/walletRuntimePaths';

export type InitializeBrowserSigningRuntimeArgs = {
  config: SeamsConfigsReadonly;
  userPreferencesManager: Pick<UserPreferencesManager, 'initFromIndexedDB'>;
  getWorkerBaseOrigin: () => string;
  setWorkerBaseOrigin: (origin: string) => void;
};

function resolveInitialWorkerBaseOrigin(): string {
  return resolveWorkerBaseOrigin() || (typeof window !== 'undefined' ? window.location.origin : '');
}

export function initializeBrowserSigningRuntime(args: InitializeBrowserSigningRuntimeArgs): void {
  args.setWorkerBaseOrigin(resolveInitialWorkerBaseOrigin());

  if (typeof window !== 'undefined') {
    onEmbeddedBaseChange(() => {
      const origin = resolveInitialWorkerBaseOrigin();
      if (origin !== args.getWorkerBaseOrigin()) {
        args.setWorkerBaseOrigin(origin);
      }
    });
  }

  const shouldAvoidAppOriginIndexedDB =
    args.config.wallet.mode === 'iframe' && !__isWalletIframeHostMode();
  if (!shouldAvoidAppOriginIndexedDB) {
    void args.userPreferencesManager.initFromIndexedDB().catch(() => undefined);
  }
}
