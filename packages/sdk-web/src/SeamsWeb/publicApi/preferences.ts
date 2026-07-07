import type { ConfirmationConfig } from '@/core/types/signer-worker';
import type { UserPreferencesManager } from '@/core/signingEngine/session/userPreferences';
import type { WalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { PreferencesCapability } from '@/SeamsWeb/signingSurface/types';
import type { WalletIframeCoordinator } from '@/SeamsWeb/walletIframe/coordinator';

type WalletIframeConfirmBehaviorWrite = {
  walletIframe: WalletIframeCoordinator;
  walletId: WalletId | null;
  behavior: 'requireClick' | 'skipClick';
};

type WalletIframeConfirmationConfigWrite = {
  walletIframe: WalletIframeCoordinator;
  walletId: WalletId | null;
  config: Partial<ConfirmationConfig>;
};

function applyLocalWalletIframeConfirmationConfigPatch(
  userPreferences: UserPreferencesManager,
  patch: Partial<ConfirmationConfig>,
): void {
  userPreferences.applyWalletHostConfirmationConfig({
    walletId: userPreferences.getCurrentWalletId(),
    confirmationConfig: {
      ...userPreferences.getConfirmationConfig(),
      ...patch,
    },
  });
}

function absorbPreferenceWriteError(): void {}

async function sendWalletIframeConfirmBehaviorWrite(
  args: WalletIframeConfirmBehaviorWrite,
): Promise<void> {
  const router = await args.walletIframe.requireRouter(args.walletId ?? undefined);
  await router.setConfirmBehavior(args.behavior, args.walletId);
}

async function sendWalletIframeConfirmationConfigWrite(
  args: WalletIframeConfirmationConfigWrite,
): Promise<void> {
  const router = await args.walletIframe.requireRouter(args.walletId ?? undefined);
  await router.setConfirmationConfig(args.config, args.walletId);
}

export function createPreferencesCapability(deps: {
  userPreferences: UserPreferencesManager;
  getWalletIframe: () => WalletIframeCoordinator;
}): PreferencesCapability {
  let walletIframePreferenceWrite: Promise<void> = Promise.resolve();

  return {
    setCurrentWallet: (walletId: WalletId): void => {
      deps.userPreferences.setCurrentWallet(walletId);
    },
    getCurrentWalletId: (): WalletId | null => deps.userPreferences.getCurrentWalletId(),
    onConfirmationConfigChange: (callback): (() => void) =>
      deps.userPreferences.onConfirmationConfigChange(callback),
    onCurrentWalletChange: (callback): (() => void) =>
      deps.userPreferences.onCurrentWalletChange(callback),
    setConfirmBehavior: (behavior): void => {
      const walletIframe = deps.getWalletIframe();
      if (walletIframe.shouldUseWalletIframe()) {
        const walletId = deps.userPreferences.getCurrentWalletId();
        applyLocalWalletIframeConfirmationConfigPatch(deps.userPreferences, { behavior });
        walletIframePreferenceWrite = walletIframePreferenceWrite
          .catch(absorbPreferenceWriteError)
          .then(
            sendWalletIframeConfirmBehaviorWrite.bind(null, {
              walletIframe,
              walletId,
              behavior,
            }),
          );
        void walletIframePreferenceWrite;
        return;
      }
      deps.userPreferences.setConfirmBehavior(behavior);
    },
    setConfirmationConfig: (config: Partial<ConfirmationConfig>): void => {
      const walletIframe = deps.getWalletIframe();
      if (walletIframe.shouldUseWalletIframe()) {
        const walletId = deps.userPreferences.getCurrentWalletId();
        applyLocalWalletIframeConfirmationConfigPatch(deps.userPreferences, config);
        walletIframePreferenceWrite = walletIframePreferenceWrite
          .catch(absorbPreferenceWriteError)
          .then(
            sendWalletIframeConfirmationConfigWrite.bind(null, {
              walletIframe,
              walletId,
              config: { ...config },
            }),
          );
        void walletIframePreferenceWrite;
        return;
      }
      deps.userPreferences.setConfirmationConfig(config);
    },
    getConfirmationConfig: (): ConfirmationConfig => deps.userPreferences.getConfirmationConfig(),
  };
}
