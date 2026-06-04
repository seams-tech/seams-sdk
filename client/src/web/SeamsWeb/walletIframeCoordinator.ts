import type { UserPreferencesManager } from '@/core/signingEngine/session/userPreferences';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThemeName, SeamsConfigsReadonly } from '@/core/types/seams';
import type { WalletIframeRouter } from '@/core/WalletIframe/client/router';
import type { PreferencesChangedPayload } from '@/core/WalletIframe/shared/messages';
import { __isWalletIframeHostMode } from '@/core/WalletIframe/host-mode';
import { createWalletIframeRouter } from './assembly/createWalletIframeRouter';
import type { SeamsWebContext } from './index';

type WalletIframeSigningSurface = Pick<SeamsWebContext['signingEngine'], 'warmCriticalResources'>;

export interface WalletIframeCoordinatorDeps {
  configs: SeamsConfigsReadonly;
  signingEngine: WalletIframeSigningSurface;
  userPreferences: UserPreferencesManager;
  getTheme: () => ThemeName;
  refreshWalletSession: (walletId?: string) => Promise<void>;
}

/**
 * Coordinates wallet-iframe lifecycle and preference mirroring.
 * This keeps `SeamsWeb` focused on business flows while preserving one cohesive iframe domain module.
 */
export class WalletIframeCoordinator {
  private readonly configs: SeamsConfigsReadonly;
  private readonly signingEngine: WalletIframeSigningSurface;
  private readonly userPreferences: UserPreferencesManager;
  private readonly getTheme: () => ThemeName;
  private readonly refreshWalletSession: (walletId?: string) => Promise<void>;

  private iframeRouter: WalletIframeRouter | null = null;
  private walletIframeInitInFlight: Promise<void> | null = null;
  private walletIframePrefsUnsubscribe: (() => void) | null = null;

  constructor(deps: WalletIframeCoordinatorDeps) {
    this.configs = deps.configs;
    this.signingEngine = deps.signingEngine;
    this.userPreferences = deps.userPreferences;
    this.getTheme = deps.getTheme;
    this.refreshWalletSession = deps.refreshWalletSession;
  }

  /**
   * True when the SDK is running on the app origin with a wallet iframe configured.
   * In this mode, sensitive persistence must live in the wallet-iframe origin.
   */
  shouldUseWalletIframe(): boolean {
    return this.configs.wallet.mode === 'iframe' && !__isWalletIframeHostMode();
  }

  isReady(): boolean {
    return !!this.iframeRouter?.isReady();
  }

  onReady(listener: () => void): () => void {
    const router = this.iframeRouter;
    if (!router) return () => {};
    return router.onReady(listener);
  }

  onLoginStatusChanged(
    listener: (status: { isLoggedIn: boolean; walletId: string | null }) => void,
  ): () => void {
    const router = this.iframeRouter;
    if (!router) return () => {};
    return router.onLoginStatusChanged(listener);
  }

  onPreferencesChanged(listener: (payload: PreferencesChangedPayload) => void): () => void {
    const router = this.iframeRouter;
    if (!router) return () => {};
    return router.onPreferencesChanged(listener);
  }

  async init(walletId?: string): Promise<void> {
    const walletOriginConfigured = this.configs.wallet.mode === 'iframe';
    // Warm local critical resources (nonce coordinator, workers) regardless of iframe usage.
    // In iframe mode, avoid persisting user state (lastUserAccountId, preferences) on the app origin.
    const shouldAvoidLocalUserState = walletOriginConfigured && !__isWalletIframeHostMode();
    await this.signingEngine.warmCriticalResources(
      shouldAvoidLocalUserState ? undefined : walletId,
    );

    // Guardrail: when running inside the wallet service iframe host, never attempt to
    // initialize a nested wallet iframe client, even if configs accidentally set wallet.mode='iframe'.
    // The host runs the real SeamsWeb instance and must remain self-contained.
    if (__isWalletIframeHostMode()) {
      return;
    }

    const walletIframeConfig = this.configs.wallet.iframe;
    const walletOrigin = walletIframeConfig?.origin;
    if (!walletOrigin) {
      await this.refreshWalletSession(walletId);
      return;
    }

    // Initialize iframe router once (and prevent concurrent calls from mounting multiple iframes).
    if (!this.iframeRouter) {
      if (!this.walletIframeInitInFlight) {
        this.walletIframeInitInFlight = (async () => {
          this.iframeRouter = await createWalletIframeRouter({
            configs: this.configs,
            walletOrigin,
            getTheme: this.getTheme,
          });

          await this.iframeRouter.init();
          // Opportunistically warm remote nonce context.
          try {
            await this.iframeRouter.prefetchBlockheight();
          } catch {}
        })();
      }

      try {
        await this.walletIframeInitInFlight;
      } finally {
        this.walletIframeInitInFlight = null;
      }
    } else {
      await this.iframeRouter.init();
      // Opportunistically warm remote nonce context.
      try {
        await this.iframeRouter.prefetchBlockheight();
      } catch {}
    }

    if (this.iframeRouter) {
      this.ensureWalletIframePreferencesMirror(this.iframeRouter);
      // Best-effort pull snapshot to cover missed events / older hosts.
      const cfg = await this.iframeRouter.getConfirmationConfig().catch(() => null);
      if (cfg) {
        this.userPreferences.applyWalletHostConfirmationConfig({
          walletId: walletId ? toWalletId(walletId) : null,
          confirmationConfig: cfg,
        });
      }
    }

    await this.refreshWalletSession(walletId);
  }

  async requireRouter(walletId?: string): Promise<WalletIframeRouter> {
    if (!this.shouldUseWalletIframe()) {
      throw new Error('[SeamsWeb] Wallet iframe is not configured.');
    }
    if (!this.iframeRouter) {
      await this.init(walletId);
    }
    if (!this.iframeRouter) {
      throw new Error('[SeamsWeb] Wallet iframe is configured but unavailable.');
    }
    return this.iframeRouter;
  }

  private ensureWalletIframePreferencesMirror(router: WalletIframeRouter): void {
    if (this.walletIframePrefsUnsubscribe) {
      return;
    }
    const unsubscribe = router.onPreferencesChanged?.((payload) => {
      const id = payload?.walletId;
      const walletId = id ? toWalletId(id) : null;
      this.userPreferences.applyWalletHostConfirmationConfig({
        walletId,
        confirmationConfig: payload?.confirmationConfig,
      });
    });
    this.walletIframePrefsUnsubscribe = unsubscribe ?? null;
  }
}
