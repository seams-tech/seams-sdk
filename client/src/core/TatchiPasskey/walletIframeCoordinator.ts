import type { SigningEnginePublic } from '../signingEngine/SigningEngine';
import type { UserPreferencesManager } from '../signingEngine/api/userPreferences';
import type { AccountId } from '../types/accountIds';
import { toAccountId } from '../types/accountIds';
import type { ThemeName, TatchiConfigs } from '../types/tatchi';
import type { WalletIframeRouter } from '../WalletIframe/client/router';
import type { PreferencesChangedPayload } from '../WalletIframe/shared/messages';
import { __isWalletIframeHostMode } from '../WalletIframe/host-mode';

export interface WalletIframeCoordinatorDeps {
  configs: TatchiConfigs;
  signingEngine: SigningEnginePublic;
  userPreferences: UserPreferencesManager;
  getTheme: () => ThemeName;
  refreshLoginSession: (nearAccountId?: string) => Promise<void>;
}

let warnedAboutSameOriginWallet = false;

/**
 * Coordinates wallet-iframe lifecycle and preference mirroring.
 * This keeps `TatchiPasskey` focused on business flows while preserving one cohesive iframe domain module.
 */
export class WalletIframeCoordinator {
  private readonly configs: TatchiConfigs;
  private readonly signingEngine: SigningEnginePublic;
  private readonly userPreferences: UserPreferencesManager;
  private readonly getTheme: () => ThemeName;
  private readonly refreshLoginSession: (nearAccountId?: string) => Promise<void>;

  private iframeRouter: WalletIframeRouter | null = null;
  private walletIframeInitInFlight: Promise<void> | null = null;
  private walletIframePrefsUnsubscribe: (() => void) | null = null;

  constructor(deps: WalletIframeCoordinatorDeps) {
    this.configs = deps.configs;
    this.signingEngine = deps.signingEngine;
    this.userPreferences = deps.userPreferences;
    this.getTheme = deps.getTheme;
    this.refreshLoginSession = deps.refreshLoginSession;
  }

  /**
   * True when the SDK is running on the app origin with a wallet iframe configured.
   * In this mode, sensitive persistence must live in the wallet-iframe origin.
   */
  shouldUseWalletIframe(): boolean {
    return !!this.configs.iframeWallet?.walletOrigin && !__isWalletIframeHostMode();
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
    listener: (status: { isLoggedIn: boolean; nearAccountId: string | null }) => void,
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

  async init(nearAccountId?: string): Promise<void> {
    const walletOriginConfigured = !!this.configs.iframeWallet?.walletOrigin;
    // Warm local critical resources (NonceManager, workers) regardless of iframe usage.
    // In iframe mode, avoid persisting user state (lastUserAccountId, preferences) on the app origin.
    const shouldAvoidLocalUserState = walletOriginConfigured && !__isWalletIframeHostMode();
    await this.signingEngine.warmCriticalResources(
      shouldAvoidLocalUserState ? undefined : nearAccountId,
    );

    // Guardrail: when running inside the wallet service iframe host, never attempt to
    // initialize a nested wallet iframe client, even if configs accidentally include iframeWallet.
    // The host runs the real TatchiPasskey instance and must remain self-contained.
    if (__isWalletIframeHostMode()) {
      return;
    }

    const walletIframeConfig = this.configs.iframeWallet;
    const walletOrigin = walletIframeConfig?.walletOrigin;
    if (!walletOrigin) {
      await this.refreshLoginSession(nearAccountId);
      return;
    }

    // Emit same-origin co-hosting warning only when actually initializing the iframe.
    if (!warnedAboutSameOriginWallet) {
      try {
        const parsed = new URL(walletOrigin);
        if (typeof window !== 'undefined' && parsed.origin === window.location.origin) {
          warnedAboutSameOriginWallet = true;
          console.warn(
            '[TatchiPasskey] iframeWallet.walletOrigin matches the host origin. Consider moving the wallet to a dedicated origin for stronger isolation.',
          );
        }
      } catch {
        // ignore invalid URL here; constructor downstream will surface an error
      }
    }

    // Initialize iframe router once (and prevent concurrent calls from mounting multiple iframes).
    if (!this.iframeRouter) {
      if (!this.walletIframeInitInFlight) {
        this.walletIframeInitInFlight = (async () => {
          const { WalletIframeRouter } = await import('../WalletIframe/client/router');
          this.iframeRouter = new WalletIframeRouter({
            walletOrigin,
            servicePath: walletIframeConfig?.walletServicePath || '/wallet-service',
            connectTimeoutMs: 20_000,
            requestTimeoutMs: 60_000,
            signerMode: this.configs.signerMode,
            chains: this.configs.chains,
            relayerAccount: this.configs.relayerAccount,
            relayer: this.configs.relayer,
            rpIdOverride: walletIframeConfig?.rpIdOverride,
            authenticatorOptions: this.configs.authenticatorOptions,
            appearance: {
              theme: this.getTheme(),
              tokens: this.configs.appearance?.tokens,
            },
            // Allow apps/CI to control where embedded bundles are served from.
            sdkBasePath: walletIframeConfig?.sdkBasePath,
          });

          await this.iframeRouter.init();
          // Opportunistically warm remote NonceManager.
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
      // Opportunistically warm remote NonceManager.
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
          nearAccountId: nearAccountId ? toAccountId(nearAccountId) : null,
          confirmationConfig: cfg,
        });
      }
      const signerMode = await this.iframeRouter
        .getSignerMode?.({ timeoutMs: 1000 })
        .catch(() => null);
      if (signerMode) {
        this.userPreferences.applyWalletHostSignerMode?.({
          nearAccountId: nearAccountId ? toAccountId(nearAccountId) : null,
          signerMode,
        });
      }
    }

    await this.refreshLoginSession(nearAccountId);
  }

  async requireRouter(nearAccountId?: string): Promise<WalletIframeRouter> {
    if (!this.shouldUseWalletIframe()) {
      throw new Error('[TatchiPasskey] Wallet iframe is not configured.');
    }
    if (!this.iframeRouter) {
      await this.init(nearAccountId);
    }
    if (!this.iframeRouter) {
      throw new Error('[TatchiPasskey] Wallet iframe is configured but unavailable.');
    }
    return this.iframeRouter;
  }

  private ensureWalletIframePreferencesMirror(router: WalletIframeRouter): void {
    if (this.walletIframePrefsUnsubscribe) {
      return;
    }
    const unsubscribe = router.onPreferencesChanged?.((payload) => {
      const id = payload?.nearAccountId;
      const nearAccountId: AccountId | null = id ? toAccountId(id) : null;
      this.userPreferences.applyWalletHostConfirmationConfig({
        nearAccountId,
        confirmationConfig: payload?.confirmationConfig,
      });
      if (payload?.signerMode) {
        this.userPreferences.applyWalletHostSignerMode?.({
          nearAccountId,
          signerMode: payload.signerMode,
        });
      }
    });
    this.walletIframePrefsUnsubscribe = unsubscribe ?? null;
  }
}
