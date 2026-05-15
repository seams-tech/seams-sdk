import type { SigningEnginePublic } from '../signingEngine/SigningEngine';
import type { UserPreferencesManager } from '../signingEngine/session/userPreferences';
import { toWalletId } from '../signingEngine/interfaces/ecdsaChainTarget';
import type { ThemeName, SeamsConfigsReadonly } from '../types/seams';
import { cloneAuthenticatorOptions } from '../types/authenticatorOptions';
import type { WalletIframeRouter } from '../WalletIframe/client/router';
import type { PreferencesChangedPayload } from '../WalletIframe/shared/messages';
import { __isWalletIframeHostMode } from '../WalletIframe/host-mode';

export interface WalletIframeCoordinatorDeps {
  configs: SeamsConfigsReadonly;
  signingEngine: SigningEnginePublic;
  userPreferences: UserPreferencesManager;
  getTheme: () => ThemeName;
  refreshWalletSession: (walletId?: string) => Promise<void>;
}

let warnedAboutSameOriginWallet = false;

/**
 * Coordinates wallet-iframe lifecycle and preference mirroring.
 * This keeps `SeamsPasskey` focused on business flows while preserving one cohesive iframe domain module.
 */
export class WalletIframeCoordinator {
  private readonly configs: SeamsConfigsReadonly;
  private readonly signingEngine: SigningEnginePublic;
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
    // The host runs the real SeamsPasskey instance and must remain self-contained.
    if (__isWalletIframeHostMode()) {
      return;
    }

    const walletIframeConfig = this.configs.wallet.iframe;
    const walletOrigin = walletIframeConfig?.origin;
    if (!walletOrigin) {
      await this.refreshWalletSession(walletId);
      return;
    }

    // Emit same-origin co-hosting warning only when actually initializing the iframe.
    if (!warnedAboutSameOriginWallet) {
      try {
        const parsed = new URL(walletOrigin);
        if (typeof window !== 'undefined' && parsed.origin === window.location.origin) {
          warnedAboutSameOriginWallet = true;
          console.warn(
            '[SeamsPasskey] wallet.iframe.origin matches the host origin. Consider moving the wallet to a dedicated origin for stronger isolation.',
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
          const signingSessionPersistenceMode = this.configs.signing.sessionPersistenceMode;
          const signingSessionSeal =
            signingSessionPersistenceMode === 'sealed_refresh_v1'
              ? this.configs.signing.sessionSeal
              : undefined;
          const signingSessionDefaults = this.configs.signing.sessionDefaults;
          const thresholdEcdsaPresignPool = this.configs.signing.thresholdEcdsa.presignPool;
          const provisioningDefaults = this.configs.signing.thresholdEcdsa.provisioningDefaults;
          this.iframeRouter = new WalletIframeRouter({
            walletOrigin,
            servicePath: walletIframeConfig?.servicePath || '/wallet-service',
            connectTimeoutMs: 20_000,
            requestTimeoutMs: 60_000,
            chains: this.configs.network.chains,
            relayerAccount: this.configs.network.relayer.accountId,
            relayer: this.configs.network.relayer,
            registration: this.configs.registration,
            signingSessionDefaults,
            signingSessionPersistenceMode,
            ...(signingSessionSeal ? { signingSessionSeal } : {}),
            thresholdEcdsaPresignPool,
            provisioningDefaults,
            rpIdOverride: walletIframeConfig?.rpIdOverride,
            authenticatorOptions: cloneAuthenticatorOptions(
              this.configs.webauthn.authenticatorOptions,
            ),
            appearance: {
              theme: this.getTheme(),
              tokens: this.configs.ui.appearance?.tokens,
            },
            // Allow apps/CI to control where embedded bundles are served from.
            sdkBasePath: walletIframeConfig?.sdkBasePath,
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
      throw new Error('[SeamsPasskey] Wallet iframe is not configured.');
    }
    if (!this.iframeRouter) {
      await this.init(walletId);
    }
    if (!this.iframeRouter) {
      throw new Error('[SeamsPasskey] Wallet iframe is configured but unavailable.');
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
