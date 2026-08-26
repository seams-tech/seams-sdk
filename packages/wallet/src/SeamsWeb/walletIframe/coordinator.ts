import type { UserPreferencesManager } from '@/core/signingEngine/session/userPreferences';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { AppearanceConfig, SeamsConfigsReadonly } from '@/core/types/seams';
import type { WalletIframeRouter } from '@/SeamsWeb/walletIframe/client/router';
import type { WalletIframeTransportDiagnostics } from '@/SeamsWeb/walletIframe/client/transport/IframeTransport';
import type {
  HostedAuthMenuExternalAuthRequest,
  HostedAuthMenuDemoEmailOtpDelivery,
  HostedAuthMenuExternalAuthResolutionInput,
  HostedAuthMenuOpenRequest,
  HostedAuthMenuOutcome,
  HostedAuthMenuSessionId,
  PreferencesChangedPayload,
} from '@/SeamsWeb/walletIframe/shared/messages';
import { __isWalletIframeHostMode } from '@/core/browser/walletIframe/host-mode';
import { createWalletIframeRouter } from '@/SeamsWeb/assembly/createWalletIframeRouter';
import type { WalletIframeWarmupSurface } from '@/SeamsWeb/signingSurface/types';
import { parseWebAuthnRpId, type WebAuthnRpId } from '@shared/utils/domainIds';
import type { SdkLifecycleEventListener } from '@/core/types/sdkSentEvents';
import type { SdkLifecycleEvent } from '@/core/types/sdkSentEvents';
import type {
  WalletIframeExactSessionIdentity,
  WalletIframeExactSessionLockResult,
  WalletIframeExactSessionState,
} from './shared/exactSessionState';

function requireRegistrationRpId(value: string, source: string): WebAuthnRpId {
  const parsed = parseWebAuthnRpId(value);
  if (!parsed.ok) {
    throw new Error(`${source}: ${parsed.error.message}`);
  }
  return parsed.value;
}

function walletOriginHostname(walletOrigin: string): string {
  try {
    return new URL(walletOrigin).hostname;
  } catch {
    throw new Error('[SeamsWeb] Wallet iframe origin is not a valid URL.');
  }
}

export interface WalletIframeCoordinatorDeps {
  configs: SeamsConfigsReadonly;
  signingEngine: WalletIframeWarmupSurface;
  userPreferences: UserPreferencesManager;
  getAppearance: () => AppearanceConfig;
}

/**
 * Coordinates wallet-iframe lifecycle and preference mirroring.
 * This keeps `SeamsWeb` focused on business flows while preserving one cohesive iframe domain module.
 */
export class WalletIframeCoordinator {
  private readonly configs: SeamsConfigsReadonly;
  private readonly signingEngine: WalletIframeWarmupSurface;
  private readonly userPreferences: UserPreferencesManager;
  private readonly getAppearance: () => AppearanceConfig;

  private iframeRouter: WalletIframeRouter | null = null;
  private walletIframeRouterCreationInFlight: Promise<WalletIframeRouter> | null = null;
  private walletIframeInitInFlight: Promise<void> | null = null;
  private walletIframeDisposed = false;
  private walletIframePrefsUnsubscribe: (() => void) | null = null;
  private walletIframeLifecycleUnsubscribe: (() => void) | null = null;
  private walletIframeAuthMenuUnsubscribe: (() => void) | null = null;
  private walletIframeAuthMenuDemoOtpUnsubscribe: (() => void) | null = null;
  private readonly sdkLifecycleEventListeners = new Set<SdkLifecycleEventListener>();
  private readonly hostedAuthMenuExternalAuthRequestListeners = new Set<
    (request: HostedAuthMenuExternalAuthRequest) => void
  >();
  private readonly hostedAuthMenuDemoEmailOtpDeliveryListeners = new Set<
    (delivery: HostedAuthMenuDemoEmailOtpDelivery) => void
  >();
  private readonly forwardSdkLifecycleEventListener: SdkLifecycleEventListener;
  private readonly forwardHostedAuthMenuExternalAuthRequestListener: (
    request: HostedAuthMenuExternalAuthRequest,
  ) => void;
  private readonly forwardHostedAuthMenuDemoEmailOtpDeliveryListener: (
    delivery: HostedAuthMenuDemoEmailOtpDelivery,
  ) => void;

  constructor(deps: WalletIframeCoordinatorDeps) {
    this.configs = deps.configs;
    this.signingEngine = deps.signingEngine;
    this.userPreferences = deps.userPreferences;
    this.getAppearance = deps.getAppearance;
    this.forwardSdkLifecycleEventListener = this.forwardSdkLifecycleEvent.bind(this);
    this.forwardHostedAuthMenuExternalAuthRequestListener =
      this.forwardHostedAuthMenuExternalAuthRequest.bind(this);
    this.forwardHostedAuthMenuDemoEmailOtpDeliveryListener =
      this.forwardHostedAuthMenuDemoEmailOtpDelivery.bind(this);
  }

  /**
   * True when the SDK is running on the app origin with a wallet iframe configured.
   * In this mode, sensitive persistence must live in the wallet-iframe origin.
   */
  shouldUseWalletIframe(): boolean {
    return this.configs.wallet.mode === 'iframe' && !__isWalletIframeHostMode();
  }

  resolveRegistrationRpId(localRpId: string): WebAuthnRpId {
    if (!this.shouldUseWalletIframe()) {
      return requireRegistrationRpId(localRpId, '[SeamsWeb] Local registration RP ID is invalid');
    }

    const iframeConfig = this.configs.wallet.iframe;
    const configuredRpId = String(iframeConfig.rpIdOverride || '').trim();
    if (configuredRpId) {
      return requireRegistrationRpId(
        configuredRpId,
        '[SeamsWeb] Wallet iframe registration RP ID is invalid',
      );
    }

    const walletOrigin = iframeConfig.origin;
    if (!walletOrigin) {
      throw new Error('[SeamsWeb] Wallet iframe registration requires a wallet origin.');
    }
    return requireRegistrationRpId(
      walletOriginHostname(walletOrigin),
      '[SeamsWeb] Wallet iframe origin hostname is not a valid registration RP ID',
    );
  }

  isReady(): boolean {
    return !!this.iframeRouter?.isReady();
  }

  getTransportDiagnosticsSnapshot(): WalletIframeTransportDiagnostics | null {
    return this.iframeRouter?.getTransportDiagnosticsSnapshot() ?? null;
  }

  dispose(): void {
    if (this.walletIframeDisposed) return;
    this.walletIframeDisposed = true;
    this.iframeRouter?.dispose();
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

  onSdkLifecycleEvent(listener: SdkLifecycleEventListener): () => void {
    this.sdkLifecycleEventListeners.add(listener);
    if (this.iframeRouter) {
      this.ensureWalletIframeLifecycleMirror(this.iframeRouter);
    }
    return this.removeSdkLifecycleEventListener.bind(this, listener);
  }

  onPreferencesChanged(listener: (payload: PreferencesChangedPayload) => void): () => void {
    const router = this.iframeRouter;
    if (!router) return () => {};
    return router.onPreferencesChanged(listener);
  }

  async init(_walletId?: string): Promise<WalletIframeExactSessionState> {
    if (!this.shouldUseWalletIframe()) {
      await this.signingEngine.warmCriticalResources({ kind: 'none' });
      return { kind: 'wallet_locked' };
    }

    // Guardrail: when running inside the wallet service iframe host, never attempt to
    // initialize a nested wallet iframe client, even if configs accidentally set wallet.mode='iframe'.
    // The host runs the real SeamsWeb instance and must remain self-contained.
    if (__isWalletIframeHostMode()) {
      return { kind: 'wallet_locked' };
    }

    const walletIframeConfig = this.configs.wallet.iframe;
    const walletOrigin = walletIframeConfig?.origin;
    if (!walletOrigin) {
      return { kind: 'wallet_locked' };
    }

    // Initialize iframe router once (and prevent concurrent calls from mounting multiple iframes).
    if (!this.iframeRouter) {
      if (!this.walletIframeInitInFlight) {
        this.walletIframeInitInFlight = (async () => {
          const router = await this.getOrCreateRouter(walletOrigin);
          await router.init();
          // Opportunistically warm remote nonce context.
          try {
            await router.prefetchBlockheight();
          } catch {}
        })();
      }

      try {
        await this.walletIframeInitInFlight;
      } finally {
        this.walletIframeInitInFlight = null;
      }
    } else {
      this.ensureWalletIframePreferencesMirror(this.iframeRouter);
      this.ensureWalletIframeLifecycleMirror(this.iframeRouter);
      this.ensureWalletIframeAuthMenuMirror(this.iframeRouter);
      await this.iframeRouter.init();
      // Opportunistically warm remote nonce context.
      try {
        await this.iframeRouter.prefetchBlockheight();
      } catch {}
    }

    if (this.iframeRouter) {
      const exactState = this.iframeRouter.getMirroredExactSessionState();
      if (exactState.kind !== 'wallet_locked') {
        this.userPreferences.setCurrentWallet(exactState.walletId);
      }
      // Best-effort pull snapshot to cover missed events / older hosts.
      const cfg = await this.iframeRouter.getConfirmationConfig().catch(() => null);
      if (cfg) {
        const confirmationWalletId =
          exactState.kind === 'wallet_locked' ? null : exactState.walletId;
        this.userPreferences.applyWalletHostConfirmationConfig({
          walletId: confirmationWalletId,
          confirmationConfig: cfg,
        });
      }
      return exactState;
    }
    return { kind: 'wallet_locked' };
  }

  async getExactSessionState(): Promise<WalletIframeExactSessionState> {
    const router = await this.requireRouter();
    return await router.getExactSessionState();
  }

  async openHostedAuthMenu(
    request: HostedAuthMenuOpenRequest,
    anchorElement?: HTMLElement,
  ): Promise<HostedAuthMenuOutcome> {
    const router = await this.requireAuthMenuRouter();
    return await router.openHostedAuthMenu(request, anchorElement);
  }

  async cancelHostedAuthMenu(args: { authMenuSessionId: HostedAuthMenuSessionId }): Promise<void> {
    const router = await this.requireRouter();
    await router.cancelHostedAuthMenu(args);
  }

  onHostedAuthMenuExternalAuthRequest(
    listener: (request: HostedAuthMenuExternalAuthRequest) => void,
  ): () => void {
    this.hostedAuthMenuExternalAuthRequestListeners.add(listener);
    if (this.iframeRouter) this.ensureWalletIframeAuthMenuMirror(this.iframeRouter);
    return this.removeHostedAuthMenuExternalAuthRequestListener.bind(this, listener);
  }

  onHostedAuthMenuDemoEmailOtpDelivery(
    listener: (delivery: HostedAuthMenuDemoEmailOtpDelivery) => void,
  ): () => void {
    this.hostedAuthMenuDemoEmailOtpDeliveryListeners.add(listener);
    if (this.iframeRouter) this.ensureWalletIframeAuthMenuMirror(this.iframeRouter);
    return this.removeHostedAuthMenuDemoEmailOtpDeliveryListener.bind(this, listener);
  }

  async resolveHostedAuthMenuExternalAuth(
    resolution: HostedAuthMenuExternalAuthResolutionInput,
  ): Promise<void> {
    const router = await this.requireRouter();
    await router.resolveHostedAuthMenuExternalAuth(resolution);
  }

  async lockExactSession(
    identity: WalletIframeExactSessionIdentity,
  ): Promise<WalletIframeExactSessionLockResult> {
    const router = await this.requireRouter(String(identity.walletId));
    return await router.lockExactSession(identity);
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

  private async requireAuthMenuRouter(): Promise<WalletIframeRouter> {
    if (!this.shouldUseWalletIframe()) {
      throw new Error('[SeamsWeb] Wallet iframe is not configured.');
    }
    const walletOrigin = this.configs.wallet.iframe?.origin;
    if (!walletOrigin) {
      throw new Error('[SeamsWeb] Wallet iframe is configured but unavailable.');
    }
    return await this.getOrCreateRouter(walletOrigin);
  }

  private async getOrCreateRouter(walletOrigin: string): Promise<WalletIframeRouter> {
    if (this.iframeRouter) return this.iframeRouter;
    this.walletIframeRouterCreationInFlight ??= createWalletIframeRouter({
      configs: this.configs,
      walletOrigin,
      getAppearance: this.getAppearance,
    });
    try {
      const router = await this.walletIframeRouterCreationInFlight;
      this.iframeRouter = router;
      this.ensureWalletIframePreferencesMirror(router);
      this.ensureWalletIframeLifecycleMirror(router);
      this.ensureWalletIframeAuthMenuMirror(router);
      return router;
    } finally {
      this.walletIframeRouterCreationInFlight = null;
    }
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

  private ensureWalletIframeLifecycleMirror(router: WalletIframeRouter): void {
    if (this.walletIframeLifecycleUnsubscribe) return;
    this.walletIframeLifecycleUnsubscribe = router.onSdkLifecycleEvent(
      this.forwardSdkLifecycleEventListener,
    );
  }

  private ensureWalletIframeAuthMenuMirror(router: WalletIframeRouter): void {
    if (!this.walletIframeAuthMenuUnsubscribe) {
      this.walletIframeAuthMenuUnsubscribe = router.onHostedAuthMenuExternalAuthRequest(
        this.forwardHostedAuthMenuExternalAuthRequestListener,
      );
    }
    if (!this.walletIframeAuthMenuDemoOtpUnsubscribe) {
      this.walletIframeAuthMenuDemoOtpUnsubscribe = router.onHostedAuthMenuDemoEmailOtpDelivery(
        this.forwardHostedAuthMenuDemoEmailOtpDeliveryListener,
      );
    }
  }

  private forwardSdkLifecycleEvent(event: SdkLifecycleEvent): void {
    for (const listener of Array.from(this.sdkLifecycleEventListeners)) {
      listener(event);
    }
  }

  private removeSdkLifecycleEventListener(listener: SdkLifecycleEventListener): void {
    this.sdkLifecycleEventListeners.delete(listener);
  }

  private forwardHostedAuthMenuExternalAuthRequest(
    request: HostedAuthMenuExternalAuthRequest,
  ): void {
    for (const listener of Array.from(this.hostedAuthMenuExternalAuthRequestListeners)) {
      try {
        listener(request);
      } catch {}
    }
  }

  private removeHostedAuthMenuExternalAuthRequestListener(
    listener: (request: HostedAuthMenuExternalAuthRequest) => void,
  ): void {
    this.hostedAuthMenuExternalAuthRequestListeners.delete(listener);
  }

  private forwardHostedAuthMenuDemoEmailOtpDelivery(
    delivery: HostedAuthMenuDemoEmailOtpDelivery,
  ): void {
    for (const listener of Array.from(this.hostedAuthMenuDemoEmailOtpDeliveryListeners)) {
      try {
        listener(delivery);
      } catch {}
    }
  }

  private removeHostedAuthMenuDemoEmailOtpDeliveryListener(
    listener: (delivery: HostedAuthMenuDemoEmailOtpDelivery) => void,
  ): void {
    this.hostedAuthMenuDemoEmailOtpDeliveryListeners.delete(listener);
  }
}
