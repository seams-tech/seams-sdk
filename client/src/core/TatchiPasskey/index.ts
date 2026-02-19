import { WebAuthnManager } from '../signing/api/WebAuthnManager';
import { registerPasskey } from './registration';
import { registerPasskeyInternal } from './registration';
import {
  MinimalNearClient,
  type NearClient,
  type AccessKeyList,
} from '../near/NearClient';
import type {
  ActionResult,
  GetRecentLoginsResult,
  LoginAndCreateSessionResult,
  LoginResult,
  LoginSession,
  LoginState,
  RegistrationResult,
  ThemeName,
  TatchiConfigs,
  TatchiConfigsInput,
} from '../types/tatchi';
import type {
  ActionHooksOptions,
  LoginHooksOptions,
  RegistrationHooksOptions,
} from '../types/sdkSentEvents';
import { ConfirmationConfig, type SignerMode } from '../types/signer-worker';
import { DEFAULT_AUTHENTICATOR_OPTIONS } from '../types/authenticatorOptions';
import { toAccountId, type AccountId } from '../types/accountIds';
import type { DerivedAddressRecord } from '../IndexedDBManager';
import { configureIndexedDB, IndexedDBManager } from '../IndexedDBManager';
import { chainsigAddressManager } from '../../utils/chainsigAddressManager';
import { ActionType, type ActionArgs, type TransactionInput } from '../types/actions';
import type { PreferencesChangedPayload } from '../WalletIframe/shared/messages';
import { __isWalletIframeHostMode } from '../WalletIframe/host-mode';
import { toError } from '@shared/utils/errors';
import { coerceThemeName } from '@shared/utils/theme';
import type { DelegateActionInput } from '../types/delegate';
import { buildConfigsFromEnv } from '../config/defaultConfigs';
import { WalletIframeCoordinator } from './walletIframeCoordinator';
import {
  getLoginSessionDomain,
  getRecentLoginsDomain,
  hasPasskeyCredentialDomain,
  loginAndCreateSessionDomain,
  logoutAndClearSessionDomain,
  type AuthSessionDomainDeps,
} from './authSessionDomain';
import { DeviceRecoveryDomain } from './deviceRecoveryDomain';
import { NearSigner } from './signers/nearSigner';
import { TempoSigner } from './signers/tempoSigner';
import { EvmSigner } from './signers/evmSigner';
import type { ChainSignerDeps } from './signers/shared';
import type {
  RecoveryCapability,
  EvmSignerCapability,
  KeyExportCapability,
  NearSignerCapability,
  PreferencesCapability,
  TempoSignerCapability,
} from './capabilities';

///////////////////////////////////////
// PASSKEY MANAGER
///////////////////////////////////////

export interface PasskeyManagerContext {
  webAuthnManager: WebAuthnManager;
  nearClient: NearClient;
  configs: TatchiConfigs;
  theme: ThemeName;
}

/**
 * Main TatchiPasskey class that provides framework-agnostic passkey operations
 * with flexible event-based callbacks for custom UX implementation
 */
export class TatchiPasskey {
  private readonly webAuthnManager: WebAuthnManager;
  private readonly nearClient: NearClient;
  readonly configs: TatchiConfigs;
  theme: ThemeName;
  private readonly walletIframe: WalletIframeCoordinator;
  readonly recovery: RecoveryCapability;
  readonly keys: KeyExportCapability;
  readonly preferences: PreferencesCapability;
  readonly near: NearSignerCapability;
  readonly tempo: TempoSignerCapability;
  readonly evm: EvmSignerCapability;

  constructor(
    configs: TatchiConfigsInput,
    nearClient?: NearClient
  ) {
    this.configs = buildConfigsFromEnv(configs);
    // Configure IndexedDB naming before any local persistence is touched.
    // - Wallet iframe host keeps canonical DB names.
    // - App origin disables IndexedDB entirely when iframe mode is enabled.
    const mode = __isWalletIframeHostMode()
      ? 'wallet'
      : (this.configs.iframeWallet?.walletOrigin ? 'disabled' : 'app');
    configureIndexedDB({ mode });
    // Use provided client or create default one
    this.nearClient = nearClient || new MinimalNearClient(this.configs.nearRpcUrl);
    this.webAuthnManager = new WebAuthnManager(this.configs, this.nearClient);

    this.theme = coerceThemeName(this.configs.appearance?.theme) ?? 'dark';
    try {
      this.webAuthnManager.setTheme(this.theme);
    } catch {}
    const userPreferences = this.webAuthnManager.getUserPreferences();

    this.walletIframe = new WalletIframeCoordinator({
      configs: this.configs,
      webAuthnManager: this.webAuthnManager,
      userPreferences: userPreferences,
      getTheme: () => this.theme,
      refreshLoginSession: async (nearAccountId?: string) => {
        await this.getLoginSession(nearAccountId);
      },
    });
    this.preferences = {
      setCurrentUser: (nearAccountId: AccountId): void => {
        userPreferences.setCurrentUser(nearAccountId);
      },
      getCurrentUserAccountId: (): AccountId => userPreferences.getCurrentUserAccountId(),
      onConfirmationConfigChange: (callback): (() => void) =>
        userPreferences.onConfirmationConfigChange(callback),
      onSignerModeChange: (callback): (() => void) => userPreferences.onSignerModeChange(callback),
      onCurrentUserChange: (callback): (() => void) => userPreferences.onCurrentUserChange(callback),
      setConfirmBehavior: (behavior): void => {
        if (this.walletIframe.shouldUseWalletIframe()) {
          void (async () => {
            try {
              const router = await this.walletIframe.requireRouter();
              await router.setConfirmBehavior(behavior);
            } catch { }
          })();
          return;
        }
        userPreferences.setConfirmBehavior(behavior);
      },
      setConfirmationConfig: (config): void => {
        if (this.walletIframe.shouldUseWalletIframe()) {
          void (async () => {
            try {
              const router = await this.walletIframe.requireRouter();
              await router.setConfirmationConfig(config);
            } catch { }
          })();
          return;
        }
        userPreferences.setConfirmationConfig(config);
      },
      setSignerMode: (signerMode): void => {
        userPreferences.setSignerMode(signerMode);
      },
      getConfirmationConfig: (): ConfirmationConfig => userPreferences.getConfirmationConfig(),
      getSignerMode: (): SignerMode => userPreferences.getSignerMode(),
    };
    this.recovery = new DeviceRecoveryDomain({
      getContext: () => this.getContext(),
      walletIframe: this.walletIframe,
    });
    this.keys = {
      exportPrivateKeysWithUI: async (nearAccountId, options) =>
        await this.exportPrivateKeysWithUIDomain(nearAccountId, options),
      exportNearKeypairWithUI: async (nearAccountId, options) =>
        await this.exportNearKeypairWithUIDomain(nearAccountId, options),
    };
    const signerDeps: ChainSignerDeps = {
      getContext: () => this.getContext(),
      walletIframe: this.walletIframe,
    };
    this.near = new NearSigner(signerDeps);
    this.tempo = new TempoSigner(signerDeps);
    this.evm = new EvmSigner(signerDeps);

    // Wallet-iframe mode: delegate signerMode persistence to the wallet host.
    // Non-iframe mode: ensure any previous writer is cleared (UserPreferences is a singleton).
    userPreferences.configureWalletIframeSignerModeWriter(
      this.walletIframe.shouldUseWalletIframe()
        ? async (next) => {
          const router = await this.walletIframe.requireRouter();
          await router.setSignerMode(next);
        }
        : null
    );
    // SecureConfirm worker initializes automatically in the constructor
  }

  /**
   * Initialize the hidden wallet service iframe client (optional) and warm critical resources.
   * Always warms local resources; initializes iframe when `walletOrigin` is provided.
   * Idempotent and safe to call multiple times.
   */
  async initWalletIframe(nearAccountId?: string): Promise<void> {
    await this.walletIframe.init(nearAccountId);
  }

  /** True when the wallet iframe client is connected and ready. */
  isWalletIframeReady(): boolean {
    return this.walletIframe.isReady();
  }

  /** Subscribe to wallet iframe ready state transitions. */
  onWalletIframeReady(listener: () => void): () => void {
    return this.walletIframe.onReady(listener);
  }

  /** Subscribe to wallet-host login status updates. */
  onWalletIframeLoginStatusChanged(
    listener: (status: { isLoggedIn: boolean; nearAccountId: string | null }) => void,
  ): () => void {
    return this.walletIframe.onLoginStatusChanged(listener);
  }

  /** Subscribe to wallet-host preference updates. */
  onWalletIframePreferencesChanged(
    listener: (payload: PreferencesChangedPayload) => void,
  ): () => void {
    return this.walletIframe.onPreferencesChanged(listener);
  }

  getContext(): PasskeyManagerContext {
    return {
      webAuthnManager: this.webAuthnManager,
      nearClient: this.nearClient,
      configs: this.configs,
      theme: this.theme,
    }
  }

  private getAuthSessionDeps(): AuthSessionDomainDeps {
    return {
      getContext: () => this.getContext(),
      walletIframe: this.walletIframe,
      webAuthnManager: this.webAuthnManager,
      nearClient: this.nearClient,
      initWalletIframe: async (nearAccountId?: string) => {
        await this.initWalletIframe(nearAccountId);
      },
    };
  }

  /**
   * Set SDK theme and propagate to wallet/confirmation UI (best-effort).
   * Theme propagation rules:
   * - Always update in-memory theme immediately.
   * - In wallet host mode, update `document.documentElement[data-w3a-theme]`.
   * - In app-origin iframe mode, best-effort `router.setTheme(next)`.
   * This never throws; callers should treat it as a fire-and-forget update.
   */
  setTheme(next: ThemeName): void {
    const nextTheme = coerceThemeName(next);
    if (!nextTheme) return;
    if (this.theme === nextTheme) return;
    this.theme = nextTheme;

    try {
      this.webAuthnManager.setTheme(nextTheme);
    } catch {}

    if (__isWalletIframeHostMode()) {
      try {
        document.documentElement.setAttribute('data-w3a-theme', nextTheme);
      } catch {}
    }

    if (this.walletIframe.shouldUseWalletIframe()) {
      void (async () => {
        try {
          const router = await this.walletIframe.requireRouter();
          await router.setTheme(nextTheme);
        } catch {}
      })();
    }
  }

  /**
   * Pre-warm resources on a best-effort basis without changing visible state.
   * - When iframe=true, initializes the wallet iframe client (and warms local resources).
   * - When workers=true, warms local critical resources (nonce, IndexedDB, workers) without touching iframe.
   * - When both are false/omitted, does nothing.
   */
  async prewarm(opts?: { iframe?: boolean; workers?: boolean; nearAccountId?: string }): Promise<void> {
    const iframe = !!opts?.iframe;
    const workers = !!opts?.workers;
    const nearAccountId = opts?.nearAccountId;

    const tasks: Promise<unknown>[] = [];

    if (iframe) {
      // initWalletIframe also calls WebAuthnManager.warmCriticalResources internally
      tasks.push(this.initWalletIframe(nearAccountId));
    } else if (workers) {
      // Warm local-only resources without touching the iframe.
      // In iframe mode, avoid persisting user state (lastUserAccountId, preferences) on the app origin.
      const shouldAvoidLocalUserState = this.walletIframe.shouldUseWalletIframe();
      tasks.push(this.webAuthnManager.warmCriticalResources(shouldAvoidLocalUserState ? undefined : nearAccountId));
    }

    if (tasks.length === 0) return;
    try {
      await Promise.all(tasks);
    } catch {
      // Best-effort: swallow errors so prewarm never breaks app flows
    }
  }

  /**
   * View all access keys for a given account
   * @param accountId - NEAR account ID to view access keys for
   * @returns Promise resolving to access key list
   */
  async viewAccessKeyList(accountId: string): Promise<AccessKeyList> {
    if (this.walletIframe.shouldUseWalletIframe()) {
      const router = await this.walletIframe.requireRouter(accountId);
      return await router.viewAccessKeyList(accountId);
    }
    return this.nearClient.viewAccessKeyList(accountId);
  }

  ///////////////////////////////////////
  // === Registration and Login ===
  ///////////////////////////////////////

  /**
   * Register a new passkey for the given NEAR account ID
   * Uses AccountId for on-chain operations and PRF salt derivation
   */
  async registerPasskey(
    nearAccountId: string,
    options: RegistrationHooksOptions = {}
  ): Promise<RegistrationResult> {
    // In wallet-iframe mode, always run inside the wallet origin (no app-origin fallback).
    if (this.walletIframe.shouldUseWalletIframe()) {
      try {
        const router = await this.walletIframe.requireRouter(nearAccountId);
        const confirmationConfig = options?.confirmationConfig;
        const res = await router.registerPasskey({
          nearAccountId,
          confirmationConfig,
          options: {
            onEvent: options?.onEvent,
            ...(options?.signerMode ? { signerMode: options.signerMode } : {}),
            ...(typeof options?.backupLocalKey === 'boolean' ? { backupLocalKey: options.backupLocalKey } : {}),
            ...(options?.signerOptions
              ? { signerOptions: options.signerOptions }
              : {}),
            ...(options?.confirmerText ? { confirmerText: options.confirmerText } : {})
          }
        });
        // Opportunistically warm resources (non-blocking)
        void (async () => { try { await this.initWalletIframe(nearAccountId); } catch { } })();
        await options?.afterCall?.(true, res);
        return res;
      } catch (error: unknown) {
        const e = toError(error);
        await options?.onError?.(e);
        await options?.afterCall?.(false);
        throw e;
      }
    }
    return registerPasskey(
      this.getContext(),
      toAccountId(nearAccountId),
      options,
      this.configs.authenticatorOptions || DEFAULT_AUTHENTICATOR_OPTIONS,
    );
  }

  /**
   * Internal variant that accepts a one-time confirmationConfig override.
   * Used by wallet-iframe host to force modal/skipClick behavior for ArrowButtonLit.
   */
  async registerPasskeyInternal(
    nearAccountId: string,
    options: RegistrationHooksOptions = {},
    confirmationConfigOverride?: ConfirmationConfig
  ): Promise<RegistrationResult> {
    // In wallet-iframe mode, always run inside the wallet origin (no app-origin fallback).
    if (this.walletIframe.shouldUseWalletIframe()) {
      try {
        const router = await this.walletIframe.requireRouter(nearAccountId);
        const confirmationConfig = confirmationConfigOverride ?? options?.confirmationConfig;
        const res = await router.registerPasskey({
          nearAccountId,
          confirmationConfig,
          options: {
            onEvent: options?.onEvent,
            ...(options?.signerMode ? { signerMode: options.signerMode } : {}),
            ...(typeof options?.backupLocalKey === 'boolean' ? { backupLocalKey: options.backupLocalKey } : {}),
            ...(options?.signerOptions
              ? { signerOptions: options.signerOptions }
              : {}),
            ...(options?.confirmerText ? { confirmerText: options.confirmerText } : {})
          }
        });
        void (async () => { try { await this.initWalletIframe(nearAccountId); } catch { } })();
        await options?.afterCall?.(true, res);
        return res;
      } catch (error: unknown) {
        const e = toError(error);
        await options?.onError?.(e);
        await options?.afterCall?.(false);
        throw e;
      }
    }
    // App-wallet path: call core internal with override
    return registerPasskeyInternal(
      this.getContext(),
      toAccountId(nearAccountId),
      options,
      this.configs.authenticatorOptions || DEFAULT_AUTHENTICATOR_OPTIONS,
      confirmationConfigOverride,
    );
  }

  /**
   * Post-registration threshold enrollment.
   * Runs `/threshold-ed25519/keygen` authorization and stores `threshold_ed25519_2p_v1`
   * key material locally. Intended to be called after the passkey is registered on-chain.
   */
  async enrollThresholdEd25519Key(
    nearAccountId: string,
    options?: {
      deviceNumber?: number;
      relayerUrl?: string;
    }
  ): Promise<{
    success: boolean;
    publicKey: string;
    relayerKeyId: string;
    error?: string;
  }> {
    // In wallet-iframe mode, always run inside the wallet origin (no app-origin fallback).
    if (this.walletIframe.shouldUseWalletIframe()) {
      const router = await this.walletIframe.requireRouter(nearAccountId);
      return await router.enrollThresholdEd25519Key({
        nearAccountId,
        options: options || {},
      });
    }

    return await this.webAuthnManager.thresholdKeyLifecycle.enrollThresholdEd25519KeyPostRegistration({
      nearAccountId: toAccountId(nearAccountId),
      deviceNumber: options?.deviceNumber,
    });
  }

  /**
   * Threshold key rotation helper:
   * keygen → AddKey(new) → DeleteKey(old).
   */
  async rotateThresholdEd25519Key(
    nearAccountId: string,
    options?: {
      deviceNumber?: number;
    }
  ): Promise<{
    success: boolean;
    oldPublicKey: string;
    oldRelayerKeyId: string;
    publicKey: string;
    relayerKeyId: string;
    deleteOldKeyAttempted: boolean;
    deleteOldKeySuccess: boolean;
    warning?: string;
    error?: string;
  }> {
    // In wallet-iframe mode, always run inside the wallet origin (no app-origin fallback).
    if (this.walletIframe.shouldUseWalletIframe()) {
      const router = await this.walletIframe.requireRouter(nearAccountId);
      return await router.rotateThresholdEd25519Key({
        nearAccountId,
        options: options || {},
      });
    }

    return await this.webAuthnManager.thresholdKeyLifecycle.rotateThresholdEd25519KeyPostRegistration({
      nearAccountId: toAccountId(nearAccountId),
      deviceNumber: options?.deviceNumber,
    });
  }

  /**
   * Login and optionally mint a warm signing session.
   * - Sets the active account/deviceNumber (IndexedDB last-user pointer)
   * - Optional: mints a relay session (JWT/cookie) via standard WebAuthn login challenge/verify
   * - In `threshold-signer` mode with warm-session policy enabled, threshold warm-up
   *   (ed25519 + ECDSA) is part of login and must succeed.
   * - Signing flows still prompt via SecureConfirm/WebAuthn as needed
   */
  async loginAndCreateSession(
    nearAccountId: string,
    options?: LoginHooksOptions
  ): Promise<LoginAndCreateSessionResult> {
    return await loginAndCreateSessionDomain(this.getAuthSessionDeps(), nearAccountId, options);
  }

  /**
   * Logout: clears last-user pointer and local session caches.
   */
  async logoutAndClearSession(): Promise<void> {
    await logoutAndClearSessionDomain(this.getAuthSessionDeps());
  }

  /**
   * Read login state + warm signing session status (no prompts).
   */
  async getLoginSession(nearAccountId?: string): Promise<LoginSession> {
    return await getLoginSessionDomain(this.getAuthSessionDeps(), nearAccountId);
  }

  /**
   * Get check if accountId has a passkey from IndexedDB
   */
  async hasPasskeyCredential(nearAccountId: AccountId): Promise<boolean> {
    return await hasPasskeyCredentialDomain(this.getAuthSessionDeps(), nearAccountId);
  }

  ///////////////////////////////////////
  // === User Settings ===
  ///////////////////////////////////////

  /**
   * Set confirmation behavior setting for the current user
   */
  setConfirmBehavior(behavior: 'requireClick' | 'skipClick'): void {
    this.preferences.setConfirmBehavior(behavior);
  }

  /**
   * Set the unified confirmation configuration
   */
  setConfirmationConfig(config: ConfirmationConfig): void {
    this.preferences.setConfirmationConfig(config);
  }

  setSignerMode(signerMode: SignerMode | SignerMode['mode']): void {
    this.preferences.setSignerMode(signerMode);
  }

  /**
   * Get the current confirmation configuration
   */
  getConfirmationConfig(): ConfirmationConfig {
    // Prefer wallet host value when available
    // Note: synchronous signature; returns last-known local value if iframe reply is async
    // Callers needing a fresh wallet-host value should await init + wallet iframe readiness first.
    return this.preferences.getConfirmationConfig();
  }

  getSignerMode(): SignerMode {
    return this.preferences.getSignerMode();
  }

  /**
   * Prefetch latest block height/hash (and nonce if context missing) to reduce
   * perceived latency when the user initiates a signing flow.
   */
  async prefetchBlockheight(): Promise<void> {
    if (this.walletIframe.shouldUseWalletIframe()) {
      const router = await this.walletIframe.requireRouter();
      await router.prefetchBlockheight();
      return;
    }
    try { await this.webAuthnManager.getNonceManager().prefetchBlockheight(this.nearClient); } catch { }
  }

  async getRecentLogins(): Promise<GetRecentLoginsResult> {
    return await getRecentLoginsDomain(this.getAuthSessionDeps());
  }

  ///////////////////////////////////////
  // === KEY MANAGEMENT ===
  ///////////////////////////////////////

  /**
   * Canonical entrypoint to show secure key export UI (wallet-origin only) without
   * returning private keys to the caller.
   */
  private async exportPrivateKeysWithUIDomain(
    nearAccountId: string,
    options?: {
      schemes?: Array<'ed25519' | 'secp256k1'>;
      variant?: 'drawer' | 'modal';
      theme?: 'dark' | 'light';
    },
  ): Promise<void> {
    const resolvedOptions = {
      ...options,
      theme: options?.theme ?? this.theme,
    };

    if (this.walletIframe.shouldUseWalletIframe()) {
      const router = await this.walletIframe.requireRouter(nearAccountId);
      await router.exportPrivateKeysWithUI(nearAccountId, resolvedOptions);
      return;
    }

    await this.webAuthnManager.credentialRecovery.exportPrivateKeysWithUI(toAccountId(nearAccountId), resolvedOptions);
  }

  /**
   * NEAR-only export helper.
   */
  private async exportNearKeypairWithUIDomain(
    nearAccountId: string,
    options?: { variant?: 'drawer' | 'modal'; theme?: 'dark' | 'light' }
  ): Promise<void> {
    await this.exportPrivateKeysWithUIDomain(nearAccountId, {
      schemes: ['ed25519'],
      variant: options?.variant,
      theme: options?.theme,
    });
  }

  ///////////////////////////////////////
  // === DERIVED ADDRESSES (public helpers) ===
  ///////////////////////////////////////

  /** Store a derived address for an account + contract + path (multi-chain capable via path encoding). */
  async setDerivedAddress(
    nearAccountId: string,
    args: { contractId: string; path: string; address: string }
  ): Promise<void> {
    if (this.walletIframe.shouldUseWalletIframe()) {
      try {
        const router = await this.walletIframe.requireRouter();
        return await router.setDerivedAddress({ nearAccountId, args });
      } catch {
        throw new Error('[TatchiPasskey] Wallet iframe is configured but unavailable; refusing to write derived addresses to app origin.');
      }
    }
    await chainsigAddressManager.setDerivedAddress(toAccountId(nearAccountId), args);
  }

  /** Retrieve the full derived address record (or null if not found). */
  async getDerivedAddressRecord(
    nearAccountId: string,
    args: { contractId: string; path: string }
  ): Promise<DerivedAddressRecord | null> {
    if (this.walletIframe.shouldUseWalletIframe()) {
      try {
        const router = await this.walletIframe.requireRouter();
        return await router.getDerivedAddressRecord({ nearAccountId, args });
      } catch {
        throw new Error('[TatchiPasskey] Wallet iframe is configured but unavailable; refusing to read derived addresses from app origin.');
      }
    }
    return await chainsigAddressManager.getDerivedAddressRecord(toAccountId(nearAccountId), args);
  }

  /** Retrieve only the derived address string for convenience. */
  async getDerivedAddress(
    nearAccountId: string,
    args: { contractId: string; path: string }
  ): Promise<string | null> {
    if (this.walletIframe.shouldUseWalletIframe()) {
      try {
        const router = await this.walletIframe.requireRouter();
        return await router.getDerivedAddress({ nearAccountId, args });
      } catch {
        throw new Error('[TatchiPasskey] Wallet iframe is configured but unavailable; refusing to read derived addresses from app origin.');
      }
    }
    return await chainsigAddressManager.getDerivedAddress(toAccountId(nearAccountId), args);
  }

  /**
   * Delete a device key from an account
   */
  async deleteDeviceKey(
    accountId: string,
    publicKeyToDelete: string,
    options: ActionHooksOptions
  ): Promise<ActionResult> {
    // Validate that we're not deleting the last key
    const keysView = await this.viewAccessKeyList(accountId);
    if (keysView.keys.length <= 1) {
      throw new Error('Cannot delete the last access key from an account');
    }

    // Find the key to delete
    const keyToDelete = keysView.keys.find((k: { public_key: string }) => k.public_key === publicKeyToDelete);
    if (!keyToDelete) {
      throw new Error(`Access key ${publicKeyToDelete} not found on account ${accountId}`);
    }

    // Use NEAR signer executeAction with DeleteKey action
    return this.near.executeAction({
      nearAccountId: accountId,
      receiverId: accountId,
      actionArgs: {
        type: ActionType.DeleteKey,
        publicKey: publicKeyToDelete
      },
      options: options
    });
  }

}

// Re-export types for convenience
export type {
  TatchiConfigs,
  TatchiConfigsInput,
  RegistrationResult,
  LoginAndCreateSessionResult,
  LoginResult,
  LoginSession,
  SigningSessionStatus,
  ActionResult,
} from '../types/tatchi';
export type {
  ActionHooksOptions,
  AfterCall,
  EventCallback,
  LoginHooksOptions,
  LoginSSEvent,
  RegistrationHooksOptions,
  RegistrationSSEEvent,
  SignNEP413HooksOptions,
  SyncAccountHooksOptions,
} from '../types/sdkSentEvents';
// Context alias (optional convenience)
export type TatchiPasskeyContext = PasskeyManagerContext;

// Re-export NEP-413 types
export type {
  SignNEP413MessageParams,
  SignNEP413MessageResult
} from './signNEP413';

export type { DeviceLinkingQRData, DeviceLinkingSession, LinkDeviceResult } from '../types/linkDevice';
export { DeviceLinkingPhase, DeviceLinkingError, DeviceLinkingErrorCode } from '../types/linkDevice';
export type { SyncAccountResult } from './syncAccount';
