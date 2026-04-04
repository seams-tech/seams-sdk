import { SigningEngine } from '../signingEngine/SigningEngine';
import { registerPasskey } from './registration';
import { registerPasskeyInternal } from './registration';
import {
  MinimalNearClient,
  type NearClient,
  type AccessKeyList,
} from '../rpcClients/near/NearClient';
import type {
  ActionResult,
  GetRecentUnlocksResult,
  LoginAndCreateSessionResult,
  WalletSession,
  RegistrationResult,
  ThemeName,
  TatchiConfigsReadonly,
  TatchiConfigsInput,
} from '../types/tatchi';
import type {
  ActionHooksOptions,
  LoginHooksOptions,
  RegistrationHooksOptions,
} from '../types/sdkSentEvents';
import { ConfirmationConfig, type ConfirmationBehavior } from '../types/signer-worker';
import { cloneAuthenticatorOptions } from '../types/authenticatorOptions';
import { toAccountId, type AccountId } from '../types/accountIds';
import { configureIndexedDB } from '../indexedDB';
import { ActionType } from '../types/actions';
import type { PreferencesChangedPayload } from '../WalletIframe/shared/messages';
import { __isWalletIframeHostMode } from '../WalletIframe/host-mode';
import { toError } from '@shared/utils/errors';
import { coerceThemeName } from '@shared/utils/theme';
import { buildConfigsFromEnv } from '../config/defaultConfigs';
import { resolvePrimaryNearRpcUrl } from '../config/chains';
import { WalletIframeCoordinator } from './walletIframeCoordinator';
import {
  getWalletSessionDomain,
  prefillThresholdEcdsaPresignPoolDomain,
  getRecentUnlocksDomain,
  hasPasskeyCredentialDomain,
  unlockDomain,
  lockDomain,
  type AuthSessionDomainDeps,
} from './authSessions';
import type {
  AuthCapability,
  EvmSignerCapability,
  KeyExportCapability,
  NearSignerCapability,
  PasskeyManagerContext,
  PreferencesCapability,
  RegistrationCapability,
  RecoveryCapability,
  TempoSignerCapability,
} from './interfaces';
import type {
  ThresholdEd25519HssFinalizedReportEnvelope,
  ThresholdEd25519HssPreparedSessionEnvelope,
} from '../signingEngine/signers/wasm/hssClientSignerWasm';
import type {
  ThresholdEcdsaActivationChain,
  ThresholdEcdsaLoginPrefillResult,
} from '../signingEngine/SigningEngine';
import { EmailRecoveryDomain } from './near/emailRecovery';
import { DeviceLinkingDomain } from './near/linkDevice';
import { NearSigner } from './near';
import { TempoSigner } from './tempo';
import { EvmSigner } from './evm';

///////////////////////////////////////
// PASSKEY MANAGER
///////////////////////////////////////

/**
 * Main TatchiPasskey class that provides framework-agnostic passkey operations
 * with flexible event-based callbacks for custom UX implementation
 */
export class TatchiPasskey {
  private readonly signingEngine: SigningEngine;
  private readonly nearClient: NearClient;
  readonly configs: TatchiConfigsReadonly;
  theme: ThemeName;
  private readonly walletIframe: WalletIframeCoordinator;
  readonly recovery: RecoveryCapability;
  readonly keys: KeyExportCapability;
  readonly preferences: PreferencesCapability;
  readonly auth: AuthCapability;
  readonly registration: RegistrationCapability;
  readonly near: NearSignerCapability;
  readonly tempo: TempoSignerCapability;
  readonly evm: EvmSignerCapability;

  constructor(configs: TatchiConfigsInput, nearClient?: NearClient) {
    this.configs = buildConfigsFromEnv(configs);
    // Configure IndexedDB naming before any local persistence is touched.
    // - Wallet iframe host keeps canonical DB names.
    // - App origin disables IndexedDB entirely when iframe mode is enabled.
    const mode = __isWalletIframeHostMode()
      ? 'wallet'
      : this.configs.wallet.mode === 'iframe'
        ? 'disabled'
        : 'app';
    configureIndexedDB({ mode });
    // Use provided client or create default one
    this.nearClient =
      nearClient || new MinimalNearClient(resolvePrimaryNearRpcUrl(this.configs.network.chains));
    this.signingEngine = new SigningEngine(this.configs, this.nearClient);

    this.theme = coerceThemeName(this.configs.ui.appearance?.theme) ?? 'dark';
    try {
      this.signingEngine.setTheme(this.theme);
    } catch {}
    const userPreferences = this.signingEngine.getUserPreferences();

    this.walletIframe = new WalletIframeCoordinator({
      configs: this.configs,
      signingEngine: this.signingEngine,
      userPreferences: userPreferences,
      getTheme: () => this.theme,
      refreshWalletSession: async (nearAccountId?: string) => {
        await this.getWalletSession(nearAccountId);
      },
    });
    this.preferences = {
      setCurrentUser: (nearAccountId: AccountId): void => {
        userPreferences.setCurrentUser(nearAccountId);
      },
      getCurrentUserAccountId: (): AccountId => userPreferences.getCurrentUserAccountId(),
      onConfirmationConfigChange: (callback): (() => void) =>
        userPreferences.onConfirmationConfigChange(callback),
      onCurrentUserChange: (callback): (() => void) =>
        userPreferences.onCurrentUserChange(callback),
      setConfirmBehavior: (behavior): void => {
        if (this.walletIframe.shouldUseWalletIframe()) {
          void (async () => {
            try {
              const router = await this.walletIframe.requireRouter();
              await router.setConfirmBehavior(behavior);
            } catch {}
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
            } catch {}
          })();
          return;
        }
        userPreferences.setConfirmationConfig(config);
      },
      getConfirmationConfig: (): ConfirmationConfig => userPreferences.getConfirmationConfig(),
    };
    this.auth = {
      unlock: async (nearAccountId, options) => await this.unlock(nearAccountId, options),
      lock: async () => await this.lock(),
      getWalletSession: async (nearAccountId) => await this.getWalletSession(nearAccountId),
      getRecentUnlocks: async () => await this.getRecentUnlocks(),
      hasPasskeyCredential: async (nearAccountId) => await this.hasPasskeyCredential(nearAccountId),
      prefillThresholdEcdsaPresignPool: async (args) =>
        await this.prefillThresholdEcdsaPresignPool(args),
    };
    this.registration = {
      registerPasskey: async (nearAccountId, options) =>
        await this.registerPasskey(nearAccountId, options),
      registerPasskeyInternal: async (nearAccountId, options, confirmationConfigOverride) =>
        await this.registerPasskeyInternal(nearAccountId, options, confirmationConfigOverride),
    };
    const recoveryDeps = {
      getContext: () => this.getContext(),
      walletIframe: this.walletIframe,
    };
    const emailRecovery = new EmailRecoveryDomain(recoveryDeps);
    const deviceLinking = new DeviceLinkingDomain(recoveryDeps);
    this.recovery = {
      getRecoveryEmails: async (accountId) => await emailRecovery.getRecoveryEmails(accountId),
      setRecoveryEmails: async (args) => await emailRecovery.setRecoveryEmails(args),
      syncAccount: async (args) => await emailRecovery.syncAccount(args),
      startEmailRecovery: async (args) => await emailRecovery.startEmailRecovery(args),
      finalizeEmailRecovery: async (args) => await emailRecovery.finalizeEmailRecovery(args),
      cancelEmailRecovery: async (args) => await emailRecovery.cancelEmailRecovery(args),
      startDevice2LinkingFlow: async (args) => await deviceLinking.startDevice2LinkingFlow(args),
      stopDevice2LinkingFlow: async () => await deviceLinking.stopDevice2LinkingFlow(),
      linkDeviceWithScannedQRData: async (qrData, options) =>
        await deviceLinking.linkDeviceWithScannedQRData(qrData, options),
    };
    this.keys = {
      exportKeypairWithUI: async (nearAccountId, options) =>
        await this.exportKeypairWithUIDomain(nearAccountId, options),
      exportThresholdEd25519SeedFromHssReport: async (args) =>
        await this.exportThresholdEd25519SeedFromHssReportDomain(args),
    };
    const signerDeps = {
      getContext: () => this.getContext(),
      walletIframe: this.walletIframe,
    };
    this.near = new NearSigner(signerDeps);
    this.tempo = new TempoSigner(signerDeps);
    this.evm = new EvmSigner(signerDeps);

    // UserConfirm worker initializes automatically in the constructor
  }

  /**
   * Initialize the hidden wallet service iframe client (optional) and warm critical resources.
   * Always warms local resources; initializes iframe when wallet mode is `iframe`.
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
      signingEngine: this.signingEngine,
      nearClient: this.nearClient,
      configs: this.configs,
      theme: this.theme,
    };
  }

  private getAuthSessionDeps(): AuthSessionDomainDeps {
    return {
      getContext: () => this.getContext(),
      walletIframe: this.walletIframe,
      signingEngine: this.signingEngine,
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
      this.signingEngine.setTheme(nextTheme);
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
  async prewarm(opts?: {
    iframe?: boolean;
    workers?: boolean;
    nearAccountId?: string;
  }): Promise<void> {
    const iframe = !!opts?.iframe;
    const workers = !!opts?.workers;
    const nearAccountId = opts?.nearAccountId;

    const tasks: Promise<unknown>[] = [];

    if (iframe) {
      // initWalletIframe also calls SigningEngine.warmCriticalResources internally
      tasks.push(this.initWalletIframe(nearAccountId));
    } else if (workers) {
      // Warm local-only resources without touching the iframe.
      // In iframe mode, avoid persisting user state (lastUserAccountId, preferences) on the app origin.
      const shouldAvoidLocalUserState = this.walletIframe.shouldUseWalletIframe();
      tasks.push(
        this.signingEngine.warmCriticalResources(
          shouldAvoidLocalUserState ? undefined : nearAccountId,
        ),
      );
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
    options: RegistrationHooksOptions = {},
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
            ...(options?.signerOptions ? { signerOptions: options.signerOptions } : {}),
            ...(options?.confirmerText ? { confirmerText: options.confirmerText } : {}),
          },
        });
        // Opportunistically warm resources (non-blocking)
        void (async () => {
          try {
            await this.initWalletIframe(nearAccountId);
          } catch {}
        })();
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
      cloneAuthenticatorOptions(this.configs.webauthn.authenticatorOptions),
    );
  }

  /**
   * Internal variant that accepts a one-time confirmationConfig override.
   * Used by wallet-iframe host to force modal/skipClick behavior for ArrowButtonLit.
   */
  async registerPasskeyInternal(
    nearAccountId: string,
    options: RegistrationHooksOptions = {},
    confirmationConfigOverride?: ConfirmationConfig,
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
            ...(options?.signerOptions ? { signerOptions: options.signerOptions } : {}),
            ...(options?.confirmerText ? { confirmerText: options.confirmerText } : {}),
          },
        });
        void (async () => {
          try {
            await this.initWalletIframe(nearAccountId);
          } catch {}
        })();
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
      cloneAuthenticatorOptions(this.configs.webauthn.authenticatorOptions),
      confirmationConfigOverride,
    );
  }

  /**
   * Unlock wallet state and optionally mint a warm signing session.
   * - Sets the active account/deviceNumber (IndexedDB last-user pointer)
   * - Optional: mints a relay app-session (JWT/cookie) via BYO exchange
   * - In `threshold-signer` mode with warm-session policy enabled, threshold warm-up
   *   (ed25519 + ECDSA) is part of unlock and must succeed.
   */
  async unlock(
    nearAccountId: string,
    options?: LoginHooksOptions,
  ): Promise<LoginAndCreateSessionResult> {
    return await unlockDomain(this.getAuthSessionDeps(), nearAccountId, options);
  }

  /**
   * Lock wallet state: clears last-user pointer and local session caches.
   */
  async lock(): Promise<void> {
    await lockDomain(this.getAuthSessionDeps());
  }

  /**
   * Read wallet session state + warm signing session status (no prompts).
   */
  async getWalletSession(nearAccountId?: string): Promise<WalletSession> {
    return await getWalletSessionDomain(this.getAuthSessionDeps(), nearAccountId);
  }

  /**
   * Get check if accountId has a passkey from IndexedDB
   */
  async hasPasskeyCredential(nearAccountId: AccountId): Promise<boolean> {
    return await hasPasskeyCredentialDomain(this.getAuthSessionDeps(), nearAccountId);
  }

  async prefillThresholdEcdsaPresignPool(args: {
    nearAccountId: string;
    chain?: ThresholdEcdsaActivationChain;
    waitForPoolReady?: boolean;
    poolReadyTimeoutMs?: number;
    poolReadyPollIntervalMs?: number;
    minRemainingUsesBeforePrefill?: number;
  }): Promise<ThresholdEcdsaLoginPrefillResult> {
    return await prefillThresholdEcdsaPresignPoolDomain(this.getAuthSessionDeps(), args);
  }

  ///////////////////////////////////////
  // === User Settings ===
  ///////////////////////////////////////

  /**
   * Set confirmation behavior setting for the current user
   */
  setConfirmBehavior(behavior: ConfirmationBehavior): void {
    this.preferences.setConfirmBehavior(behavior);
  }

  /**
   * Set the unified confirmation configuration
   */
  setConfirmationConfig(config: ConfirmationConfig): void {
    this.preferences.setConfirmationConfig(config);
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
    try {
      await this.signingEngine.getNonceManager().prefetchBlockheight(this.nearClient);
    } catch {}
  }

  async getRecentUnlocks(): Promise<GetRecentUnlocksResult> {
    return await getRecentUnlocksDomain(this.getAuthSessionDeps());
  }

  ///////////////////////////////////////
  // === KEY MANAGEMENT ===
  ///////////////////////////////////////

  /**
   * Canonical entrypoint to show secure key export UI (wallet-origin only) without
   * returning private keys to the caller.
   */
  private async exportKeypairWithUIDomain(
    nearAccountId: string,
    options: {
      chain: 'near' | 'evm' | 'tempo';
      variant?: 'drawer' | 'modal';
      theme?: 'dark' | 'light';
    },
  ): Promise<void> {
    const resolvedOptions = {
      ...options,
      theme: options.theme ?? this.theme,
    };

    if (this.walletIframe.shouldUseWalletIframe()) {
      const router = await this.walletIframe.requireRouter(nearAccountId);
      await router.exportKeypairWithUI(nearAccountId, resolvedOptions);
      return;
    }

    await this.signingEngine.exportKeypairWithUI(toAccountId(nearAccountId), resolvedOptions);
  }

  private async exportThresholdEd25519SeedFromHssReportDomain(args: {
    nearAccountId: string;
    preparedSession: ThresholdEd25519HssPreparedSessionEnvelope;
    finalizedReport: ThresholdEd25519HssFinalizedReportEnvelope;
    expectedPublicKey: string;
    options: {
      variant?: 'drawer' | 'modal';
      theme?: 'dark' | 'light';
    };
  }): Promise<void> {
    const resolvedOptions = {
      ...args.options,
      theme: args.options.theme ?? this.theme,
    };

    if (this.walletIframe.shouldUseWalletIframe()) {
      const router = await this.walletIframe.requireRouter(args.nearAccountId);
      await router.exportThresholdEd25519SeedFromHssReport({
        nearAccountId: args.nearAccountId,
        preparedSession: args.preparedSession,
        finalizedReport: args.finalizedReport,
        expectedPublicKey: args.expectedPublicKey,
        options: resolvedOptions,
      });
      return;
    }

    await this.signingEngine.exportThresholdEd25519SeedFromHssReport({
      nearAccountId: toAccountId(args.nearAccountId),
      preparedSession: args.preparedSession,
      finalizedReport: args.finalizedReport,
      expectedPublicKey: args.expectedPublicKey,
      options: resolvedOptions,
    });
  }

  /**
   * Delete a device key from an account
   */
  async deleteDeviceKey(
    accountId: string,
    publicKeyToDelete: string,
    options: ActionHooksOptions,
  ): Promise<ActionResult> {
    // Validate that we're not deleting the last key
    const keysView = await this.viewAccessKeyList(accountId);
    if (keysView.keys.length <= 1) {
      throw new Error('Cannot delete the last access key from an account');
    }

    // Find the key to delete
    const keyToDelete = keysView.keys.find(
      (k: { public_key: string }) => k.public_key === publicKeyToDelete,
    );
    if (!keyToDelete) {
      throw new Error(`Access key ${publicKeyToDelete} not found on account ${accountId}`);
    }

    // Use NEAR signer executeAction with DeleteKey action
    return this.near.executeAction({
      nearAccountId: accountId,
      receiverId: accountId,
      actionArgs: {
        type: ActionType.DeleteKey,
        publicKey: publicKeyToDelete,
      },
      options: options,
    });
  }
}

// Re-export types for convenience
export type {
  AuthCapability,
  BootstrapThresholdEcdsaSessionArgs,
  ExecuteEvmFamilyTransactionArgs,
  ExecuteEvmFamilyTransactionResult,
  EvmSignerCapability,
  FinalizedEvmTxPayloadVerification,
  KeyExportCapability,
  NearSignerCapability,
  PasskeyManagerContext,
  PreferencesCapability,
  RegistrationCapability,
  RecoveryCapability,
  ReconcileTempoNonceLaneArgs,
  ReportTempoBroadcastAcceptedArgs,
  ReportTempoBroadcastRejectedArgs,
  ReportTempoDroppedOrReplacedArgs,
  ReportTempoFinalizedArgs,
  SignTempoArgs,
  TempoNonceLifecycleEvent,
  TempoNonceLifecycleOptions,
  TempoNonceLaneStatus,
  TempoSignerCapability,
} from './interfaces';

export type {
  TatchiConfigsReadonly,
  TatchiConfigsInput,
  RegistrationResult,
  LoginAndCreateSessionResult,
  LoginResult,
  WalletSession,
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

// Re-export NEP-413 types
export type { SignNEP413MessageParams, SignNEP413MessageResult } from './near/signNEP413';

export type {
  DeviceLinkingQRData,
  DeviceLinkingSession,
  LinkDeviceResult,
} from '../types/linkDevice';
export {
  DeviceLinkingPhase,
  DeviceLinkingError,
  DeviceLinkingErrorCode,
} from '../types/linkDevice';
export type { SyncAccountResult } from './syncAccount';
