/**
 * SeamsPasskeyIframe - Entry Point Layer
 *
 * This is the main API that developers interact with when using the WalletIframe system.
 * It provides the same interface as the regular SeamsPasskey for core wallet actions, and routes calls to
 * a secure iframe for enhanced security and WebAuthn compatibility.
 *
 * Key Responsibilities:
 * - Acts as a transparent proxy to the real SeamsPasskey running in the iframe
 * - Handles hook callbacks (afterCall, onError, onEvent) locally
 * - Avoids app-origin IndexedDB persistence (no silent fallbacks)
 * - Manages theme state and user settings synchronization
 * - Bridges progress events from iframe back to developer callbacks
 *
 * Architecture:
 * - Uses WalletIframeRouter for all iframe communication
 * - Maintains local state for immediate synchronous access (theme, config)
 * - Does not fall back to app-origin persistence when the iframe is unavailable
 */

import { WalletIframeRouter } from './client/router';
import type {
  ThresholdEcdsaActivationChain,
  ThresholdEcdsaLoginPrefillResult,
  ThresholdEcdsaSessionBootstrapResult,
} from '../signingEngine/SigningEngine';
import type {
  ThresholdEd25519HssFinalizedReportEnvelope,
  ThresholdEd25519HssPreparedSessionEnvelope,
} from '../signingEngine/signers/wasm/hssClientSignerWasm';
import type { SignedTransaction, AccessKeyList } from '../rpcClients/near/NearClient';
import type { PreferencesChangedPayload } from './shared/messages';
import type {
  ActionResult,
  DelegateRelayResult,
  GetRecentUnlocksResult,
  LoginAndCreateSessionResult,
  WalletSession,
  LoginState,
  RegistrationResult,
  SignAndSendDelegateActionResult,
  SignDelegateActionResult,
  SignTransactionResult,
  ThemeName,
  SeamsConfigsReadonly,
  SeamsConfigsInput,
} from '../types/seams';
import type {
  ActionHooksOptions,
  DelegateActionHooksOptions,
  DelegateRelayHooksOptions,
  KeyExportHooksOptions,
  LoginHooksOptions,
  RegistrationHooksOptions,
  SendTransactionHooksOptions,
  SignAndSendDelegateActionHooksOptions,
  SignAndSendTransactionHooksOptions,
  SignNEP413HooksOptions,
  SignTransactionHooksOptions,
} from '../types/sdkSentEvents';

import type { ActionArgs, TransactionInput, TxExecutionStatus } from '../types';
import {
  type ConfirmationConfig,
  type WasmSignedDelegate,
  DEFAULT_CONFIRMATION_CONFIG,
} from '../types/signer-worker';
import type { SignNEP413MessageParams, SignNEP413MessageResult } from '../SeamsPasskey/near';
import { toError } from '@shared/utils/errors';
import { coerceThemeName } from '@shared/utils/theme';
import type { WalletUIRegistry } from './host/lit-ui/iframe-lit-element-registry';
import type { DelegateActionInput, SignedDelegate } from '../types/delegate';
import { buildConfigsFromEnv } from '../config/defaultConfigs';
import { cloneAuthenticatorOptions } from '../types/authenticatorOptions';
import { configureIndexedDB } from '../indexedDB';
import type { EvmSignedResult } from '../signingEngine/chainAdaptors/evm/evmAdapter';
import type { TempoSignedResult } from '../signingEngine/chainAdaptors/tempo/tempoAdapter';
import type {
  BootstrapThresholdEcdsaSessionArgs,
  ExecuteEvmFamilyTransactionArgs,
  ExecuteEvmFamilyTransactionResult,
  RecoveryCapability,
  EvmSignerCapability,
  KeyExportCapability,
  NearSignerCapability,
  ReconcileTempoNonceLaneArgs,
  ReportTempoBroadcastAcceptedArgs,
  ReportTempoBroadcastRejectedArgs,
  ReportTempoDroppedOrReplacedArgs,
  ReportTempoFinalizedArgs,
  SignTempoArgs,
  TempoNonceLaneStatus,
  TempoSignerCapability,
} from '../SeamsPasskey';
import { executeEvmFamilyTransactionLifecycle } from '../SeamsPasskey/tempo/executeEvmFamilyTransaction';

export class SeamsPasskeyIframe {
  readonly configs: SeamsConfigsReadonly;
  theme: ThemeName;
  private router: WalletIframeRouter;
  private lastConfirmationConfig: ConfirmationConfig = DEFAULT_CONFIRMATION_CONFIG;
  private prefsUnsubscribe: (() => void) | null = null;
  readonly near: NearSignerCapability;
  readonly tempo: TempoSignerCapability;
  readonly evm: EvmSignerCapability;
  readonly recovery: RecoveryCapability;
  readonly keys: KeyExportCapability;

  // Expose a userPreferences shim so API matches SeamsPasskey
  get userPreferences() {
    return {
      setConfirmBehavior: (b: 'requireClick' | 'skipClick') => {
        this.setConfirmBehavior(b);
      },
      setConfirmationConfig: (c: ConfirmationConfig) => {
        this.setConfirmationConfig(c);
      },
      getConfirmationConfig: () => this.getConfirmationConfig(),
    };
  }

  constructor(configs: SeamsConfigsInput) {
    this.configs = buildConfigsFromEnv(configs);
    // In iframe-wallet mode, disable app-origin IndexedDB entirely so no SDK tables are created there.
    // Wallet iframe host uses canonical DB names within the wallet origin.
    configureIndexedDB({ mode: 'disabled' });

    const walletOrigin = this.configs.wallet.iframe?.origin;
    if (!walletOrigin) {
      throw new Error(
        '[SeamsPasskeyIframe] wallet.iframe.origin is required to enable the wallet iframe. Configure it to a dedicated origin.',
      );
    }

    let parsedWalletOrigin: URL;
    try {
      parsedWalletOrigin = new URL(walletOrigin);
    } catch (err) {
      throw new Error(
        `[SeamsPasskeyIframe] Invalid wallet.iframe.origin (${walletOrigin}). Provide an absolute URL.`,
      );
    }

    if (typeof window !== 'undefined') {
      const parentOrigin = window.location.origin;
      if (parsedWalletOrigin.origin === parentOrigin) {
        console.warn(
          '[SeamsPasskeyIframe] wallet.iframe.origin matches the host origin. Isolation is reduced; consider serving the wallet from a dedicated origin.',
        );
      }
    }

    this.theme = 'dark';
    this.lastConfirmationConfig = { ...DEFAULT_CONFIRMATION_CONFIG } as ConfirmationConfig;
    const signingSessionPersistenceMode = this.configs.signing.sessionPersistenceMode;
    const signingSessionSeal =
      signingSessionPersistenceMode === 'sealed_refresh_v1'
        ? this.configs.signing.sessionSeal
        : undefined;
    const signingSessionDefaults = this.configs.signing.sessionDefaults;
    const thresholdEcdsaPresignPool = this.configs.signing.thresholdEcdsa.presignPool;
    const provisioningDefaults = this.configs.signing.thresholdEcdsa.provisioningDefaults;

    this.router = new WalletIframeRouter({
      walletOrigin: parsedWalletOrigin.toString(),
      servicePath: this.configs.wallet.iframe?.servicePath || '/wallet-service',
      // Lower connect timeout to reduce initial boot-wait window (25% of this).
      // With 3_000ms, boot wait caps at ~750ms; improves sub‑second readiness in dev.
      connectTimeoutMs: 3_000,
      requestTimeoutMs: 60_000,
      chains: this.configs.network.chains,
      relayerAccount: this.configs.network.relayer.accountId,
      registration: this.configs.registration,
      signingSessionDefaults,
      signingSessionPersistenceMode,
      ...(signingSessionSeal ? { signingSessionSeal } : {}),
      thresholdEcdsaPresignPool,
      provisioningDefaults,
      // relayer: configs.network.relayer,
      rpIdOverride: this.configs.wallet.iframe?.rpIdOverride,
      authenticatorOptions: cloneAuthenticatorOptions(this.configs.webauthn.authenticatorOptions),
    });

    this.near = {
      executeAction: async (args) => await this.executeActionDomain(args),
      signAndSendTransactions: async (args) => await this.signAndSendTransactionsDomain(args),
      signAndSendTransaction: async (args) => {
        const results = await this.signAndSendTransactionsDomain({
          nearAccountId: args.nearAccountId,
          transactions: [
            {
              receiverId: args.receiverId,
              actions: args.actions,
            },
          ],
          options: args.options,
        });
        return results[0] as ActionResult;
      },
      signTransactionsWithActions: async (args) =>
        await this.signTransactionsWithActionsDomain(args),
      sendTransaction: async (args) => await this.sendTransactionDomain(args),
      signDelegateAction: async (args) => await this.signDelegateActionDomain(args),
      sendDelegateActionViaRelayer: async (args) =>
        await this.sendDelegateActionViaRelayerDomain(args),
      signAndSendDelegateAction: async (args) => await this.signAndSendDelegateActionDomain(args),
      signNEP413Message: async (args) => await this.signNEP413MessageDomain(args),
    };
    this.tempo = {
      signTempo: async (args) => await this.signTempoDomain(args),
      executeEvmFamilyTransaction: async (args) =>
        await this.executeEvmFamilyTransactionDomain(args),
      reportBroadcastAccepted: async (args) => await this.reportTempoBroadcastAcceptedDomain(args),
      reportBroadcastRejected: async (args) => await this.reportTempoBroadcastRejectedDomain(args),
      reportFinalized: async (args) => await this.reportTempoFinalizedDomain(args),
      reportDroppedOrReplaced: async (args) => await this.reportTempoDroppedOrReplacedDomain(args),
      reconcileNonceLane: async (args) => await this.reconcileTempoNonceLaneDomain(args),
      bootstrapEcdsaSession: async (args) =>
        await this.bootstrapEcdsaSessionDomain({
          nearAccountId: args.nearAccountId,
          options: { ...(args.options || {}), chain: 'tempo' },
        }),
    };
    this.evm = {
      bootstrapEcdsaSession: async (args) =>
        await this.bootstrapEcdsaSessionDomain({
          nearAccountId: args.nearAccountId,
          options: { ...(args.options || {}), chain: 'evm' },
        }),
    };
    this.recovery = {
      getRecoveryEmails: async (accountId) => {
        await this.requireRouterReady();
        return await this.router.getRecoveryEmails(accountId);
      },
      setRecoveryEmails: async (args) => {
        await this.requireRouterReady();
        return await this.router.setRecoveryEmails({
          nearAccountId: args.accountId,
          recoveryEmails: args.recoveryEmails,
          options: args.options,
        });
      },
      syncAccount: async (args) => {
        await this.requireRouterReady();
        return await this.router.syncAccount({
          ...(args?.accountId ? { accountId: args.accountId } : {}),
          onEvent: args?.options?.onEvent,
        });
      },
      startEmailRecovery: async (args) => {
        await this.requireRouterReady();
        return await this.router.startEmailRecovery({
          accountId: args.accountId,
          onEvent: args.options?.onEvent,
          options: {
            ...(args.options?.confirmerText ? { confirmerText: args.options.confirmerText } : {}),
            ...(args.options?.confirmationConfig
              ? { confirmationConfig: args.options.confirmationConfig }
              : {}),
          },
        });
      },
      finalizeEmailRecovery: async (args) => {
        await this.requireRouterReady();
        await this.router.finalizeEmailRecovery({
          accountId: args.accountId,
          ...(args.nearPublicKey ? { nearPublicKey: args.nearPublicKey } : {}),
          onEvent: args.options?.onEvent,
        });
      },
      cancelEmailRecovery: async (args) => {
        await this.requireRouterReady();
        await this.router.stopEmailRecovery(args);
      },
      startDevice2LinkingFlow: async (args) => {
        await this.requireRouterReady();
        return await this.router.startDevice2LinkingFlow(args);
      },
      stopDevice2LinkingFlow: async () => {
        await this.requireRouterReady();
        await this.router.stopDevice2LinkingFlow();
      },
      linkDeviceWithScannedQRData: async (qrData, options) => {
        await this.requireRouterReady();
        return await this.router.linkDeviceWithScannedQRData({
          qrData,
          fundingAmount: options.fundingAmount,
          options: {
            onEvent: options.onEvent,
            ...(options.confirmerText ? { confirmerText: options.confirmerText } : {}),
            ...(options.confirmationConfig
              ? { confirmationConfig: options.confirmationConfig }
              : {}),
          },
        });
      },
    };
    this.keys = {
      exportKeypairWithUI: async (nearAccountId, options) =>
        await this.exportKeypairWithUIDomain(nearAccountId, options),
      exportThresholdEd25519SeedFromHssReport: async (args) =>
        await this.exportThresholdEd25519SeedFromHssReportDomain(args),
    };
  }

  async initWalletIframe(): Promise<void> {
    await this.router.init();
    if (!this.prefsUnsubscribe) {
      this.prefsUnsubscribe =
        this.router.onPreferencesChanged?.((payload: PreferencesChangedPayload) => {
          const cfg = payload.confirmationConfig;
          if (!cfg) return;
          this.applyRemoteConfirmationConfig(cfg);
        }) || null;
    }
    await this.refreshConfirmationConfig();
  }

  private async requireRouterReady(): Promise<WalletIframeRouter> {
    if (!this.router.isReady()) {
      await this.initWalletIframe();
    }
    if (!this.router.isReady()) {
      throw new Error('[SeamsPasskeyIframe] Wallet iframe is configured but unavailable.');
    }
    return this.router;
  }

  isReady(): boolean {
    return this.router.isReady();
  }

  onReady(cb: () => void): () => void {
    return this.router.onReady(cb);
  }

  onLoginStatusChanged(
    cb: (status: { isLoggedIn: boolean; nearAccountId: string | null }) => void,
  ): () => void {
    return this.router.onLoginStatusChanged(cb);
  }

  // === Generic Wallet UI registration/mounting ===
  registerWalletUI(types: WalletUIRegistry): void {
    this.router.registerUiTypes(types);
  }
  mountWalletUI(params: {
    key: string;
    props?: Record<string, unknown>;
    targetSelector?: string;
    id?: string;
  }): void {
    this.router.mountUiComponent(params);
  }
  updateWalletUI(id: string, props?: Record<string, unknown>): void {
    this.router.updateUiComponent({ id, props });
  }
  unmountWalletUI(id: string): void {
    this.router.unmountUiComponent(id);
  }

  async registerPasskey(
    nearAccountId: string,
    options: RegistrationHooksOptions = {},
  ): Promise<RegistrationResult> {
    try {
      // Route the registration request to the iframe via WalletIframeRouter
      // This will:
      // - Create a unique request ID
      // - Send PM_REGISTER message to iframe
      // - Show overlay for WebAuthn activation
      // - Bridge progress events back to onEvent callback
      const res = await this.router.registerPasskey({
        nearAccountId,
        confirmationConfig: options?.confirmationConfig,
        options: {
          onEvent: options?.onEvent,
          ...(options?.signerOptions ? { signerOptions: options.signerOptions } : {}),
          ...(options?.confirmerText ? { confirmerText: options.confirmerText } : {}),
        }, // Bridge progress events from iframe to parent
      });
      await options?.afterCall?.(true, res);
      return res;
    } catch (err: unknown) {
      const e = toError(err);
      await options?.onError?.(e);
      await options?.afterCall?.(false, undefined, e);
      throw e;
    }
  }

  async unlock(
    nearAccountId: string,
    options?: LoginHooksOptions,
  ): Promise<LoginAndCreateSessionResult> {
    try {
      // Route login request to iframe - similar flow to registerPasskey
      // The iframe will handle WebAuthn authentication and session creation
      const res = await this.router.unlock({
        nearAccountId,
        options: {
          onEvent: options?.onEvent,
          signerSlot: options?.signerSlot,
          session: options?.session,
          signingSession: options?.signingSession,
        }, // Progress events flow back to parent
      });
      await options?.afterCall?.(true, res);
      return res;
    } catch (err: unknown) {
      const e = toError(err);
      await options?.onError?.(e);
      await options?.afterCall?.(false, undefined, e);
      throw e;
    }
  }

  async lock(): Promise<void> {
    await this.router.lock();
  }

  async getWalletSession(nearAccountId?: string): Promise<WalletSession> {
    if (!this.router.isReady()) {
      const login: LoginState = {
        isLoggedIn: false,
        nearAccountId: null,
        publicKey: null,
        userData: null,
      } as LoginState;
      return { login, signingSession: null };
    }
    return await this.router.getWalletSession(nearAccountId);
  }

  async prefillThresholdEcdsaPresignPool(args: {
    nearAccountId: string;
    chain?: ThresholdEcdsaActivationChain;
    waitForPoolReady?: boolean;
    poolReadyTimeoutMs?: number;
    poolReadyPollIntervalMs?: number;
    minRemainingUsesBeforePrefill?: number;
  }): Promise<ThresholdEcdsaLoginPrefillResult> {
    await this.requireRouterReady();
    return await this.router.prefillThresholdEcdsaPresignPool({
      nearAccountId: args.nearAccountId,
      options: {
        ...(args.chain ? { chain: args.chain } : {}),
        ...(typeof args.waitForPoolReady === 'boolean'
          ? { waitForPoolReady: args.waitForPoolReady }
          : {}),
        ...(typeof args.poolReadyTimeoutMs === 'number'
          ? { poolReadyTimeoutMs: args.poolReadyTimeoutMs }
          : {}),
        ...(typeof args.poolReadyPollIntervalMs === 'number'
          ? { poolReadyPollIntervalMs: args.poolReadyPollIntervalMs }
          : {}),
        ...(typeof args.minRemainingUsesBeforePrefill === 'number'
          ? { minRemainingUsesBeforePrefill: args.minRemainingUsesBeforePrefill }
          : {}),
      },
    });
  }

  private async signTransactionsWithActionsDomain(args: {
    nearAccountId: string;
    transactions: TransactionInput[];
    options: SignTransactionHooksOptions;
  }): Promise<SignTransactionResult[]> {
    try {
      // Route transaction signing to iframe
      // This will:
      // - Send PM_SIGN_TXS_WITH_ACTIONS message to iframe
      // - Show overlay during user confirmation and WebAuthn phases
      // - Handle transaction signing in secure iframe context
      // - Bridge progress events back to parent
      const res = await this.router.signTransactionsWithActions({
        nearAccountId: args.nearAccountId,
        transactions: args.transactions,
        options: {
          signerSlot: args.options?.signerSlot,
          confirmerText: args.options?.confirmerText,
          confirmationConfig: args.options?.confirmationConfig,
          onEvent: args.options?.onEvent,
        },
      });
      await args.options?.afterCall?.(true, res);
      return res;
    } catch (err: unknown) {
      const e = toError(err);
      await args.options?.onError?.(e);
      await args.options?.afterCall?.(false, undefined, e);
      throw e;
    }
  }

  private async signNEP413MessageDomain(args: {
    nearAccountId: string;
    params: SignNEP413MessageParams;
    options: SignNEP413HooksOptions;
  }): Promise<SignNEP413MessageResult> {
    try {
      const res = await this.router.signNep413Message({
        nearAccountId: args.nearAccountId,
        message: args.params.message,
        recipient: args.params.recipient,
        state: args.params.state,
        options: {
          signerSlot: args.options?.signerSlot,
          onEvent: args.options?.onEvent,
          confirmerText: args.options?.confirmerText,
          confirmationConfig: args.options?.confirmationConfig,
        },
      });
      await args.options?.afterCall?.(true, res);
      return res;
    } catch (err: unknown) {
      const e = toError(err);
      await args.options?.onError?.(e);
      await args.options?.afterCall?.(false, undefined, e);
      throw e;
    }
  }

  private async signDelegateActionDomain(args: {
    nearAccountId: string;
    delegate: DelegateActionInput;
    options: DelegateActionHooksOptions;
  }): Promise<SignDelegateActionResult> {
    const options = args.options;
    try {
      await this.requireRouterReady();
      const res = (await this.router.signDelegateAction({
        nearAccountId: args.nearAccountId,
        delegate: args.delegate,
        options: {
          signerSlot: options?.signerSlot,
          onEvent: options?.onEvent,
          confirmationConfig: options?.confirmationConfig,
          confirmerText: options?.confirmerText,
        },
      })) as SignDelegateActionResult;
      await options?.afterCall?.(true, res);
      return res;
    } catch (err: unknown) {
      const e = toError(err);
      await args.options?.onError?.(e);
      await args.options?.afterCall?.(false, undefined, e);
      throw e;
    }
  }

  private async sendDelegateActionViaRelayerDomain(args: {
    relayerUrl: string;
    signedDelegate: SignedDelegate | WasmSignedDelegate;
    hash: string;
    signal?: AbortSignal;
    options?: DelegateRelayHooksOptions;
  }): Promise<DelegateRelayResult> {
    const base = args.relayerUrl.replace(/\/+$/, '');
    const route = (
      this.configs.network.relayer?.routes?.delegateAction || '/signed-delegate'
    ).replace(/^\/?/, '/');
    const endpoint = `${base}${route}`;
    const { sendDelegateActionViaRelayer } = await import('../SeamsPasskey/near');
    return sendDelegateActionViaRelayer({
      url: endpoint,
      payload: {
        hash: args.hash,
        signedDelegate: args.signedDelegate,
      },
      signal: args.signal,
      options: args.options,
    });
  }

  private async signAndSendDelegateActionDomain(args: {
    nearAccountId: string;
    delegate: DelegateActionInput;
    relayerUrl: string;
    signal?: AbortSignal;
    options: SignAndSendDelegateActionHooksOptions;
  }): Promise<SignAndSendDelegateActionResult> {
    const { nearAccountId, delegate, relayerUrl, signal, options } = args;

    const signOptions: DelegateActionHooksOptions | undefined = options
      ? {
          signerSlot: options.signerSlot,
          onEvent: options.onEvent,
          onError: options.onError,
          waitUntil: options.waitUntil,
          confirmationConfig: options.confirmationConfig,
          confirmerText: options.confirmerText,
          afterCall: () => {},
        }
      : undefined;

    let signResult: SignDelegateActionResult;
    try {
      signResult = await this.signDelegateActionDomain({
        nearAccountId,
        delegate,
        options: signOptions as DelegateActionHooksOptions,
      });
    } catch (error) {
      const e = toError(error);
      await options?.afterCall?.(false, undefined, e);
      throw e;
    }

    const relayOptions: DelegateRelayHooksOptions | undefined = options
      ? {
          onEvent: options.onEvent,
          onError: options.onError,
        }
      : undefined;

    let relayResult: DelegateRelayResult;
    try {
      relayResult = await this.sendDelegateActionViaRelayerDomain({
        relayerUrl,
        hash: signResult.hash,
        signedDelegate: signResult.signedDelegate,
        signal,
        options: relayOptions,
      });
    } catch (error) {
      const e = toError(error);
      await options?.afterCall?.(false, undefined, e);
      throw e;
    }

    const combined: SignAndSendDelegateActionResult = {
      signResult,
      relayResult,
    };

    const success = relayResult.ok !== false;
    if (success) {
      await options?.afterCall?.(true, combined);
    } else {
      const relayError = toError(relayResult.error || 'Delegate relay failed');
      await options?.afterCall?.(false, undefined, relayError);
    }
    return combined;
  }

  private async signTempoDomain(args: SignTempoArgs): Promise<TempoSignedResult | EvmSignedResult> {
    await this.requireRouterReady();
    return await this.router.signTempo({
      nearAccountId: args.nearAccountId,
      request: args.request,
      options: {
        confirmationConfig: args.options?.confirmationConfig,
        onEvent: args.options?.onEvent,
      },
    });
  }

  private async executeEvmFamilyTransactionDomain(
    args: ExecuteEvmFamilyTransactionArgs,
  ): Promise<ExecuteEvmFamilyTransactionResult> {
    return await executeEvmFamilyTransactionLifecycle({
      capability: {
        signTempo: async (innerArgs) => await this.signTempoDomain(innerArgs),
        reportBroadcastAccepted: async (innerArgs) =>
          await this.reportTempoBroadcastAcceptedDomain(innerArgs),
        reportBroadcastRejected: async (innerArgs) =>
          await this.reportTempoBroadcastRejectedDomain(innerArgs),
        reportFinalized: async (innerArgs) => await this.reportTempoFinalizedDomain(innerArgs),
        reportDroppedOrReplaced: async (innerArgs) =>
          await this.reportTempoDroppedOrReplacedDomain(innerArgs),
        reconcileNonceLane: async (innerArgs) =>
          await this.reconcileTempoNonceLaneDomain(innerArgs),
      },
      chains: this.configs.network.chains,
      input: args,
    });
  }

  private async reportTempoBroadcastAcceptedDomain(
    args: ReportTempoBroadcastAcceptedArgs,
  ): Promise<void> {
    await this.requireRouterReady();
    await this.router.reportTempoBroadcastAccepted({
      nearAccountId: args.nearAccountId,
      signedResult: args.signedResult,
      ...(args.txHash ? { txHash: args.txHash } : {}),
      options: {
        onEvent: args.options?.onEvent,
      },
    });
  }

  private async reportTempoBroadcastRejectedDomain(
    args: ReportTempoBroadcastRejectedArgs,
  ): Promise<void> {
    await this.requireRouterReady();
    await this.router.reportTempoBroadcastRejected({
      nearAccountId: args.nearAccountId,
      signedResult: args.signedResult,
      ...(args.error == null
        ? {}
        : {
            error: (() => {
              if (typeof args.error === 'string') return { message: args.error };
              if (args.error instanceof Error) {
                const code = String((args.error as { code?: unknown }).code || '').trim();
                return {
                  ...(code ? { code } : {}),
                  message: String(args.error.message || ''),
                };
              }
              if (typeof args.error === 'object') {
                const value = args.error as {
                  code?: unknown;
                  message?: unknown;
                  details?: unknown;
                };
                const code = String(value.code || '').trim();
                const message = String(value.message || '').trim();
                return {
                  ...(code ? { code } : {}),
                  ...(message ? { message } : {}),
                  ...(value.details !== undefined ? { details: value.details } : {}),
                };
              }
              return { message: String(args.error) };
            })(),
          }),
      options: {
        onEvent: args.options?.onEvent,
      },
    });
  }

  private async reportTempoFinalizedDomain(args: ReportTempoFinalizedArgs): Promise<void> {
    await this.requireRouterReady();
    await this.router.reportTempoFinalized({
      nearAccountId: args.nearAccountId,
      signedResult: args.signedResult,
      ...(args.txHash ? { txHash: args.txHash } : {}),
      ...(args.receiptStatus ? { receiptStatus: args.receiptStatus } : {}),
      options: {
        onEvent: args.options?.onEvent,
      },
    });
  }

  private async reportTempoDroppedOrReplacedDomain(
    args: ReportTempoDroppedOrReplacedArgs,
  ): Promise<void> {
    await this.requireRouterReady();
    await this.router.reportTempoDroppedOrReplaced({
      nearAccountId: args.nearAccountId,
      signedResult: args.signedResult,
      reason: args.reason,
      ...(args.txHash ? { txHash: args.txHash } : {}),
      options: {
        onEvent: args.options?.onEvent,
      },
    });
  }

  private async reconcileTempoNonceLaneDomain(
    args: ReconcileTempoNonceLaneArgs,
  ): Promise<TempoNonceLaneStatus> {
    await this.requireRouterReady();
    return await this.router.reconcileTempoNonceLane({
      nearAccountId: args.nearAccountId,
      signedResult: args.signedResult,
      options: {
        onEvent: args.options?.onEvent,
      },
    });
  }

  private async bootstrapEcdsaSessionDomain(
    args: BootstrapThresholdEcdsaSessionArgs,
  ): Promise<ThresholdEcdsaSessionBootstrapResult> {
    await this.requireRouterReady();
    return await this.router.bootstrapEcdsaSession({
      nearAccountId: args.nearAccountId,
      options: args.options,
    });
  }

  /**
   * Internal registration with confirmation config override, for parity with
   * the host-side SeamsPasskey. Routes to the wallet iframe router when ready.
   */
  async registerPasskeyInternal(
    nearAccountId: string,
    options: RegistrationHooksOptions = {},
    confirmationConfigOverride?: ConfirmationConfig,
  ): Promise<RegistrationResult> {
    try {
      await this.requireRouterReady();
      const confirmationConfig = confirmationConfigOverride ?? options?.confirmationConfig;
      const res = await this.router.registerPasskey({
        nearAccountId,
        confirmationConfig,
        options: {
          onEvent: options?.onEvent,
          ...(options?.signerOptions ? { signerOptions: options.signerOptions } : {}),
          ...(options?.confirmerText ? { confirmerText: options.confirmerText } : {}),
        },
      });
      await options?.afterCall?.(true, res);
      return res;
    } catch (err: unknown) {
      const e = toError(err);
      await options?.onError?.(e);
      await options?.afterCall?.(false, undefined, e);
      throw e;
    }
  }

  // Parity with PasskeyManager API
  setConfirmBehavior(behavior: 'requireClick' | 'skipClick'): void {
    void this.router
      .setConfirmBehavior(behavior)
      .then(() => this.refreshConfirmationConfig())
      .catch(() => {});
  }
  setTheme(next: ThemeName): void {
    const nextTheme = coerceThemeName(next);
    if (!nextTheme) return;
    if (this.theme === nextTheme) return;
    this.theme = nextTheme;
    void this.router
      .setTheme(nextTheme)
      .then(() => this.refreshConfirmationConfig())
      .catch(() => {});
  }
  setConfirmationConfig(config: ConfirmationConfig): void {
    void this.router
      .setConfirmationConfig(config)
      .then(() => this.refreshConfirmationConfig())
      .catch(() => {});
  }
  getConfirmationConfig(): ConfirmationConfig {
    // Synchronous API parity with PasskeyManager
    return this.lastConfirmationConfig;
  }
  async prefetchBlockheight(): Promise<void> {
    await this.router.prefetchBlockheight();
  }
  async getRecentUnlocks(): Promise<GetRecentUnlocksResult> {
    // In wallet-iframe mode, do not fall back to app-origin persistence.
    return await this.requireRouterReady()
      .then(() => this.router.getRecentUnlocks())
      .catch(() => ({ accountIds: [], lastUsedAccount: null }));
  }

  async hasPasskeyCredential(nearAccountId: string): Promise<boolean> {
    return this.router.hasPasskeyCredential(nearAccountId);
  }
  async viewAccessKeyList(accountId: string): Promise<AccessKeyList> {
    return this.router.viewAccessKeyList(accountId);
  }
  async deleteDeviceKey(
    accountId: string,
    publicKeyToDelete: string,
    options: ActionHooksOptions,
  ): Promise<ActionResult> {
    try {
      const res = await this.router.deleteDeviceKey({
        accountId,
        publicKeyToDelete,
        options: {
          onEvent: options?.onEvent,
        },
      });
      await options?.afterCall?.(true, res);
      return res;
    } catch (err: unknown) {
      const e = toError(err);
      await options?.onError?.(e);
      await options?.afterCall?.(false, undefined, e);
      throw e;
    }
  }
  private async executeActionDomain(args: {
    nearAccountId: string;
    receiverId: string;
    actionArgs: ActionArgs | ActionArgs[];
    options: ActionHooksOptions;
  }): Promise<ActionResult> {
    try {
      const res = await this.router.executeAction({
        nearAccountId: args.nearAccountId,
        receiverId: args.receiverId,
        actionArgs: args.actionArgs,
        options: args.options,
      });
      await args.options?.afterCall?.(true, res);
      return res;
    } catch (err: unknown) {
      const e = toError(err);
      await args.options?.onError?.(e);
      await args.options?.afterCall?.(false, undefined, e);
      throw e;
    }
  }
  private async sendTransactionDomain(args: {
    signedTransaction: SignedTransaction;
    options?: SendTransactionHooksOptions;
  }): Promise<ActionResult> {
    // Route via iframe router with PROGRESS bridging
    const options = args.options;
    try {
      const res = await this.router.sendTransaction({
        signedTransaction: args.signedTransaction,
        options: {
          onEvent: options?.onEvent,
          waitUntil: options?.waitUntil,
        },
      });
      await options?.afterCall?.(true, res);
      return res;
    } catch (err: unknown) {
      const e = toError(err);
      await options?.onError?.(e);
      await options?.afterCall?.(false, undefined, e);
      throw e;
    }
  }

  private async exportKeypairWithUIDomain(
    nearAccountId: string,
    options: {
      chain: 'near' | 'evm' | 'tempo';
      variant?: 'drawer' | 'modal';
      theme?: 'dark' | 'light';
      onEvent?: KeyExportHooksOptions['onEvent'];
    },
  ): Promise<void> {
    await this.requireRouterReady();
    return this.router.exportKeypairWithUI(nearAccountId, options);
  }

  private async exportThresholdEd25519SeedFromHssReportDomain(args: {
    nearAccountId: string;
    preparedSession: ThresholdEd25519HssPreparedSessionEnvelope;
    finalizedReport: ThresholdEd25519HssFinalizedReportEnvelope;
    expectedPublicKey: string;
    options: {
      variant?: 'drawer' | 'modal';
      theme?: 'dark' | 'light';
      onEvent?: KeyExportHooksOptions['onEvent'];
    };
  }): Promise<void> {
    await this.requireRouterReady();
    return this.router.exportThresholdEd25519SeedFromHssReport(args);
  }

  // Utility: sign and send in one call via wallet iframe (single before/after)
  private async signAndSendTransactionsDomain(args: {
    nearAccountId: string;
    transactions: TransactionInput[];
    options: SignAndSendTransactionHooksOptions;
  }): Promise<ActionResult[]> {
    const options = args.options;
    try {
      const res = await this.router.signAndSendTransactions({
        nearAccountId: args.nearAccountId,
        transactions: args.transactions,
        // Default to sequential execution when executionWait is not provided
        options,
      });
      await options?.afterCall?.(true, res);
      return res;
    } catch (err: unknown) {
      const e = toError(err);
      await options?.onError?.(e);
      await options?.afterCall?.(false, undefined, e);
      throw e;
    }
  }

  private applyRemoteConfirmationConfig(cfg: ConfirmationConfig): void {
    this.lastConfirmationConfig = {
      ...DEFAULT_CONFIRMATION_CONFIG,
      ...(cfg || {}),
    } as ConfirmationConfig;
  }

  private async refreshConfirmationConfig(): Promise<void> {
    await this.router
      .getConfirmationConfig()
      .then((cfg) => this.applyRemoteConfirmationConfig(cfg))
      .catch(() => {});
  }
}
