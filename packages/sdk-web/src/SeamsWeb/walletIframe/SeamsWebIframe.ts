/**
 * SeamsWebIframe - Entry Point Layer
 *
 * This is the main API that developers interact with when using the WalletIframe system.
 * It provides the same interface as the regular SeamsWeb for core wallet actions, and routes calls to
 * a secure iframe for enhanced security and WebAuthn compatibility.
 *
 * Key Responsibilities:
 * - Acts as a transparent proxy to the real SeamsWeb running in the iframe
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
import { signingSessionSealInputFromReadonly } from './shared/signingSessionSealConfig';
import { walletIframeUnlockRequestFromLoginHooks } from './shared/unlockOptions';
import type { RouterAbEcdsaHssLoginPresignaturePrefillResult } from '@/core/signingEngine/session/warmCapabilities/ecdsaLoginPrefill';
import type { ThresholdEcdsaSessionBootstrapResult } from '@/core/signingEngine/threshold/ecdsa/activation';
import {
  toWalletId,
  type NearAccountRef,
  type ThresholdEcdsaChainTarget,
  type WalletSessionRef,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type {
  ThresholdEd25519HssFinalizedReportEnvelope,
  ThresholdEd25519HssPreparedSessionEnvelope,
} from '@/core/signingEngine/threshold/crypto/hssClientSignerWasm';
import type { SignedTransaction, AccessKeyList } from '@/core/rpcClients/near/NearClient';
import type { PreferencesChangedPayload } from './shared/messages';
import type {
  ActionResult,
  DelegateRouterApiResult,
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
} from '@/core/types/seams';
import type {
  ActionHooksOptions,
  DelegateActionHooksOptions,
  DelegateRelayHooksOptions,
  KeyExportHooksOptions,
  LoginHooksOptions,
  SendTransactionHooksOptions,
  SignAndSendDelegateActionHooksOptions,
  SignAndSendTransactionHooksOptions,
  SignNEP413HooksOptions,
  SignTransactionHooksOptions,
} from '@/core/types/sdkSentEvents';

import type { ActionArgs, TransactionInput, TxExecutionStatus } from '@/core/types';
import {
  type ConfirmationConfig,
  type WasmSignedDelegate,
  DEFAULT_CONFIRMATION_CONFIG,
} from '@/core/types/signer-worker';
import type { SignNEP413MessageParams, SignNEP413MessageResult } from '@/SeamsWeb/operations/near';
import { toError } from '@shared/utils/errors';
import { coerceThemeName } from '@shared/utils/theme';
import { buildNoCurrentWalletAuthMethod } from '@shared/utils/walletCapabilityBindings';
import type { WalletUIRegistry } from './host/lit-ui/iframe-lit-element-registry';
import type { DelegateActionInput, SignedDelegate } from '@/core/types/delegate';
import { buildConfigsFromEnv } from '@/core/config/defaultConfigs';
import { cloneAuthenticatorOptions } from '@/core/types/authenticatorOptions';
import { configureIndexedDB } from '@/core/indexedDB';
import type { EvmSignedResult } from '@/core/signingEngine/chains/evm/evmAdapter';
import type { TempoSignedResult } from '@/core/signingEngine/chains/tempo/tempoAdapter';
import type {
  BootstrapThresholdEcdsaSessionArgs,
  AuthCapability,
  DevicesCapability,
  ExecuteEvmFamilyTransactionArgs,
  ExecuteEvmFamilyTransactionResult,
  RecoveryCapability,
  EvmSignerCapability,
  KeyExportCapability,
  NearSignerCapability,
  PreferencesCapability,
  RegistrationCapability,
  ReconcileTempoNonceLaneArgs,
  ReportTempoBroadcastAcceptedArgs,
  ReportTempoBroadcastRejectedArgs,
  ReportTempoDroppedOrReplacedArgs,
  ReportTempoFinalizedArgs,
  SignTempoArgs,
  TempoNonceLaneStatus,
  TempoSignerCapability,
} from '@/SeamsWeb';
import { executeEvmFamilyTransactionLifecycle } from '@/SeamsWeb/operations/tempo/executeEvmFamilyTransaction';
import {
  implicitNearAccountProvisioning,
  type RegisterWalletInput,
} from '@shared/utils/registrationIntent';
import { parseWebAuthnRpId, type WebAuthnRpId } from '@shared/utils/domainIds';
import { buildNearWalletRegistrationSignerSetSelection } from '@/SeamsWeb/operations/registration/registrationSignerSet';

export class SeamsWebIframe {
  readonly configs: SeamsConfigsReadonly;
  theme: ThemeName;
  private router: WalletIframeRouter;
  private lastConfirmationConfig: ConfirmationConfig = DEFAULT_CONFIRMATION_CONFIG;
  private prefsUnsubscribe: (() => void) | null = null;
  readonly near: NearSignerCapability;
  readonly tempo: TempoSignerCapability;
  readonly evm: EvmSignerCapability;
  readonly auth: AuthCapability;
  readonly registration: RegistrationCapability;
  readonly recovery: RecoveryCapability;
  readonly devices: DevicesCapability;
  readonly keys: KeyExportCapability;
  readonly preferences: PreferencesCapability;
  private currentWalletId: ReturnType<PreferencesCapability['getCurrentWalletId']> = null;
  private readonly currentWalletListeners = new Set<
    Parameters<PreferencesCapability['onCurrentWalletChange']>[0]
  >();
  private readonly confirmationConfigListeners = new Set<
    Parameters<PreferencesCapability['onConfirmationConfigChange']>[0]
  >();

  // Expose a userPreferences shim so API matches SeamsWeb
  get userPreferences() {
    return {
      setConfirmBehavior: (b: 'requireClick' | 'skipClick') => {
        this.preferences.setConfirmBehavior(b);
      },
      setConfirmationConfig: (c: ConfirmationConfig) => {
        this.preferences.setConfirmationConfig(c);
      },
      getConfirmationConfig: () => this.preferences.getConfirmationConfig(),
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
        '[SeamsWebIframe] wallet.iframe.origin is required to enable the wallet iframe. Configure it to a dedicated origin.',
      );
    }

    let parsedWalletOrigin: URL;
    try {
      parsedWalletOrigin = new URL(walletOrigin);
    } catch (err) {
      throw new Error(
        `[SeamsWebIframe] Invalid wallet.iframe.origin (${walletOrigin}). Provide an absolute URL.`,
      );
    }

    if (typeof window !== 'undefined') {
      const parentOrigin = window.location.origin;
      if (parsedWalletOrigin.origin === parentOrigin) {
        console.warn(
          '[SeamsWebIframe] wallet.iframe.origin matches the host origin. Isolation is reduced; consider serving the wallet from a dedicated origin.',
        );
      }
    }

    this.theme = 'dark';
    this.lastConfirmationConfig = { ...DEFAULT_CONFIRMATION_CONFIG } as ConfirmationConfig;
    const signingSessionPersistenceMode = this.configs.signing.sessionPersistenceMode;
    const signingSessionSeal =
      signingSessionPersistenceMode === 'sealed_refresh_v1'
        ? signingSessionSealInputFromReadonly(this.configs.signing.sessionSeal)
        : undefined;
    const signingSessionDefaults = this.configs.signing.sessionDefaults;
    const routerAb = this.configs.signing.routerAb;
    const routerAbEcdsaHssPresignaturePool = this.configs.signing.routerAbEcdsaHss.presignaturePool;
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
      routerAb,
      routerAbEcdsaHssPresignaturePool,
      provisioningDefaults,
      // relayer: configs.network.relayer,
      rpIdOverride: this.configs.wallet.iframe?.rpIdOverride,
      authenticatorOptions: cloneAuthenticatorOptions(this.configs.webauthn.authenticatorOptions),
    });
    this.auth = {
      unlock: async (walletId, options) => await this.unlockDomain(walletId, options),
      lock: async () => await this.lockDomain(),
      getWalletSession: async (walletId) => await this.getWalletSessionDomain(walletId),
      getRecentUnlocks: async () => await this.getRecentUnlocksDomain(),
      hasPasskeyCredential: async (walletId) => await this.hasPasskeyCredentialDomain(walletId),
      prefillRouterAbEcdsaHssPresignaturePool: async (args) =>
        await this.prefillRouterAbEcdsaHssPresignaturePoolDomain(args),
      requestEmailOtpChallenge: async (args) => {
        const result = await this.router.requestEmailOtpChallenge(args);
        return result;
      },
      requestEmailOtpSigningSessionChallenge: async (args) =>
        await this.router.requestEmailOtpSigningSessionChallenge(args),
      refreshEmailOtpSigningSession: async (args) =>
        await this.router.refreshEmailOtpSigningSession(args),
      exchangeGoogleEmailOtpSession: async (args) =>
        await this.router.exchangeGoogleEmailOtpSession(args),
      loginWithEmailOtpEcdsaCapability: async (args) =>
        await this.router.loginWithEmailOtpEcdsaCapability(args),
      beginGoogleEmailOtpWalletAuth: async (args) =>
        await this.router.beginGoogleEmailOtpWalletAuth(args),
    };
    this.registration = {
      addWalletSigner: async (args) => await this.addWalletSignerDomain(args),
      registerWallet: async (args) => await this.registerWalletDomain(args),
      registerWithEmailOtp: async (args) => await this.registerWalletDomain(args),
      registerPasskey: async (options) => await this.registerPasskeyDomain(options),
      createPasskeyRegistrationActivationSurface: (args) =>
        this.router.createPasskeyRegistrationActivationSurface(args),
      requestEmailOtpEnrollmentChallenge: async (args) =>
        await this.router.requestEmailOtpEnrollmentChallenge(args),
      enrollEmailOtp: async (args) => await this.router.enrollEmailOtp(args),
      enrollAndLoginWithEmailOtpEcdsaCapability: async (args) =>
        await this.router.enrollAndLoginWithEmailOtpEcdsaCapability(args),
    };
    this.preferences = {
      setCurrentWallet: (walletId) => {
        this.currentWalletId = walletId;
        for (const listener of this.currentWalletListeners) listener(walletId);
      },
      getCurrentWalletId: () => this.currentWalletId,
      onConfirmationConfigChange: (callback) => {
        this.confirmationConfigListeners.add(callback);
        return () => {
          this.confirmationConfigListeners.delete(callback);
        };
      },
      onCurrentWalletChange: (callback) => {
        this.currentWalletListeners.add(callback);
        return () => {
          this.currentWalletListeners.delete(callback);
        };
      },
      setConfirmBehavior: (behavior) => this.setConfirmBehaviorDomain(behavior),
      setConfirmationConfig: (config) => this.setConfirmationConfigDomain(config),
      getConfirmationConfig: () => this.getConfirmationConfigDomain(),
    };

    this.near = {
      registerNearWallet: async (args) => {
        const rpId = this.resolveRegistrationRpId('near.registerNearWallet');
        const accountProvisioning =
          args.accountProvisioning?.kind === 'sponsored_named_account'
            ? args.accountProvisioning
            : args.accountProvisioning || implicitNearAccountProvisioning();
        let wallet: RegisterWalletInput;
        switch (accountProvisioning.kind) {
          case 'implicit_account':
            wallet = args.wallet || { kind: 'server_allocated' };
            break;
          case 'sponsored_named_account':
            if (!args.wallet) {
              throw new Error(
                '[SeamsWebIframe][near] sponsored NEAR registration requires a provided walletId',
              );
            }
            wallet = args.wallet;
            break;
          default:
            throw new Error('[SeamsWebIframe][near] unsupported NEAR account provisioning branch');
        }
        return await this.registration.registerWallet({
          wallet,
          authMethod: args.authMethod || { kind: 'passkey' as const, rpId },
          signerSelection: buildNearWalletRegistrationSignerSetSelection({
            configs: this.configs,
            accountProvisioning,
            options: args.options || {},
          }),
          options: args.options,
        });
      },
      executeAction: async (args) => await this.executeActionDomain(args),
      signAndSendTransaction: async (args) => {
        return await this.signAndSendTransactionDomain({
          walletSession: args.walletSession,
          nearAccount: args.nearAccount,
          receiverId: args.receiverId,
          actions: args.actions,
          options: args.options,
        });
      },
      signTransactionWithActions: async (args) => await this.signTransactionWithActionsDomain(args),
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
      bootstrapEcdsaSession: async (args) => await this.bootstrapEcdsaSessionDomain(args),
    };
    this.evm = {
      registerEvmWallet: async (args) => {
        if (!args.chainTargets.length) {
          throw new Error('[SeamsWeb][evm] registerEvmWallet requires at least one chain target');
        }
        if (!args.participantIds.length) {
          throw new Error('[SeamsWeb][evm] registerEvmWallet requires participant ids');
        }
        const rpId = this.resolveRegistrationRpId('evm.registerEvmWallet');
        return await this.registration.registerWallet({
          wallet: { kind: 'server_allocated' },
          authMethod: args.authMethod || { kind: 'passkey' as const, rpId },
          signerSelection: {
            kind: 'signer_set',
            signers: [
              {
                kind: 'evm_family_ecdsa',
                chainTargets: [...args.chainTargets],
                participantIds: [...args.participantIds],
              },
            ],
          },
          options: args.options,
        });
      },
      bootstrapEcdsaSession: async (args) => await this.bootstrapEcdsaSessionDomain(args),
    };
    this.recovery = {
      getRecoveryEmails: async (walletId) => {
        await this.requireRouterReady();
        return await this.router.getRecoveryEmails(walletId);
      },
      setRecoveryEmails: async (args) => {
        await this.requireRouterReady();
        return await this.router.setRecoveryEmails({
          walletId: args.walletId,
          recoveryEmails: args.recoveryEmails,
          options: args.options,
        });
      },
      syncAccount: async (args) => {
        await this.requireRouterReady();
        return await this.router.syncAccount({
          ...(args?.walletId ? { walletId: args.walletId } : {}),
          onEvent: args?.options?.onEvent,
        });
      },
      startEmailRecovery: async (args) => {
        await this.requireRouterReady();
        return await this.router.startEmailRecovery({
          walletId: args.walletId,
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
          walletId: args.walletId,
          ...(args.nearPublicKey ? { nearPublicKey: args.nearPublicKey } : {}),
          onEvent: args.options?.onEvent,
        });
      },
      cancelEmailRecovery: async (args) => {
        await this.requireRouterReady();
        await this.router.stopEmailRecovery(args);
      },
      getEmailOtpRecoveryCodeStatus: async (args) =>
        await this.router.getEmailOtpRecoveryCodeStatus({
          walletId: args.walletId,
          relayUrl: String(args.relayUrl || this.configs.network.relayer.url || '').trim(),
          ...(args.appSessionJwt ? { appSessionJwt: args.appSessionJwt } : {}),
        }),
      rotateEmailOtpRecoveryCodes: async (args) =>
        await this.router.rotateEmailOtpRecoveryCodes({
          walletId: args.walletId,
          relayUrl: String(args.relayUrl || this.configs.network.relayer.url || '').trim(),
          ...(args.appSessionJwt ? { appSessionJwt: args.appSessionJwt } : {}),
        }),
    } satisfies RecoveryCapability;
    this.devices = {
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
      viewAccessKeyList: async (args) => await this.viewAccessKeyListDomain(args),
      deleteDeviceKey: async (args) => await this.deleteDeviceKeyDomain(args),
    };
    this.keys = {
      exportKeypairWithUI: async (input) => await this.exportKeypairWithUIDomain(input),
      exportThresholdEd25519SeedFromHssReport: async (args) =>
        await this.exportThresholdEd25519SeedFromHssReportDomain(args),
    };
  }

  private resolveRegistrationRpId(operation: string): WebAuthnRpId {
    const configured = String(this.configs.wallet.iframe?.rpIdOverride || '').trim();
    if (configured) {
      const parsed = parseWebAuthnRpId(configured);
      if (parsed.ok) return parsed.value;
      throw new Error(parsed.error.message);
    }
    try {
      const hostname = String(globalThis.location?.hostname || '').trim();
      if (hostname) {
        const parsed = parseWebAuthnRpId(hostname);
        if (parsed.ok) return parsed.value;
        throw new Error(parsed.error.message);
      }
    } catch {}
    throw new Error(`[SeamsWeb][iframe] ${operation} requires rpId`);
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
      throw new Error('[SeamsWebIframe] Wallet iframe is configured but unavailable.');
    }
    return this.router;
  }

  async showEmailOtpRecoveryCodesForAccountMenu(args: { walletId: string }): Promise<{
    status: Awaited<ReturnType<RecoveryCapability['getEmailOtpRecoveryCodeStatus']>>;
    displayedStoredCodes: boolean;
  }> {
    await this.requireRouterReady();
    return await this.router.showEmailOtpRecoveryCodes({
      walletId: args.walletId,
      relayUrl: String(this.configs.network.relayer.url || '').trim(),
    });
  }

  isReady(): boolean {
    return this.router.isReady();
  }

  onReady(cb: () => void): () => void {
    return this.router.onReady(cb);
  }

  onLoginStatusChanged(
    cb: (status: { isLoggedIn: boolean; walletId: string | null }) => void,
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

  private async registerPasskeyDomain(
    options: Parameters<RegistrationCapability['registerPasskey']>[0] = {},
  ): Promise<RegistrationResult> {
    if (typeof options === 'string') {
      throw new Error(
        '[SeamsWebIframe] registration.registerPasskey no longer accepts a NEAR account id; call registration.registerPasskey(options) for implicit NEAR registration or registerWallet(...) with explicit sponsored accountProvisioning.',
      );
    }
    const { wallet, ...registrationOptions } = options || {};
    return await this.near.registerNearWallet({
      ...(wallet ? { wallet } : {}),
      options: registrationOptions,
    });
  }

  private async registerWalletDomain(
    args: Parameters<RegistrationCapability['registerWallet']>[0],
  ): Promise<RegistrationResult> {
    try {
      await this.requireRouterReady();
      const res = await this.router.registerWallet(args);
      await args.options?.afterCall?.(true, res);
      return res;
    } catch (err: unknown) {
      const e = toError(err);
      await args.options?.onError?.(e);
      await args.options?.afterCall?.(false, undefined, e);
      throw e;
    }
  }

  private async addWalletSignerDomain(
    args: Parameters<RegistrationCapability['addWalletSigner']>[0],
  ): Promise<RegistrationResult> {
    try {
      await this.requireRouterReady();
      const res = await this.router.addWalletSigner(args);
      await args.options?.afterCall?.(true, res);
      return res;
    } catch (err: unknown) {
      const e = toError(err);
      await args.options?.onError?.(e);
      await args.options?.afterCall?.(false, undefined, e);
      throw e;
    }
  }

  private async unlockDomain(
    walletId: string,
    options?: LoginHooksOptions,
  ): Promise<LoginAndCreateSessionResult> {
    try {
      // Route login request to iframe - similar flow to registerPasskey
      // The iframe will handle WebAuthn authentication and session creation
      const res = await this.router.unlock(
        walletIframeUnlockRequestFromLoginHooks({
          walletId,
          options,
        }),
      );
      if (!res.success) {
        const unlockError = new Error(res.error || 'Login failed');
        await options?.onError?.(unlockError);
        await options?.afterCall?.(false, undefined, unlockError);
        return res;
      }
      await options?.afterCall?.(true, res);
      return res;
    } catch (err: unknown) {
      const e = toError(err);
      await options?.onError?.(e);
      await options?.afterCall?.(false, undefined, e);
      throw e;
    }
  }

  private async lockDomain(): Promise<void> {
    await this.router.lock();
  }

  private async getWalletSessionDomain(walletId?: string): Promise<WalletSession> {
    if (!this.router.isReady()) {
      const login: LoginState = {
        isLoggedIn: false,
        walletId: walletId ? toWalletId(walletId) : null,
        nearAccountId: null,
        publicKey: null,
        userData: null,
        currentAuthMethod: buildNoCurrentWalletAuthMethod(),
        authMethods: [],
      };
      return {
        login,
        signingSession: null,
        currentAuthMethod: buildNoCurrentWalletAuthMethod(),
        authMethods: [],
      };
    }
    return await this.router.getWalletSession(walletId);
  }

  private resolveNearSigningWalletId(args: { walletSession: WalletSessionRef }): string {
    return String(args.walletSession.walletId);
  }

  private async prefillRouterAbEcdsaHssPresignaturePoolDomain(args: {
    walletSession: WalletSessionRef;
    chainTarget: ThresholdEcdsaChainTarget;
    waitForPoolReady?: boolean;
    poolReadyTimeoutMs?: number;
    poolReadyPollIntervalMs?: number;
    minRemainingUsesBeforePrefill?: number;
  }): Promise<RouterAbEcdsaHssLoginPresignaturePrefillResult> {
    await this.requireRouterReady();
    return await this.router.prefillRouterAbEcdsaHssPresignaturePool({
      walletSession: args.walletSession,
      options: {
        chainTarget: args.chainTarget,
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

  private async signTransactionWithActionsDomain(args: {
    walletSession: WalletSessionRef;
    nearAccount: NearAccountRef;
    transaction: TransactionInput;
    options: SignTransactionHooksOptions;
  }): Promise<SignTransactionResult> {
    try {
      const walletId = this.resolveNearSigningWalletId(args);
      // Route transaction signing to iframe
      // This will:
      // - Send PM_SIGN_TX_WITH_ACTIONS message to iframe
      // - Show overlay during user confirmation and WebAuthn phases
      // - Handle transaction signing in secure iframe context
      // - Bridge progress events back to parent
      const res = await this.router.signTransactionWithActions({
        walletId,
        nearAccountId: args.nearAccount.accountId,
        transaction: args.transaction,
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
    walletSession: WalletSessionRef;
    nearAccount: NearAccountRef;
    params: SignNEP413MessageParams;
    options: SignNEP413HooksOptions;
  }): Promise<SignNEP413MessageResult> {
    try {
      const walletId = this.resolveNearSigningWalletId(args);
      const res = await this.router.signNep413Message({
        walletId,
        nearAccountId: args.nearAccount.accountId,
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
    walletSession: WalletSessionRef;
    nearAccount: NearAccountRef;
    delegate: DelegateActionInput;
    options: DelegateActionHooksOptions;
  }): Promise<SignDelegateActionResult> {
    const options = args.options;
    try {
      await this.requireRouterReady();
      const walletId = this.resolveNearSigningWalletId(args);
      const res = (await this.router.signDelegateAction({
        walletId,
        nearAccountId: args.nearAccount.accountId,
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
  }): Promise<DelegateRouterApiResult> {
    const base = args.relayerUrl.replace(/\/+$/, '');
    const route = (
      this.configs.network.relayer?.routes?.delegateAction || '/signed-delegate'
    ).replace(/^\/?/, '/');
    const endpoint = `${base}${route}`;
    const { sendDelegateActionViaRelayer } = await import('@/SeamsWeb/operations/near');
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
    walletSession: WalletSessionRef;
    nearAccount: NearAccountRef;
    delegate: DelegateActionInput;
    relayerUrl: string;
    signal?: AbortSignal;
    options: SignAndSendDelegateActionHooksOptions;
  }): Promise<SignAndSendDelegateActionResult> {
    const { nearAccount, delegate, relayerUrl, signal, options } = args;

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
        walletSession: args.walletSession,
        nearAccount,
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

    let relayResult: DelegateRouterApiResult;
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
      walletSession: args.walletSession,
      request: args.request,
      chainTarget: args.chainTarget,
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
      lifecycle: {
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
      walletSession: args.walletSession,
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
      walletSession: args.walletSession,
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
      walletSession: args.walletSession,
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
      walletSession: args.walletSession,
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
      walletSession: args.walletSession,
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
    return await this.router.bootstrapEcdsaSession(args);
  }

  private setConfirmBehaviorDomain(behavior: 'requireClick' | 'skipClick'): void {
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
  private setConfirmationConfigDomain(config: ConfirmationConfig): void {
    this.applyRemoteConfirmationConfig(config);
    void this.router
      .setConfirmationConfig(config)
      .then(() => this.refreshConfirmationConfig())
      .catch(() => {});
  }
  private getConfirmationConfigDomain(): ConfirmationConfig {
    return this.lastConfirmationConfig;
  }
  async prefetchBlockheight(): Promise<void> {
    await this.router.prefetchBlockheight();
  }
  private async getRecentUnlocksDomain(): Promise<GetRecentUnlocksResult> {
    // In wallet-iframe mode, do not fall back to app-origin persistence.
    return await this.requireRouterReady()
      .then(() => this.router.getRecentUnlocks())
      .catch(() => ({ walletIds: [], accountIds: [], lastUsedAccount: null }));
  }

  private async hasPasskeyCredentialDomain(walletId: string): Promise<boolean> {
    return this.router.hasPasskeyCredential(walletId);
  }
  private async viewAccessKeyListDomain(args: {
    walletSession: WalletSessionRef;
    nearAccount: NearAccountRef;
  }): Promise<AccessKeyList> {
    return this.router.viewAccessKeyList({
      walletId: args.walletSession.walletId,
      nearAccountId: String(args.nearAccount.accountId),
    });
  }
  private async deleteDeviceKeyDomain(
    args: Parameters<DevicesCapability['deleteDeviceKey']>[0],
  ): Promise<ActionResult> {
    try {
      const res = await this.router.deleteDeviceKey({
        walletId: String(args.walletSession.walletId),
        nearAccountId: String(args.nearAccount.accountId),
        publicKeyToDelete: args.publicKeyToDelete,
        options: {
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
  private async executeActionDomain(args: {
    walletSession: WalletSessionRef;
    nearAccount: NearAccountRef;
    receiverId: string;
    actionArgs: ActionArgs | ActionArgs[];
    options: ActionHooksOptions;
  }): Promise<ActionResult> {
    try {
      const walletId = this.resolveNearSigningWalletId(args);
      const res = await this.router.executeAction({
        walletId,
        nearAccountId: args.nearAccount.accountId,
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
    walletSession: WalletSessionRef;
    nearAccount: NearAccountRef;
    signedTransaction: SignedTransaction;
    options?: SendTransactionHooksOptions;
  }): Promise<ActionResult> {
    // Route via iframe router with PROGRESS bridging
    const options = args.options;
    try {
      const walletId = this.resolveNearSigningWalletId(args);
      const res = await this.router.sendTransaction({
        walletId,
        nearAccountId: args.nearAccount.accountId,
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
    input: Parameters<KeyExportCapability['exportKeypairWithUI']>[0],
  ): Promise<void> {
    await this.requireRouterReady();
    return this.router.exportKeypairWithUI(input);
  }

  private async exportThresholdEd25519SeedFromHssReportDomain(args: {
    walletSession: WalletSessionRef;
    nearAccount: NearAccountRef;
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
    return this.router.exportThresholdEd25519SeedFromHssReport({
      walletId: args.walletSession.walletId,
      nearAccountId: String(args.nearAccount.accountId),
      preparedSession: args.preparedSession,
      finalizedReport: args.finalizedReport,
      expectedPublicKey: args.expectedPublicKey,
      options: args.options,
    });
  }

  private async signAndSendTransactionDomain(args: {
    walletSession: WalletSessionRef;
    nearAccount: NearAccountRef;
    receiverId: string;
    actions: ActionArgs[];
    options: SignAndSendTransactionHooksOptions;
  }): Promise<ActionResult> {
    const options = args.options;
    try {
      const walletId = this.resolveNearSigningWalletId(args);
      const res = await this.router.signAndSendTransaction({
        walletId,
        nearAccountId: args.nearAccount.accountId,
        transaction: {
          receiverId: args.receiverId,
          actions: args.actions,
        },
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
    for (const listener of this.confirmationConfigListeners) {
      listener(this.lastConfirmationConfig);
    }
  }

  private async refreshConfirmationConfig(): Promise<void> {
    await this.router
      .getConfirmationConfig()
      .then((cfg) => this.applyRemoteConfirmationConfig(cfg))
      .catch(() => {});
  }
}
