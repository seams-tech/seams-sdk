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
  SeamsConfigsReadonly,
  SeamsConfigsInput,
} from '../types/seams';
import type {
  ActionHooksOptions,
  CreateRegistrationFlowEventInput,
  CreateUnlockFlowEventInput,
  KeyExportHooksOptions,
  LoginHooksOptions,
  RegistrationHooksOptions,
  RegistrationFlowEvent,
  UnlockFlowEvent,
} from '../types/sdkSentEvents';
import {
  createRegistrationFlowEvent,
  createUnlockFlowEvent,
  RegistrationEventPhase,
  UnlockEventPhase,
} from '../types/sdkSentEvents';
import { ConfirmationConfig, type ConfirmationBehavior } from '../types/signer-worker';
import { cloneAuthenticatorOptions } from '../types/authenticatorOptions';
import { toAccountId, type AccountId } from '../types/accountIds';
import { configureIndexedDB } from '../indexedDB';
import { ActionType } from '../types/actions';
import type { PreferencesChangedPayload } from '../WalletIframe/shared/messages';
import { __isWalletIframeHostMode } from '../WalletIframe/host-mode';
import { isUserCancellationError, toError } from '@shared/utils/errors';
import { coerceThemeName } from '@shared/utils/theme';
import type { WalletEmailOtpLoginOperation } from '@shared/utils/emailOtpDomain';
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
  EmailOtpChallengeResult,
  EmailOtpEcdsaCapabilityArgs,
  EmailOtpEcdsaEnrollmentCapabilityArgs,
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
import type { ThresholdEcdsaLoginPrefillResult } from '../signingEngine/SigningEngine';
import {
  thresholdEcdsaChainTargetFromRequest,
  type ThresholdEcdsaChainTarget,
  type WalletSubjectId,
} from '../signingEngine/session/signingSession/ecdsaChainTarget';
import type { EmailOtpWorkerProgressEvent } from '../signingEngine/workerManager/workerTypes';
import { EmailRecoveryDomain } from './near/emailRecovery';
import {
  exchangeGoogleEmailOtpSession,
  requestEmailOtpChallenge,
  requestEmailOtpEnrollmentChallenge,
} from './emailOtp';
import { DeviceLinkingDomain } from './near/linkDevice';
import { NearSigner } from './near';
import { TempoSigner } from './tempo';
import { EvmSigner } from './evm';

///////////////////////////////////////
// PASSKEY MANAGER
///////////////////////////////////////

function requireConcreteEcdsaChainTarget(
  value: unknown,
  operation: string,
): ThresholdEcdsaChainTarget {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`[SeamsPasskey] ${operation} requires a concrete ECDSA chainTarget`);
  }
  return thresholdEcdsaChainTargetFromRequest(value as Record<string, unknown>);
}

/**
 * Main SeamsPasskey class that provides framework-agnostic passkey operations
 * with flexible event-based callbacks for custom UX implementation
 */
export class SeamsPasskey {
  private readonly signingEngine: SigningEngine;
  private readonly nearClient: NearClient;
  readonly configs: SeamsConfigsReadonly;
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

  constructor(configs: SeamsConfigsInput, nearClient?: NearClient) {
    this.configs = buildConfigsFromEnv(configs);
    // Configure IndexedDB naming before any local persistence is touched.
    // - Wallet iframe host keeps canonical DB names.
    // - App-origin iframe mode routes persistence through the wallet origin.
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
      requestEmailOtpChallenge: async (args) => await this.requestEmailOtpChallenge(args),
      requestEmailOtpEnrollmentChallenge: async (args) =>
        await this.requestEmailOtpEnrollmentChallenge(args),
      requestEmailOtpSigningSessionChallenge: async (args) =>
        await this.requestEmailOtpSigningSessionChallenge(args),
      refreshEmailOtpSigningSession: async (args) => await this.refreshEmailOtpSigningSession(args),
      exchangeGoogleEmailOtpSession: async (args) => await this.exchangeGoogleEmailOtpSession(args),
      enrollEmailOtp: async (args) => await this.enrollEmailOtp(args),
      loginWithEmailOtpEcdsaCapability: async (args) =>
        await this.loginWithEmailOtpEcdsaCapability(args),
      enrollAndLoginWithEmailOtpEcdsaCapability: async (args) =>
        await this.enrollAndLoginWithEmailOtpEcdsaCapability(args),
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
      exportKeypairWithUI: async (input) => await this.exportKeypairWithUIDomain(input),
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
   * - Sets the active account signer slot (IndexedDB last-user pointer)
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
    chainTarget: ThresholdEcdsaChainTarget;
    waitForPoolReady?: boolean;
    poolReadyTimeoutMs?: number;
    poolReadyPollIntervalMs?: number;
    minRemainingUsesBeforePrefill?: number;
  }): Promise<ThresholdEcdsaLoginPrefillResult> {
    return await prefillThresholdEcdsaPresignPoolDomain(this.getAuthSessionDeps(), args);
  }

  private emailOtpRegistrationFlowId(nearAccountId: string, challengeId?: string): string {
    const accountPart = String(nearAccountId || 'unknown-account').trim() || 'unknown-account';
    const challengePart = String(challengeId || 'active').trim() || 'active';
    return `email-otp-registration:${accountPart}:${challengePart}`;
  }

  private emailOtpUnlockFlowId(nearAccountId: string, challengeId?: string): string {
    const accountPart = String(nearAccountId || 'unknown-account').trim() || 'unknown-account';
    const challengePart = String(challengeId || 'active').trim() || 'active';
    return `email-otp-unlock:${accountPart}:${challengePart}`;
  }

  private emitEmailOtpRegistrationEvent(
    onEvent: ((event: RegistrationFlowEvent) => void) | undefined,
    input: CreateRegistrationFlowEventInput,
  ): void {
    try {
      onEvent?.(createRegistrationFlowEvent(input));
    } catch {}
  }

  private emitEmailOtpUnlockEvent(
    onEvent: ((event: UnlockFlowEvent) => void) | undefined,
    input: CreateUnlockFlowEventInput,
  ): void {
    try {
      onEvent?.(createUnlockFlowEvent(input));
    } catch {}
  }

  private emitEmailOtpRegistrationFailure(
    onEvent: ((event: RegistrationFlowEvent) => void) | undefined,
    input: Omit<CreateRegistrationFlowEventInput, 'phase' | 'status' | 'error'> & {
      error: Error;
    },
  ): void {
    this.emitEmailOtpRegistrationEvent(onEvent, {
      ...input,
      phase: RegistrationEventPhase.FAILED,
      status: 'failed',
      error: { message: input.error.message },
    });
  }

  private emitEmailOtpRegistrationWorkerProgress(
    onEvent: ((event: RegistrationFlowEvent) => void) | undefined,
    args: {
      flowId: string;
      accountId: string;
      challengeId?: string;
      chainTarget: ThresholdEcdsaChainTarget;
      progress: EmailOtpWorkerProgressEvent;
    },
  ): RegistrationEventPhase | null {
    const base = {
      flowId: args.flowId,
      accountId: args.accountId,
      authMethod: 'email_otp' as const,
      ...(args.challengeId ? { requestId: args.challengeId } : {}),
    };
    switch (args.progress.code) {
      case 'otp.verify.succeeded':
        this.emitEmailOtpRegistrationEvent(onEvent, {
          ...base,
          phase: RegistrationEventPhase.STEP_04_OTP_VERIFY_SUCCEEDED,
          status: 'succeeded',
          interaction: { kind: 'otp_input', overlay: 'hide' },
        });
        return RegistrationEventPhase.STEP_04_OTP_VERIFY_SUCCEEDED;
      case 'signer.email_otp.enroll.started':
        this.emitEmailOtpRegistrationEvent(onEvent, {
          ...base,
          phase: RegistrationEventPhase.STEP_09_EMAIL_OTP_SIGNER_ENROLL_STARTED,
          status: 'running',
        });
        return RegistrationEventPhase.STEP_09_EMAIL_OTP_SIGNER_ENROLL_STARTED;
      case 'signer.email_otp.enroll.succeeded':
        this.emitEmailOtpRegistrationEvent(onEvent, {
          ...base,
          phase: RegistrationEventPhase.STEP_09_EMAIL_OTP_SIGNER_ENROLL_SUCCEEDED,
          status: 'succeeded',
        });
        return RegistrationEventPhase.STEP_09_EMAIL_OTP_SIGNER_ENROLL_SUCCEEDED;
      case 'signer.ecdsa.bootstrap.started':
        this.emitEmailOtpRegistrationEvent(onEvent, {
          ...base,
          phase: RegistrationEventPhase.STEP_10_ECDSA_SIGNER_PROVISION_STARTED,
          status: 'running',
          data: { chainTarget: args.chainTarget },
        });
        return RegistrationEventPhase.STEP_10_ECDSA_SIGNER_PROVISION_STARTED;
      case 'signer.ecdsa.bootstrap.prepared':
        this.emitEmailOtpRegistrationEvent(onEvent, {
          ...base,
          phase: RegistrationEventPhase.STEP_10_ECDSA_SIGNER_PROVISION_STARTED,
          status: 'running',
          message: 'Coordinating EVM signing session',
          data: { chainTarget: args.chainTarget },
        });
        return RegistrationEventPhase.STEP_10_ECDSA_SIGNER_PROVISION_STARTED;
      case 'signer.ecdsa.bootstrap.responded':
        this.emitEmailOtpRegistrationEvent(onEvent, {
          ...base,
          phase: RegistrationEventPhase.STEP_10_ECDSA_SIGNER_PROVISION_STARTED,
          status: 'running',
          message: 'Finalizing EVM signing session',
          data: { chainTarget: args.chainTarget },
        });
        return RegistrationEventPhase.STEP_10_ECDSA_SIGNER_PROVISION_STARTED;
      case 'signer.ecdsa.bootstrap.succeeded':
        this.emitEmailOtpRegistrationEvent(onEvent, {
          ...base,
          phase: RegistrationEventPhase.STEP_10_ECDSA_SIGNER_PROVISION_SUCCEEDED,
          status: 'succeeded',
          data: { chainTarget: args.chainTarget },
        });
        return RegistrationEventPhase.STEP_10_ECDSA_SIGNER_PROVISION_SUCCEEDED;
      default:
        return null;
    }
  }

  private emitEmailOtpUnlockWorkerProgress(
    onEvent: ((event: UnlockFlowEvent) => void) | undefined,
    args: {
      flowId: string;
      accountId: string;
      challengeId?: string;
      chainTarget: ThresholdEcdsaChainTarget;
      progress: EmailOtpWorkerProgressEvent;
    },
  ): UnlockEventPhase | null {
    const chainLabel = args.chainTarget.kind === 'tempo' ? 'Tempo' : 'EVM';
    const base = {
      flowId: args.flowId,
      accountId: args.accountId,
      authMethod: 'email_otp' as const,
      ...(args.challengeId ? { requestId: args.challengeId } : {}),
    };
    switch (args.progress.code) {
      case 'otp.verify.succeeded':
        this.emitEmailOtpUnlockEvent(onEvent, {
          ...base,
          phase: UnlockEventPhase.STEP_03_EMAIL_OTP_VERIFY_SUCCEEDED,
          status: 'succeeded',
          interaction: { kind: 'otp_input', overlay: 'hide' },
        });
        return UnlockEventPhase.STEP_03_EMAIL_OTP_VERIFY_SUCCEEDED;
      case 'signer.ecdsa.bootstrap.started':
        this.emitEmailOtpUnlockEvent(onEvent, {
          ...base,
          phase: UnlockEventPhase.STEP_05_SIGNING_SESSION_WARMUP_STARTED,
          status: 'running',
          message: `Preparing ${chainLabel} signing session`,
          data: { chainTarget: args.chainTarget },
        });
        return UnlockEventPhase.STEP_05_SIGNING_SESSION_WARMUP_STARTED;
      case 'signer.ecdsa.bootstrap.prepared':
        this.emitEmailOtpUnlockEvent(onEvent, {
          ...base,
          phase: UnlockEventPhase.STEP_05_SIGNING_SESSION_WARMUP_STARTED,
          status: 'running',
          message: `Coordinating ${chainLabel} signing session`,
          data: { chainTarget: args.chainTarget },
        });
        return UnlockEventPhase.STEP_05_SIGNING_SESSION_WARMUP_STARTED;
      case 'signer.ecdsa.bootstrap.responded':
        this.emitEmailOtpUnlockEvent(onEvent, {
          ...base,
          phase: UnlockEventPhase.STEP_05_SIGNING_SESSION_WARMUP_STARTED,
          status: 'running',
          message: `Finalizing ${chainLabel} signing session`,
          data: { chainTarget: args.chainTarget },
        });
        return UnlockEventPhase.STEP_05_SIGNING_SESSION_WARMUP_STARTED;
      case 'signer.ecdsa.bootstrap.succeeded':
        this.emitEmailOtpUnlockEvent(onEvent, {
          ...base,
          phase: UnlockEventPhase.STEP_05_SIGNING_SESSION_WARMUP_STARTED,
          status: 'running',
          message: `Saving ${chainLabel} signing session`,
          data: { chainTarget: args.chainTarget },
        });
        return UnlockEventPhase.STEP_05_SIGNING_SESSION_WARMUP_STARTED;
      default:
        return null;
    }
  }

  private emitEmailOtpUnlockFailure(
    onEvent: ((event: UnlockFlowEvent) => void) | undefined,
    input: Omit<CreateUnlockFlowEventInput, 'phase' | 'status' | 'error'> & {
      error: Error;
    },
  ): void {
    const cancelled = isUserCancellationError(input.error);
    this.emitEmailOtpUnlockEvent(onEvent, {
      ...input,
      phase: cancelled ? UnlockEventPhase.CANCELLED : UnlockEventPhase.FAILED,
      status: cancelled ? 'cancelled' : 'failed',
      interaction: input.interaction ?? {
        kind: cancelled ? 'otp_input' : 'none',
        overlay: 'hide',
      },
      error: { message: input.error.message },
    });
  }

  async requestEmailOtpChallenge(args: {
    nearAccountId: string;
    relayUrl?: string;
    appSessionJwt?: string;
    operation?: WalletEmailOtpLoginOperation;
    onEvent?: (event: UnlockFlowEvent) => void;
  }): Promise<EmailOtpChallengeResult> {
    const flowId = this.emailOtpUnlockFlowId(args.nearAccountId);
    this.emitEmailOtpUnlockEvent(args.onEvent, {
      flowId,
      accountId: args.nearAccountId,
      authMethod: 'email_otp',
      phase: UnlockEventPhase.STEP_03_EMAIL_OTP_CHALLENGE_STARTED,
      status: 'running',
    });
    try {
      if (this.walletIframe.shouldUseWalletIframe()) {
        const router = await this.walletIframe.requireRouter(args.nearAccountId);
        const result = await router.requestEmailOtpChallenge(args);
        this.emitEmailOtpUnlockEvent(args.onEvent, {
          flowId: this.emailOtpUnlockFlowId(args.nearAccountId, result.challengeId),
          accountId: args.nearAccountId,
          authMethod: 'email_otp',
          phase: UnlockEventPhase.STEP_03_EMAIL_OTP_CHALLENGE_SENT,
          status: 'succeeded',
          data: { challengeId: result.challengeId, otpChannel: result.otpChannel },
        });
        return result;
      }
      const result = await requestEmailOtpChallenge({
        relayUrl: String(args.relayUrl || this.configs.network.relayer.url || '').trim(),
        walletId: String(args.nearAccountId || '').trim(),
        ...(args.appSessionJwt ? { appSessionJwt: args.appSessionJwt } : {}),
        ...(args.operation ? { operation: args.operation } : {}),
      });
      this.emitEmailOtpUnlockEvent(args.onEvent, {
        flowId: this.emailOtpUnlockFlowId(args.nearAccountId, result.challengeId),
        accountId: args.nearAccountId,
        authMethod: 'email_otp',
        phase: UnlockEventPhase.STEP_03_EMAIL_OTP_CHALLENGE_SENT,
        status: 'succeeded',
        data: { challengeId: result.challengeId, otpChannel: result.otpChannel },
      });
      return result;
    } catch (error: unknown) {
      const e = toError(error);
      this.emitEmailOtpUnlockFailure(args.onEvent, {
        flowId,
        accountId: args.nearAccountId,
        authMethod: 'email_otp',
        error: e,
      });
      throw e;
    }
  }

  async requestEmailOtpEnrollmentChallenge(args: {
    nearAccountId: string;
    relayUrl?: string;
    appSessionJwt?: string;
    onEvent?: (event: RegistrationFlowEvent) => void;
  }): Promise<EmailOtpChallengeResult> {
    const flowId = this.emailOtpRegistrationFlowId(args.nearAccountId);
    this.emitEmailOtpRegistrationEvent(args.onEvent, {
      flowId,
      accountId: args.nearAccountId,
      authMethod: 'email_otp',
      phase: RegistrationEventPhase.STEP_04_OTP_CHALLENGE_STARTED,
      status: 'running',
    });
    try {
      if (this.walletIframe.shouldUseWalletIframe()) {
        const router = await this.walletIframe.requireRouter(args.nearAccountId);
        const result = await router.requestEmailOtpEnrollmentChallenge(args);
        this.emitEmailOtpRegistrationEvent(args.onEvent, {
          flowId: this.emailOtpRegistrationFlowId(args.nearAccountId, result.challengeId),
          accountId: args.nearAccountId,
          authMethod: 'email_otp',
          phase: RegistrationEventPhase.STEP_04_OTP_CHALLENGE_SENT,
          status: 'succeeded',
          data: { challengeId: result.challengeId, otpChannel: result.otpChannel },
        });
        return result;
      }
      const result = await requestEmailOtpEnrollmentChallenge({
        relayUrl: String(args.relayUrl || this.configs.network.relayer.url || '').trim(),
        walletId: String(args.nearAccountId || '').trim(),
        ...(args.appSessionJwt ? { appSessionJwt: args.appSessionJwt } : {}),
      });
      this.emitEmailOtpRegistrationEvent(args.onEvent, {
        flowId: this.emailOtpRegistrationFlowId(args.nearAccountId, result.challengeId),
        accountId: args.nearAccountId,
        authMethod: 'email_otp',
        phase: RegistrationEventPhase.STEP_04_OTP_CHALLENGE_SENT,
        status: 'succeeded',
        data: { challengeId: result.challengeId, otpChannel: result.otpChannel },
      });
      return result;
    } catch (error: unknown) {
      const e = toError(error);
      this.emitEmailOtpRegistrationFailure(args.onEvent, {
        flowId,
        accountId: args.nearAccountId,
        authMethod: 'email_otp',
        error: e,
      });
      throw e;
    }
  }

  async requestEmailOtpSigningSessionChallenge(args: {
    nearAccountId: string;
    subjectId: WalletSubjectId;
    chainTarget: ThresholdEcdsaChainTarget;
    onEvent?: (event: UnlockFlowEvent) => void;
  }): Promise<{ challengeId: string; emailHint?: string }> {
    const flowId = this.emailOtpUnlockFlowId(args.nearAccountId);
    this.emitEmailOtpUnlockEvent(args.onEvent, {
      flowId,
      accountId: args.nearAccountId,
      authMethod: 'email_otp',
      phase: UnlockEventPhase.STEP_03_EMAIL_OTP_CHALLENGE_STARTED,
      status: 'running',
    });
    try {
      if (this.walletIframe.shouldUseWalletIframe()) {
        const router = await this.walletIframe.requireRouter(args.nearAccountId);
        const result = await router.requestEmailOtpSigningSessionChallenge({
          nearAccountId: args.nearAccountId,
          subjectId: args.subjectId,
          chainTarget: args.chainTarget,
        });
        this.emitEmailOtpUnlockEvent(args.onEvent, {
          flowId: this.emailOtpUnlockFlowId(args.nearAccountId, result.challengeId),
          accountId: args.nearAccountId,
          authMethod: 'email_otp',
          phase: UnlockEventPhase.STEP_03_EMAIL_OTP_CHALLENGE_SENT,
          status: 'succeeded',
          data: { challengeId: result.challengeId, otpChannel: 'email_otp' },
        });
        return result;
      }
      const result = await this.signingEngine.requestEmailOtpSigningSessionChallenge({
        nearAccountId: toAccountId(args.nearAccountId),
        subjectId: args.subjectId,
        chainTarget: args.chainTarget,
      });
      this.emitEmailOtpUnlockEvent(args.onEvent, {
        flowId: this.emailOtpUnlockFlowId(args.nearAccountId, result.challengeId),
        accountId: args.nearAccountId,
        authMethod: 'email_otp',
        phase: UnlockEventPhase.STEP_03_EMAIL_OTP_CHALLENGE_SENT,
        status: 'succeeded',
        data: { challengeId: result.challengeId, otpChannel: 'email_otp' },
      });
      return result;
    } catch (error: unknown) {
      const e = toError(error);
      this.emitEmailOtpUnlockFailure(args.onEvent, {
        flowId,
        accountId: args.nearAccountId,
        authMethod: 'email_otp',
        error: e,
      });
      throw e;
    }
  }

  async exchangeGoogleEmailOtpSession(args: {
    idToken: string;
    accountMode: 'register' | 'login';
    relayUrl?: string;
    sessionKind?: 'jwt' | 'cookie';
    rerollRegistrationAttempt?: boolean;
    onEvent?: (event: RegistrationFlowEvent | UnlockFlowEvent) => void;
  }): Promise<Awaited<ReturnType<typeof exchangeGoogleEmailOtpSession>>> {
    const exchangeFlowId = `email-otp-${args.accountMode}:google-session`;
    if (args.accountMode === 'register') {
      this.emitEmailOtpRegistrationEvent(args.onEvent, {
        flowId: exchangeFlowId,
        authMethod: 'email_otp',
        phase: RegistrationEventPhase.STEP_03_SESSION_EXCHANGE_STARTED,
        status: 'running',
      });
    } else {
      this.emitEmailOtpUnlockEvent(args.onEvent, {
        flowId: exchangeFlowId,
        authMethod: 'email_otp',
        phase: UnlockEventPhase.STEP_04_APP_SESSION_EXCHANGE_STARTED,
        status: 'running',
      });
    }
    try {
      if (this.walletIframe.shouldUseWalletIframe()) {
        const router = await this.walletIframe.requireRouter();
        const result = await router.exchangeGoogleEmailOtpSession(args);
        const walletId = String(result.session?.walletId || '').trim();
        if (args.accountMode === 'register') {
          this.emitEmailOtpRegistrationEvent(args.onEvent, {
            flowId: walletId ? this.emailOtpRegistrationFlowId(walletId) : exchangeFlowId,
            ...(walletId ? { accountId: walletId } : {}),
            authMethod: 'email_otp',
            phase: RegistrationEventPhase.STEP_03_SESSION_EXCHANGE_SUCCEEDED,
            status: 'succeeded',
            data: {
              googleEmailOtpResolution: result.session?.googleEmailOtpResolution,
            },
          });
        } else {
          this.emitEmailOtpUnlockEvent(args.onEvent, {
            flowId: walletId ? this.emailOtpUnlockFlowId(walletId) : exchangeFlowId,
            ...(walletId ? { accountId: walletId } : {}),
            authMethod: 'email_otp',
            phase: UnlockEventPhase.STEP_04_APP_SESSION_EXCHANGE_SUCCEEDED,
            status: 'succeeded',
          });
        }
        return result;
      }
      const managedRegistration =
        this.configs.registration.mode === 'managed' ? this.configs.registration : null;
      const result = await exchangeGoogleEmailOtpSession({
        relayUrl: String(args.relayUrl || this.configs.network.relayer.url || '').trim(),
        idToken: args.idToken,
        accountMode: args.accountMode,
        ...(args.rerollRegistrationAttempt ? { rerollRegistrationAttempt: true } : {}),
        ...(args.sessionKind ? { sessionKind: args.sessionKind } : {}),
        ...(managedRegistration
          ? {
              runtimeEnvironmentId: managedRegistration.environmentId,
              publishableKey: managedRegistration.publishableKey,
            }
          : {}),
      });
      const walletId = String(result.session?.walletId || '').trim();
      if (args.accountMode === 'register') {
        this.emitEmailOtpRegistrationEvent(args.onEvent, {
          flowId: walletId ? this.emailOtpRegistrationFlowId(walletId) : exchangeFlowId,
          ...(walletId ? { accountId: walletId } : {}),
          authMethod: 'email_otp',
          phase: RegistrationEventPhase.STEP_03_SESSION_EXCHANGE_SUCCEEDED,
          status: 'succeeded',
          data: {
            googleEmailOtpResolution: result.session?.googleEmailOtpResolution,
          },
        });
      } else {
        this.emitEmailOtpUnlockEvent(args.onEvent, {
          flowId: walletId ? this.emailOtpUnlockFlowId(walletId) : exchangeFlowId,
          ...(walletId ? { accountId: walletId } : {}),
          authMethod: 'email_otp',
          phase: UnlockEventPhase.STEP_04_APP_SESSION_EXCHANGE_SUCCEEDED,
          status: 'succeeded',
        });
      }
      return result;
    } catch (error: unknown) {
      const e = toError(error);
      if (args.accountMode === 'register') {
        this.emitEmailOtpRegistrationFailure(args.onEvent, {
          flowId: exchangeFlowId,
          authMethod: 'email_otp',
          error: e,
        });
      } else {
        this.emitEmailOtpUnlockFailure(args.onEvent, {
          flowId: exchangeFlowId,
          authMethod: 'email_otp',
          error: e,
        });
      }
      throw e;
    }
  }

  async enrollEmailOtp(args: {
    nearAccountId: string;
    otpCode: string;
    relayUrl?: string;
    challengeId?: string;
    shamirPrimeB64u?: string;
    appSessionJwt?: string;
    clientSecret32?: Uint8Array;
    onEvent?: (event: RegistrationFlowEvent) => void;
  }): Promise<Awaited<ReturnType<SigningEngine['enrollEmailOtpInternal']>>> {
    const flowId = this.emailOtpRegistrationFlowId(args.nearAccountId, args.challengeId);
    this.emitEmailOtpRegistrationEvent(args.onEvent, {
      flowId,
      accountId: args.nearAccountId,
      authMethod: 'email_otp',
      phase: RegistrationEventPhase.STEP_04_OTP_VERIFY_STARTED,
      status: 'running',
      interaction: { kind: 'otp_input', overlay: 'none' },
      ...(args.challengeId ? { requestId: args.challengeId } : {}),
    });
    try {
      if (this.walletIframe.shouldUseWalletIframe()) {
        if (args.clientSecret32) {
          throw new Error(
            '[SeamsPasskey] Wallet iframe Email OTP enrollment owns client secret generation; clientSecret32 is not accepted from the app origin.',
          );
        }
        const router = await this.walletIframe.requireRouter(args.nearAccountId);
        const iframeArgs = { ...args };
        delete iframeArgs.clientSecret32;
        delete iframeArgs.onEvent;
        const result = await router.enrollEmailOtp(iframeArgs);
        this.emitEmailOtpRegistrationEvent(args.onEvent, {
          flowId,
          accountId: args.nearAccountId,
          authMethod: 'email_otp',
          phase: RegistrationEventPhase.STEP_04_OTP_VERIFY_SUCCEEDED,
          status: 'succeeded',
          interaction: { kind: 'otp_input', overlay: 'hide' },
          ...(args.challengeId ? { requestId: args.challengeId } : {}),
          data: {
            otpChannel: result.otpChannel,
            enrollmentSealKeyVersion: result.enrollmentSealKeyVersion,
          },
        });
        this.emitEmailOtpRegistrationEvent(args.onEvent, {
          flowId,
          accountId: args.nearAccountId,
          authMethod: 'email_otp',
          phase: RegistrationEventPhase.STEP_09_EMAIL_OTP_SIGNER_ENROLL_STARTED,
          status: 'running',
          ...(args.challengeId ? { requestId: args.challengeId } : {}),
        });
        this.emitEmailOtpRegistrationEvent(args.onEvent, {
          flowId,
          accountId: args.nearAccountId,
          authMethod: 'email_otp',
          phase: RegistrationEventPhase.STEP_09_EMAIL_OTP_SIGNER_ENROLL_SUCCEEDED,
          status: 'succeeded',
          ...(args.challengeId ? { requestId: args.challengeId } : {}),
          data: { unlockKeyVersion: result.unlockKeyVersion },
        });
        return result;
      }
      const result = await this.signingEngine.enrollEmailOtpInternal({
        nearAccountId: args.nearAccountId,
        otpCode: args.otpCode,
        ...(args.relayUrl ? { relayUrl: args.relayUrl } : {}),
        ...(args.challengeId ? { challengeId: args.challengeId } : {}),
        ...(args.shamirPrimeB64u ? { shamirPrimeB64u: args.shamirPrimeB64u } : {}),
        ...(args.appSessionJwt ? { appSessionJwt: args.appSessionJwt } : {}),
        ...(args.clientSecret32 ? { clientSecret32: args.clientSecret32 } : {}),
      });
      this.emitEmailOtpRegistrationEvent(args.onEvent, {
        flowId,
        accountId: args.nearAccountId,
        authMethod: 'email_otp',
        phase: RegistrationEventPhase.STEP_04_OTP_VERIFY_SUCCEEDED,
        status: 'succeeded',
        interaction: { kind: 'otp_input', overlay: 'hide' },
        ...(args.challengeId ? { requestId: args.challengeId } : {}),
        data: {
          otpChannel: result.otpChannel,
          enrollmentSealKeyVersion: result.enrollmentSealKeyVersion,
        },
      });
      this.emitEmailOtpRegistrationEvent(args.onEvent, {
        flowId,
        accountId: args.nearAccountId,
        authMethod: 'email_otp',
        phase: RegistrationEventPhase.STEP_09_EMAIL_OTP_SIGNER_ENROLL_STARTED,
        status: 'running',
        ...(args.challengeId ? { requestId: args.challengeId } : {}),
      });
      this.emitEmailOtpRegistrationEvent(args.onEvent, {
        flowId,
        accountId: args.nearAccountId,
        authMethod: 'email_otp',
        phase: RegistrationEventPhase.STEP_09_EMAIL_OTP_SIGNER_ENROLL_SUCCEEDED,
        status: 'succeeded',
        ...(args.challengeId ? { requestId: args.challengeId } : {}),
        data: { unlockKeyVersion: result.unlockKeyVersion },
      });
      return result;
    } catch (error: unknown) {
      const e = toError(error);
      this.emitEmailOtpRegistrationFailure(args.onEvent, {
        flowId,
        accountId: args.nearAccountId,
        authMethod: 'email_otp',
        ...(args.challengeId ? { requestId: args.challengeId } : {}),
        error: e,
      });
      throw e;
    }
  }

  async loginWithEmailOtpEcdsaCapability(
    args: EmailOtpEcdsaCapabilityArgs,
  ): Promise<Awaited<ReturnType<SigningEngine['loginWithEmailOtpEcdsaCapabilityInternal']>>> {
    const flowId = this.emailOtpUnlockFlowId(args.nearAccountId, args.challengeId);
    const chainTarget = requireConcreteEcdsaChainTarget(args.chainTarget, 'Email OTP ECDSA unlock');
    this.emitEmailOtpUnlockEvent(args.onEvent, {
      flowId,
      accountId: args.nearAccountId,
      authMethod: 'email_otp',
      phase: UnlockEventPhase.STEP_03_EMAIL_OTP_VERIFY_STARTED,
      status: 'running',
      interaction: { kind: 'otp_input', overlay: 'none' },
      ...(args.challengeId ? { requestId: args.challengeId } : {}),
    });
    try {
      if (this.walletIframe.shouldUseWalletIframe()) {
        const router = await this.walletIframe.requireRouter(args.nearAccountId);
        const iframeArgs = { ...args, chainTarget };
        delete iframeArgs.onEvent;
        const result = await router.loginWithEmailOtpEcdsaCapability(iframeArgs);
        this.emitEmailOtpUnlockEvent(args.onEvent, {
          flowId,
          accountId: args.nearAccountId,
          authMethod: 'email_otp',
          phase: UnlockEventPhase.STEP_03_EMAIL_OTP_VERIFY_SUCCEEDED,
          status: 'succeeded',
          interaction: { kind: 'otp_input', overlay: 'hide' },
          ...(args.challengeId ? { requestId: args.challengeId } : {}),
        });
        this.emitEmailOtpUnlockEvent(args.onEvent, {
          flowId,
          accountId: args.nearAccountId,
          authMethod: 'email_otp',
          phase: UnlockEventPhase.STEP_05_ECDSA_SIGNING_SESSION_READY,
          status: 'succeeded',
          ...(args.challengeId ? { requestId: args.challengeId } : {}),
          data: { chainTarget },
        });
        this.emitEmailOtpUnlockEvent(args.onEvent, {
          flowId,
          accountId: args.nearAccountId,
          authMethod: 'email_otp',
          phase: UnlockEventPhase.STEP_07_COMPLETED,
          status: 'succeeded',
          ...(args.challengeId ? { requestId: args.challengeId } : {}),
        });
        return result;
      }
      const workerProgressPhases = new Set<UnlockEventPhase>();
      const markWorkerProgress = (progress: EmailOtpWorkerProgressEvent) => {
        const phase = this.emitEmailOtpUnlockWorkerProgress(args.onEvent, {
          flowId,
          accountId: args.nearAccountId,
          challengeId: args.challengeId,
          chainTarget,
          progress,
        });
        if (phase) workerProgressPhases.add(phase);
      };
      const emitIfWorkerProgressMissing = (input: CreateUnlockFlowEventInput) => {
        if (workerProgressPhases.has(input.phase)) return;
        this.emitEmailOtpUnlockEvent(args.onEvent, input);
      };
      const result = await this.signingEngine.loginWithEmailOtpEcdsaCapabilityInternal({
        ...args,
        chainTarget,
        onProgress: markWorkerProgress,
      });
      emitIfWorkerProgressMissing({
        flowId,
        accountId: args.nearAccountId,
        authMethod: 'email_otp',
        phase: UnlockEventPhase.STEP_03_EMAIL_OTP_VERIFY_SUCCEEDED,
        status: 'succeeded',
        interaction: { kind: 'otp_input', overlay: 'hide' },
        ...(args.challengeId ? { requestId: args.challengeId } : {}),
      });
      emitIfWorkerProgressMissing({
        flowId,
        accountId: args.nearAccountId,
        authMethod: 'email_otp',
        phase: UnlockEventPhase.STEP_05_ECDSA_SIGNING_SESSION_READY,
        status: 'succeeded',
        ...(args.challengeId ? { requestId: args.challengeId } : {}),
        data: { chainTarget },
      });
      emitIfWorkerProgressMissing({
        flowId,
        accountId: args.nearAccountId,
        authMethod: 'email_otp',
        phase: UnlockEventPhase.STEP_07_COMPLETED,
        status: 'succeeded',
        ...(args.challengeId ? { requestId: args.challengeId } : {}),
      });
      return result;
    } catch (error: unknown) {
      const e = toError(error);
      this.emitEmailOtpUnlockFailure(args.onEvent, {
        flowId,
        accountId: args.nearAccountId,
        authMethod: 'email_otp',
        ...(args.challengeId ? { requestId: args.challengeId } : {}),
        error: e,
      });
      throw e;
    }
  }

  async refreshEmailOtpSigningSession(args: {
    nearAccountId: string;
    subjectId: WalletSubjectId;
    chainTarget: ThresholdEcdsaChainTarget;
    challengeId: string;
    otpCode: string;
    ttlMs?: number;
    remainingUses?: number;
    onEvent?: (event: UnlockFlowEvent) => void;
  }): Promise<Awaited<ReturnType<SigningEngine['refreshEmailOtpSigningSession']>>> {
    const flowId = this.emailOtpUnlockFlowId(args.nearAccountId, args.challengeId);
    const chainTarget = requireConcreteEcdsaChainTarget(
      args.chainTarget,
      'Email OTP signing-session refresh',
    );
    this.emitEmailOtpUnlockEvent(args.onEvent, {
      flowId,
      accountId: args.nearAccountId,
      authMethod: 'email_otp',
      phase: UnlockEventPhase.STEP_03_EMAIL_OTP_VERIFY_STARTED,
      status: 'running',
      interaction: { kind: 'otp_input', overlay: 'none' },
      requestId: args.challengeId,
    });
    try {
      const result = this.walletIframe.shouldUseWalletIframe()
        ? await (
            await this.walletIframe.requireRouter(args.nearAccountId)
          ).refreshEmailOtpSigningSession({
            nearAccountId: args.nearAccountId,
            subjectId: args.subjectId,
            chainTarget,
            challengeId: args.challengeId,
            otpCode: args.otpCode,
            ...(typeof args.ttlMs === 'number' ? { ttlMs: args.ttlMs } : {}),
            ...(typeof args.remainingUses === 'number'
              ? { remainingUses: args.remainingUses }
              : {}),
          })
        : await this.signingEngine.refreshEmailOtpSigningSession({
            nearAccountId: toAccountId(args.nearAccountId),
            subjectId: args.subjectId,
            chainTarget,
            challengeId: args.challengeId,
            otpCode: args.otpCode,
            ...(typeof args.ttlMs === 'number' ? { ttlMs: args.ttlMs } : {}),
            ...(typeof args.remainingUses === 'number'
              ? { remainingUses: args.remainingUses }
              : {}),
          });
      this.emitEmailOtpUnlockEvent(args.onEvent, {
        flowId,
        accountId: args.nearAccountId,
        authMethod: 'email_otp',
        phase: UnlockEventPhase.STEP_03_EMAIL_OTP_VERIFY_SUCCEEDED,
        status: 'succeeded',
        interaction: { kind: 'otp_input', overlay: 'hide' },
        requestId: args.challengeId,
      });
      this.emitEmailOtpUnlockEvent(args.onEvent, {
        flowId,
        accountId: args.nearAccountId,
        authMethod: 'email_otp',
        phase: UnlockEventPhase.STEP_05_ECDSA_SIGNING_SESSION_READY,
        status: 'succeeded',
        requestId: args.challengeId,
        data: { chainTarget },
      });
      this.emitEmailOtpUnlockEvent(args.onEvent, {
        flowId,
        accountId: args.nearAccountId,
        authMethod: 'email_otp',
        phase: UnlockEventPhase.STEP_07_COMPLETED,
        status: 'succeeded',
        requestId: args.challengeId,
      });
      return result;
    } catch (error: unknown) {
      const e = toError(error);
      this.emitEmailOtpUnlockFailure(args.onEvent, {
        flowId,
        accountId: args.nearAccountId,
        authMethod: 'email_otp',
        requestId: args.challengeId,
        error: e,
      });
      throw e;
    }
  }

  async enrollAndLoginWithEmailOtpEcdsaCapability(
    args: EmailOtpEcdsaEnrollmentCapabilityArgs,
  ): Promise<
    Awaited<ReturnType<SigningEngine['enrollAndLoginWithEmailOtpEcdsaCapabilityInternal']>>
  > {
    const flowId = this.emailOtpRegistrationFlowId(args.nearAccountId, args.challengeId);
    const chainTarget = requireConcreteEcdsaChainTarget(
      args.chainTarget,
      'Email OTP ECDSA enrollment',
    );
    this.emitEmailOtpRegistrationEvent(args.onEvent, {
      flowId,
      accountId: args.nearAccountId,
      authMethod: 'email_otp',
      phase: RegistrationEventPhase.STEP_04_OTP_VERIFY_STARTED,
      status: 'running',
      interaction: { kind: 'otp_input', overlay: 'none' },
      ...(args.challengeId ? { requestId: args.challengeId } : {}),
    });
    try {
      if (this.walletIframe.shouldUseWalletIframe()) {
        if (args.clientSecret32) {
          throw new Error(
            '[SeamsPasskey] Wallet iframe Email OTP enrollment owns client secret generation; clientSecret32 is not accepted from the app origin.',
          );
        }
        const router = await this.walletIframe.requireRouter(args.nearAccountId);
        const iframeArgs = { ...args, chainTarget };
        delete iframeArgs.clientSecret32;
        delete iframeArgs.onEvent;
        const result = await router.enrollAndLoginWithEmailOtpEcdsaCapability(iframeArgs);
        this.emitEmailOtpRegistrationEvent(args.onEvent, {
          flowId,
          accountId: args.nearAccountId,
          authMethod: 'email_otp',
          phase: RegistrationEventPhase.STEP_04_OTP_VERIFY_SUCCEEDED,
          status: 'succeeded',
          interaction: { kind: 'otp_input', overlay: 'hide' },
          ...(args.challengeId ? { requestId: args.challengeId } : {}),
          data: { otpChannel: result.enrollment.otpChannel },
        });
        this.emitEmailOtpRegistrationEvent(args.onEvent, {
          flowId,
          accountId: args.nearAccountId,
          authMethod: 'email_otp',
          phase: RegistrationEventPhase.STEP_09_EMAIL_OTP_SIGNER_ENROLL_STARTED,
          status: 'running',
          ...(args.challengeId ? { requestId: args.challengeId } : {}),
        });
        this.emitEmailOtpRegistrationEvent(args.onEvent, {
          flowId,
          accountId: args.nearAccountId,
          authMethod: 'email_otp',
          phase: RegistrationEventPhase.STEP_09_EMAIL_OTP_SIGNER_ENROLL_SUCCEEDED,
          status: 'succeeded',
          ...(args.challengeId ? { requestId: args.challengeId } : {}),
          data: { otpChannel: result.enrollment.otpChannel },
        });
        this.emitEmailOtpRegistrationEvent(args.onEvent, {
          flowId,
          accountId: args.nearAccountId,
          authMethod: 'email_otp',
          phase: RegistrationEventPhase.STEP_10_ECDSA_SIGNER_PROVISION_STARTED,
          status: 'running',
          ...(args.challengeId ? { requestId: args.challengeId } : {}),
          data: { chainTarget },
        });
        this.emitEmailOtpRegistrationEvent(args.onEvent, {
          flowId,
          accountId: args.nearAccountId,
          authMethod: 'email_otp',
          phase: RegistrationEventPhase.STEP_10_ECDSA_SIGNER_PROVISION_SUCCEEDED,
          status: 'succeeded',
          ...(args.challengeId ? { requestId: args.challengeId } : {}),
          data: { chainTarget },
        });
        this.emitEmailOtpRegistrationEvent(args.onEvent, {
          flowId,
          accountId: args.nearAccountId,
          authMethod: 'email_otp',
          phase: RegistrationEventPhase.STEP_11_COMPLETED,
          status: 'succeeded',
          ...(args.challengeId ? { requestId: args.challengeId } : {}),
        });
        return result;
      }
      const workerProgressPhases = new Set<RegistrationEventPhase>();
      const markWorkerProgress = (progress: EmailOtpWorkerProgressEvent) => {
        const phase = this.emitEmailOtpRegistrationWorkerProgress(args.onEvent, {
          flowId,
          accountId: args.nearAccountId,
          challengeId: args.challengeId,
          chainTarget,
          progress,
        });
        if (phase) workerProgressPhases.add(phase);
      };
      const emitIfWorkerProgressMissing = (input: CreateRegistrationFlowEventInput) => {
        if (workerProgressPhases.has(input.phase)) return;
        this.emitEmailOtpRegistrationEvent(args.onEvent, input);
      };
      const result = await this.signingEngine.enrollAndLoginWithEmailOtpEcdsaCapabilityInternal({
        ...args,
        chainTarget,
        onProgress: markWorkerProgress,
      });
      emitIfWorkerProgressMissing({
        flowId,
        accountId: args.nearAccountId,
        authMethod: 'email_otp',
        phase: RegistrationEventPhase.STEP_04_OTP_VERIFY_SUCCEEDED,
        status: 'succeeded',
        interaction: { kind: 'otp_input', overlay: 'hide' },
        ...(args.challengeId ? { requestId: args.challengeId } : {}),
        data: { otpChannel: result.enrollment.otpChannel },
      });
      emitIfWorkerProgressMissing({
        flowId,
        accountId: args.nearAccountId,
        authMethod: 'email_otp',
        phase: RegistrationEventPhase.STEP_09_EMAIL_OTP_SIGNER_ENROLL_STARTED,
        status: 'running',
        ...(args.challengeId ? { requestId: args.challengeId } : {}),
      });
      emitIfWorkerProgressMissing({
        flowId,
        accountId: args.nearAccountId,
        authMethod: 'email_otp',
        phase: RegistrationEventPhase.STEP_09_EMAIL_OTP_SIGNER_ENROLL_SUCCEEDED,
        status: 'succeeded',
        ...(args.challengeId ? { requestId: args.challengeId } : {}),
        data: { otpChannel: result.enrollment.otpChannel },
      });
      emitIfWorkerProgressMissing({
        flowId,
        accountId: args.nearAccountId,
        authMethod: 'email_otp',
        phase: RegistrationEventPhase.STEP_10_ECDSA_SIGNER_PROVISION_STARTED,
        status: 'running',
        ...(args.challengeId ? { requestId: args.challengeId } : {}),
        data: { chainTarget },
      });
      emitIfWorkerProgressMissing({
        flowId,
        accountId: args.nearAccountId,
        authMethod: 'email_otp',
        phase: RegistrationEventPhase.STEP_10_ECDSA_SIGNER_PROVISION_SUCCEEDED,
        status: 'succeeded',
        ...(args.challengeId ? { requestId: args.challengeId } : {}),
        data: { chainTarget },
      });
      this.emitEmailOtpRegistrationEvent(args.onEvent, {
        flowId,
        accountId: args.nearAccountId,
        authMethod: 'email_otp',
        phase: RegistrationEventPhase.STEP_11_COMPLETED,
        status: 'succeeded',
        ...(args.challengeId ? { requestId: args.challengeId } : {}),
      });
      return result;
    } catch (error: unknown) {
      const e = toError(error);
      this.emitEmailOtpRegistrationFailure(args.onEvent, {
        flowId,
        accountId: args.nearAccountId,
        authMethod: 'email_otp',
        ...(args.challengeId ? { requestId: args.challengeId } : {}),
        error: e,
      });
      throw e;
    }
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
      await this.signingEngine.getNonceCoordinator().prefetchNearContext({
        nearClient: this.nearClient,
      });
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
    input: Parameters<KeyExportCapability['exportKeypairWithUI']>[0],
  ): Promise<void> {
    const options = input.options;
    const resolvedOptions = {
      ...options,
      theme: options.theme ?? this.theme,
    };
    const resolvedInput =
      input.kind === 'near'
        ? {
            kind: 'near' as const,
            nearAccount: input.nearAccount,
            options: {
              ...resolvedOptions,
              chain: 'near' as const,
            },
          }
        : {
            kind: 'ecdsa' as const,
            subjectId: input.subjectId,
            chainTarget: input.chainTarget,
            walletSessionUserId: String(input.walletSessionUserId || '').trim(),
            options: resolvedOptions,
          };
    const routerAccountId =
      resolvedInput.kind === 'near'
        ? resolvedInput.nearAccount.accountId
        : resolvedInput.walletSessionUserId;
    if (!routerAccountId) {
      throw new Error('[SeamsPasskey] key export requires wallet session user context');
    }

    if (this.walletIframe.shouldUseWalletIframe()) {
      const router = await this.walletIframe.requireRouter(routerAccountId);
      await router.exportKeypairWithUI(resolvedInput);
      return;
    }

    await this.signingEngine.exportKeypairWithUI(resolvedInput);
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
  EmailOtpChallengeResult,
  EmailOtpEcdsaCapabilityArgs,
  EmailOtpEcdsaCapabilityResult,
  EmailOtpEcdsaEnrollmentCapabilityArgs,
  EmailOtpEcdsaEnrollmentCapabilityResult,
  EmailOtpEnrollmentResult,
  ExportKeypairWithUIInput,
  GoogleEmailOtpSessionExchangeResult,
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
  SeamsConfigsReadonly,
  SeamsConfigsInput,
  RegistrationResult,
  LoginAndCreateSessionResult,
  LoginResult,
  WalletSession,
  SigningSessionStatus,
  ActionResult,
} from '../types/seams';
export type {
  ActionHooksOptions,
  AfterCall,
  EventCallback,
  LoginHooksOptions,
  RegistrationHooksOptions,
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
  LinkDeviceEventPhase,
  DeviceLinkingError,
  DeviceLinkingErrorCode,
} from '../types/linkDevice';
export type { SyncAccountResult } from './syncAccount';
