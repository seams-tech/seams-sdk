import { BrowserSigningSurface } from '@/SeamsWeb/signingSurface/BrowserSigningSurface';
import {
  addWalletSigner as addWalletSignerWithUnifiedCeremony,
  isRegistrationBenchmarkDiagnosticsEnabled,
  registerWallet as registerWalletWithUnifiedCeremony,
  WALLET_IFRAME_TRANSPORT_TIMING_LABEL,
} from '@/SeamsWeb/operations/registration/registration';
import {
  MinimalNearClient,
  type NearClient,
  type AccessKeyList,
} from '@/core/rpcClients/near/NearClient';
import type {
  ActionResult,
  GetRecentUnlocksResult,
  LoginAndCreateSessionResult,
  WalletSession,
  RegistrationResult,
  ThemeName,
  SeamsConfigsReadonly,
  SeamsConfigsInput,
} from '@/core/types/seams';
import type {
  ActionHooksOptions,
  CreateRegistrationFlowEventInput,
  CreateUnlockFlowEventInput,
  KeyExportHooksOptions,
  LoginHooksOptions,
  RegistrationHooksOptions,
  RegistrationFlowEvent,
  UnlockFlowEvent,
} from '@/core/types/sdkSentEvents';
import {
  createRegistrationFlowEvent,
  createUnlockFlowEvent,
  RegistrationEventPhase,
  UnlockEventPhase,
} from '@/core/types/sdkSentEvents';
import { cloneAuthenticatorOptions } from '@/core/types/authenticatorOptions';
import { toAccountId, type AccountId } from '@/core/types/accountIds';
import { IndexedDBManager } from '@/core/indexedDB';
import { ActionType } from '@/core/types/actions';
import type { PreferencesChangedPayload } from '@/SeamsWeb/walletIframe/shared/messages';
import { __isWalletIframeHostMode } from '@/core/browser/walletIframe/host-mode';
import { isUserCancellationError, toError } from '@shared/utils/errors';
import { coerceThemeName } from '@shared/utils/theme';
import type { WalletEmailOtpLoginOperation } from '@shared/utils/emailOtpDomain';
import { buildConfigsFromEnv } from '@/core/config/defaultConfigs';
import { resolvePrimaryNearRpcUrl } from '@/core/config/chains';
import { WalletIframeCoordinator } from '@/SeamsWeb/walletIframe/coordinator';
import { shouldPrewarmBrowserWorkers } from './assembly/browserWorkerWarmupPolicy';
import { configureBrowserIndexedDB } from './assembly/configureBrowserIndexedDB';
import { createBrowserSigningRuntime } from './assembly/createBrowserSigningRuntime';
import { createBrowserSigningStores } from './assembly/createBrowserSigningStores';
import { initializeBrowserSigningRuntime } from './assembly/initializeBrowserSigningRuntime';
import {
  getWalletSessionDomain,
  type AuthSessionDomainDeps,
} from '@/SeamsWeb/operations/auth/authSessions';
import { createPublicApi, type WalletIframeControlCapability } from './publicApi';
import type {
  AuthCapability,
  DevicesCapability,
  EmailOtpBackedUpEnrollmentResult,
  EmailOtpChallengeResult,
  EmailOtpEcdsaCapabilityArgs,
  EmailOtpEcdsaCapabilityResult,
  EmailOtpEcdsaEnrollmentCapabilityArgs,
  EmailOtpEcdsaEnrollmentCapabilityResult,
  EvmSignerCapability,
  KeyExportCapability,
  NearSignerCapability,
  SeamsWebContext,
  SeamsWebSigningSurface,
  PreferencesCapability,
  RegistrationCapability,
  RecoveryCapability,
  TempoSignerCapability,
} from '@/SeamsWeb/signingSurface/types';
import type {
  ThresholdEd25519HssFinalizedReportEnvelope,
  ThresholdEd25519HssPreparedSessionEnvelope,
} from '@/core/signingEngine/threshold/crypto/hssClientSignerWasm';
import type { ThresholdEcdsaLoginPrefillResult } from '@/core/signingEngine/session/warmCapabilities/ecdsaLoginPrefill';
import type { EnrollEmailOtpInternalResult } from '@/core/signingEngine/flows/signEvmFamily/emailOtpPublic';
import {
  nearAccountRefFromAccountId,
  toWalletId,
  thresholdEcdsaChainTargetFromRequest,
  walletSessionRefFromSession,
  type ThresholdEcdsaChainTarget,
  type WalletId,
  type WalletSessionRef,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { assertWalletRuntimePostconditions } from '@/core/signingEngine/session/postconditions/runtimePostconditions';
import { configuredEmailOtpEcdsaSnapshotChainTargets } from '@/core/signingEngine/session/emailOtp/persistedSnapshot';
import type { EmailOtpWorkerProgressEvent } from '@/core/signingEngine/workerManager/workerTypes';
import {
  parseThresholdRuntimePolicyScopeFromJwt,
} from '@/core/signingEngine/threshold/sessionPolicy';
import type {
  EmailOtpEd25519SessionReconstructionPlan,
} from '@/core/signingEngine/session/emailOtp/provisioning';
import {
  exchangeGoogleEmailOtpSession,
  requestEmailOtpChallenge,
  requestEmailOtpEnrollmentChallenge,
} from '@/SeamsWeb/operations/authMethods/emailOtp/challenge';
import {
  beginGoogleEmailOtpWalletAuth,
} from '@/SeamsWeb/operations/authMethods/emailOtp/googleEmailOtpWalletAuthFlow';
import {
  getEmailOtpRecoveryCodeStatus,
  storeRotatedEmailOtpRecoveryCodes,
} from '@/SeamsWeb/operations/authMethods/emailOtp/recoveryCodeBackup';
import { walletIdFromString } from '@shared/utils/registrationIntent';
import { buildNearWalletRegistrationSignerSelection } from '@/SeamsWeb/operations/registration/registrationSignerSelection';
import { SIGNER_AUTH_METHODS, SIGNER_KINDS } from '@shared/utils/signerDomain';
import { buildThresholdEd25519Participants2pV1 } from '@shared/threshold/participants';
import { isObject } from '@shared/utils/validation';

///////////////////////////////////////
// PASSKEY MANAGER
///////////////////////////////////////

function requireConcreteEcdsaChainTarget(
  value: unknown,
  operation: string,
): ThresholdEcdsaChainTarget {
  if (!isObject(value)) {
    throw new Error(`[SeamsWeb] ${operation} requires a concrete ECDSA chainTarget`);
  }
  return thresholdEcdsaChainTargetFromRequest(value);
}

async function resolveEmailOtpEd25519SessionReconstruction(
  args: EmailOtpEcdsaCapabilityArgs,
): Promise<EmailOtpEd25519SessionReconstructionPlan> {
  const walletId = toAccountId(args.walletSession.walletId);
  const keyIdentity = await resolveEmailOtpEd25519KeyIdentity(walletId);
  const runtimePolicyScope =
    args.runtimePolicyScope || parseThresholdRuntimePolicyScopeFromJwt(args.appSessionJwt);
  const diagnostic = {
    walletId,
    signerSlot: keyIdentity?.signerSlot || null,
    keyIdentitySource: keyIdentity?.source || null,
    hasRelayerKeyId: Boolean(keyIdentity?.ed25519Key.relayerKeyId),
    hasKeyVersion: Boolean(keyIdentity?.ed25519Key.keyVersion),
    participantCount: keyIdentity?.ed25519Key.participantIds.length || 0,
    hasRuntimePolicyScope: Boolean(runtimePolicyScope),
  };

  if (keyIdentity) {
    const ed25519Key = keyIdentity.ed25519Key;
    if (!runtimePolicyScope) {
      console.warn(
        '[SeamsWeb][email-otp] Ed25519 reconstruction deferred before unlock',
        {
          ...diagnostic,
          reason: 'missing_runtime_policy_scope',
        },
      );
      return {
        kind: 'defer',
        reason: 'missing_runtime_policy_scope',
        ed25519Key,
      };
    }
    return {
      kind: 'reconstruct',
      ed25519Key,
      runtimePolicyScope,
    };
  }

  console.warn(
    '[SeamsWeb][email-otp] Ed25519 reconstruction deferred before unlock',
    {
      ...diagnostic,
      reason: 'missing_ed25519_key_identity',
    },
  );
  return {
    kind: 'defer',
    reason: 'missing_ed25519_key_identity',
  };
}

type EmailOtpEd25519KeyIdentity = {
  signerSlot: number;
  source: 'wallet_profile_signer';
  ed25519Key: {
    relayerKeyId: string;
    keyVersion: string;
    participantIds: number[];
  };
};

function normalizeParticipantIds(value: unknown): number[] {
  if (!Array.isArray(value)) return [];
  return value
    .map((participant) =>
      typeof participant === 'object' && participant !== null && 'id' in participant
        ? Number((participant as { id?: unknown }).id)
        : Number(participant),
    )
    .filter((participantId) => Number.isSafeInteger(participantId) && participantId > 0);
}

function participantIdsFromEmailOtpEd25519SignerMetadata(args: {
  relayerKeyId: string;
  metadata: Record<string, unknown>;
}): number[] {
  const participantIds = normalizeParticipantIds(args.metadata.participantIds);
  if (participantIds.length) return participantIds;
  return buildThresholdEd25519Participants2pV1({
    relayerKeyId: args.relayerKeyId,
    clientParticipantId: Number(args.metadata.clientParticipantId),
    relayerParticipantId: Number(args.metadata.relayerParticipantId),
    clientShareDerivation: 'prf_first_v1',
  }).map((participant) => participant.id);
}

function emailOtpEd25519KeyIdentityFromSigner(
  signer: Awaited<ReturnType<typeof IndexedDBManager.listAccountSigners>>[number],
  source: EmailOtpEd25519KeyIdentity['source'],
): EmailOtpEd25519KeyIdentity | null {
  if (signer.signerKind !== SIGNER_KINDS.thresholdEd25519) return null;
  if (signer.signerAuthMethod !== SIGNER_AUTH_METHODS.emailOtp) return null;
  const metadata = signer.metadata || {};
  const relayerKeyId = String(metadata.relayerKeyId || '').trim();
  const keyVersion = String(metadata.keyVersion || '').trim();
  const participantIds = participantIdsFromEmailOtpEd25519SignerMetadata({
    relayerKeyId,
    metadata,
  });
  if (!relayerKeyId || !keyVersion || !participantIds.length) return null;
  return {
    signerSlot: signer.signerSlot,
    source,
    ed25519Key: {
      relayerKeyId,
      keyVersion,
      participantIds,
    },
  };
}

function findEmailOtpEd25519KeyIdentityFromSigners(
  signers: Awaited<ReturnType<typeof IndexedDBManager.listAccountSigners>>,
  source: EmailOtpEd25519KeyIdentity['source'],
): EmailOtpEd25519KeyIdentity | null {
  for (const signer of signers.slice().sort((left, right) => left.signerSlot - right.signerSlot)) {
    const identity = emailOtpEd25519KeyIdentityFromSigner(signer, source);
    if (identity) return identity;
  }
  return null;
}

function accountSignerDiagnosticSummary(
  signers: Awaited<ReturnType<typeof IndexedDBManager.listAccountSigners>>,
): Array<Record<string, unknown>> {
  return signers.map((signer) => ({
    signerSlot: signer.signerSlot,
    signerKind: signer.signerKind,
    signerAuthMethod: signer.signerAuthMethod,
    chainIdKey: signer.chainIdKey,
    accountAddress: signer.accountAddress,
    hasRelayerKeyId: Boolean(String(signer.metadata?.relayerKeyId || '').trim()),
    hasKeyVersion: Boolean(String(signer.metadata?.keyVersion || '').trim()),
    hasParticipantIds: Array.isArray(signer.metadata?.participantIds),
    hasClientParticipantId: signer.metadata?.clientParticipantId != null,
    hasRelayerParticipantId: signer.metadata?.relayerParticipantId != null,
  }));
}

async function resolveEmailOtpEd25519KeyIdentity(
  walletId: AccountId,
): Promise<EmailOtpEd25519KeyIdentity | null> {
  const walletProfileSigners = await IndexedDBManager.listAccountSignersByProfile({
    profileId: String(walletId),
    status: 'active',
  }).catch(() => []);
  const walletProfileIdentity = findEmailOtpEd25519KeyIdentityFromSigners(
    walletProfileSigners,
    'wallet_profile_signer',
  );
  if (walletProfileIdentity) return walletProfileIdentity;

  console.warn('[SeamsWeb][email-otp] Ed25519 key identity lookup failed', {
    walletId,
    walletProfileSignerCount: walletProfileSigners.length,
    walletProfileSigners: accountSignerDiagnosticSummary(walletProfileSigners),
  });
  return null;
}

/**
 * Main SeamsWeb class that provides framework-agnostic passkey operations
 * with flexible event-based callbacks for custom UX implementation
 */
export class SeamsWeb {
  private readonly signingEngine: SeamsWebSigningSurface;
  private readonly nearClient: NearClient;
  readonly configs: SeamsConfigsReadonly;
  theme: ThemeName;
  private readonly walletIframe: WalletIframeCoordinator;
  readonly recovery: RecoveryCapability;
  readonly devices: DevicesCapability;
  readonly keys: KeyExportCapability;
  readonly preferences: PreferencesCapability;
  readonly auth: AuthCapability;
  readonly registration: RegistrationCapability;
  readonly near: NearSignerCapability;
  readonly tempo: TempoSignerCapability;
  readonly evm: EvmSignerCapability;
  private readonly walletIframeControls: WalletIframeControlCapability;

  constructor(configs: SeamsConfigsInput, nearClient?: NearClient) {
    this.configs = buildConfigsFromEnv(configs);
    configureBrowserIndexedDB(this.configs);
    // Use provided client or create default one
    this.nearClient =
      nearClient || new MinimalNearClient(resolvePrimaryNearRpcUrl(this.configs.network.chains));
    const browserSigningStores = createBrowserSigningStores(IndexedDBManager);
    this.signingEngine = new BrowserSigningSurface(this.configs, this.nearClient, {
      managerStores: browserSigningStores.managerStores,
      signingEngineStores: browserSigningStores.signingEngineStores,
      sealedSigningSessionStore: browserSigningStores.sealedSigningSessionStore,
      createRuntime: createBrowserSigningRuntime,
      initializeRuntime: initializeBrowserSigningRuntime,
      shouldPrewarmWorkers: shouldPrewarmBrowserWorkers,
    });

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
      refreshWalletSession: async (walletId?: string) => {
        await getWalletSessionDomain(this.getAuthSessionDeps(), walletId);
      },
    });
    const publicApi = createPublicApi({
      signingEngine: this.signingEngine,
      nearClient: this.nearClient,
      configs: this.configs,
      getTheme: () => this.theme,
      userPreferences,
      getWalletIframe: () => this.walletIframe,
      getAuthSessionDeps: () => this.getAuthSessionDeps(),
      auth: {
        requestEmailOtpChallenge: async (args) => await this.requestEmailOtpChallengeDomain(args),
        requestEmailOtpSigningSessionChallenge: async (args) =>
          await this.requestEmailOtpSigningSessionChallengeDomain(args),
        refreshEmailOtpSigningSession: async (args) =>
          await this.refreshEmailOtpSigningSessionDomain(args),
        exchangeGoogleEmailOtpSession: async (args) =>
          await this.exchangeGoogleEmailOtpSessionDomain(args),
        loginWithEmailOtpEcdsaCapability: async (args) =>
          await this.loginWithEmailOtpEcdsaCapabilityDomain(args),
        beginGoogleEmailOtpWalletAuth: async (args) =>
          await beginGoogleEmailOtpWalletAuth(
            {
              configs: this.configs,
              getRpId: () => this.signingEngine.getRpId(),
              exchangeGoogleEmailOtpSession: async (exchangeArgs) =>
                await this.exchangeGoogleEmailOtpSessionDomain(exchangeArgs),
              requestEmailOtpChallenge: async (challengeArgs) =>
                await this.requestEmailOtpChallengeDomain(challengeArgs),
              prepareEmailOtpRegistrationEnrollmentMaterial: async (prepareArgs) =>
                await this.signingEngine.prepareEmailOtpRegistrationEnrollmentMaterialInternal({
                  relayUrl: prepareArgs.relayUrl,
                  walletId: walletIdFromString(prepareArgs.walletId),
                  userId: prepareArgs.userId,
                  rpId: prepareArgs.rpId,
                  appSessionJwt: prepareArgs.appSessionJwt,
                }),
              registerWallet: async (registerArgs) =>
                await this.registerWalletDomain(registerArgs),
              loginWithEmailOtpEcdsaCapability: async (loginArgs) =>
                await this.loginWithEmailOtpEcdsaCapabilityDomain(loginArgs),
              getWalletSession: async (walletId) =>
                await getWalletSessionDomain(this.getAuthSessionDeps(), walletId),
            },
            args,
          ),
      },
      registration: {
        addWalletSigner: async (args) => await this.registerWalletSignerDomain(args),
        registerWallet: async (args) => await this.registerWalletDomain(args),
        registerPasskey: async (nearAccountId, options) =>
          await this.registerPasskeyDomain(nearAccountId, options),
        createPasskeyRegistrationActivationSurface: (args) =>
          this.createPasskeyRegistrationActivationSurfaceDomain(args),
        requestEmailOtpEnrollmentChallenge: async (args) =>
          await this.requestEmailOtpEnrollmentChallengeDomain(args),
        enrollEmailOtp: async (args) => await this.enrollEmailOtpDomain(args),
        enrollAndLoginWithEmailOtpEcdsaCapability: async (args) =>
          await this.enrollAndLoginWithEmailOtpEcdsaCapabilityDomain(args),
      },
      recovery: {
        getEmailOtpRecoveryCodeStatus: async (args) =>
          await this.getEmailOtpRecoveryCodeStatusDomain(args),
        rotateEmailOtpRecoveryCodes: async (args) =>
          await this.rotateEmailOtpRecoveryCodesDomain(args),
      },
      devices: {
        viewAccessKeyList: async (accountId) => await this.viewAccessKeyListDomain(accountId),
        deleteDeviceKey: async (accountId, publicKeyToDelete, options) =>
          await this.deleteDeviceKeyDomain(accountId, publicKeyToDelete, options),
      },
      keys: {
        exportKeypairWithUI: async (input) => await this.exportKeypairWithUIDomain(input),
        exportThresholdEd25519SeedFromHssReport: async (args) =>
          await this.exportThresholdEd25519SeedFromHssReportDomain(args),
      },
    });
    this.walletIframeControls = publicApi.walletIframeControls;
    this.preferences = publicApi.preferences;
    this.auth = publicApi.auth;
    this.registration = publicApi.registration;
    this.recovery = publicApi.recovery;
    this.devices = publicApi.devices;
    this.keys = publicApi.keys;
    this.near = publicApi.near;
    this.tempo = publicApi.tempo;
    this.evm = publicApi.evm;

    // UserConfirm worker initializes automatically in the constructor
  }

  /**
   * Initialize the hidden wallet service iframe client (optional) and warm critical resources.
   * Always warms local resources; initializes iframe when wallet mode is `iframe`.
   * Idempotent and safe to call multiple times.
   */
  async initWalletIframe(walletId?: string): Promise<void> {
    await this.walletIframeControls.initWalletIframe(walletId);
  }

  /** True when the wallet iframe client is connected and ready. */
  isWalletIframeReady(): boolean {
    return this.walletIframeControls.isWalletIframeReady();
  }

  /** Subscribe to wallet iframe ready state transitions. */
  onWalletIframeReady(listener: () => void): () => void {
    return this.walletIframeControls.onWalletIframeReady(listener);
  }

  /** Subscribe to wallet-host login status updates. */
  onWalletIframeLoginStatusChanged(
    listener: (status: { isLoggedIn: boolean; walletId: string | null }) => void,
  ): () => void {
    return this.walletIframeControls.onWalletIframeLoginStatusChanged(listener);
  }

  /** Subscribe to wallet-host preference updates. */
  onWalletIframePreferencesChanged(
    listener: (payload: PreferencesChangedPayload) => void,
  ): () => void {
    return this.walletIframeControls.onWalletIframePreferencesChanged(listener);
  }

  getContext(): SeamsWebContext {
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
      initWalletIframe: async (walletId?: string) => {
        await this.initWalletIframe(walletId);
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
      // initWalletIframe also calls the browser signing surface warmup internally.
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
  private async viewAccessKeyListDomain(accountId: string): Promise<AccessKeyList> {
    if (this.walletIframe.shouldUseWalletIframe()) {
      const router = await this.walletIframe.requireRouter(accountId);
      return await router.viewAccessKeyList(accountId);
    }
    return this.nearClient.viewAccessKeyList(accountId);
  }

  private emitWalletIframeTransportTimingSummary(input: {
    operation: 'registerWallet' | 'registerPasskey';
    walletId: string | null;
  }): void {
    if (!isRegistrationBenchmarkDiagnosticsEnabled()) return;
    const diagnostics = this.walletIframe.getTransportDiagnosticsSnapshot();
    if (!diagnostics) return;
    const { kind: transportKind, ...timings } = diagnostics;
    console.info(WALLET_IFRAME_TRANSPORT_TIMING_LABEL, {
      kind: 'wallet_iframe_registration_transport_timing_v1',
      operation: input.operation,
      walletId: input.walletId,
      transportKind,
      ...timings,
    });
  }

  ///////////////////////////////////////
  // === Registration and Login ===
  ///////////////////////////////////////

  private async registerWalletDomain(
    args: Parameters<RegistrationCapability['registerWallet']>[0],
  ): Promise<RegistrationResult> {
    if (this.walletIframe.shouldUseWalletIframe()) {
      try {
        const nearAccountId =
          args.signerSelection.mode === 'ed25519_only' ||
          args.signerSelection.mode === 'ed25519_and_ecdsa'
            ? args.signerSelection.ed25519.nearAccountId
            : undefined;
        const router = await this.walletIframe.requireRouter(nearAccountId);
        this.emitWalletIframeTransportTimingSummary({
          operation: 'registerWallet',
          walletId:
            nearAccountId ??
            (args.wallet.kind === 'provided' ? String(args.wallet.walletId) : null),
        });
        const res = await router.registerWallet(args);
        if (nearAccountId) {
          void (async () => {
            try {
              await this.initWalletIframe(nearAccountId);
            } catch {}
          })();
        }
        await args.options?.afterCall?.(true, res);
        return res;
      } catch (error: unknown) {
        const e = toError(error);
        await args.options?.onError?.(e);
        await args.options?.afterCall?.(false);
        throw e;
      }
    }
    return await registerWalletWithUnifiedCeremony({
      context: this.getContext(),
      authMethod: args.authMethod,
      wallet: args.wallet,
      rpId: args.rpId,
      signerSelection: args.signerSelection,
      options: args.options || {},
      authenticatorOptions: cloneAuthenticatorOptions(this.configs.webauthn.authenticatorOptions),
    });
  }

  private async registerWalletSignerDomain(
    args: Parameters<RegistrationCapability['addWalletSigner']>[0],
  ): Promise<RegistrationResult> {
    if (this.walletIframe.shouldUseWalletIframe()) {
      try {
        const router = await this.walletIframe.requireRouter(String(args.walletId || ''));
        const res = await router.addWalletSigner(args);
        await args.options?.afterCall?.(true, res);
        return res;
      } catch (error: unknown) {
        const e = toError(error);
        await args.options?.onError?.(e);
        await args.options?.afterCall?.(false);
        throw e;
      }
    }
    return await addWalletSignerWithUnifiedCeremony({
      context: this.getContext(),
      walletId: args.walletId,
      rpId: args.rpId,
      signerSelection: args.signerSelection,
      options: args.options || {},
    });
  }

  /**
   * Register a new passkey for the given NEAR account ID
   * Uses AccountId for on-chain operations and PRF salt derivation
   */
  private async registerPasskeyDomain(
    nearAccountId: string,
    options: RegistrationHooksOptions = {},
  ): Promise<RegistrationResult> {
    // In wallet-iframe mode, always run inside the wallet origin (no app-origin fallback).
    if (this.walletIframe.shouldUseWalletIframe()) {
      try {
        const router = await this.walletIframe.requireRouter(nearAccountId);
        this.emitWalletIframeTransportTimingSummary({
          operation: 'registerPasskey',
          walletId: nearAccountId,
        });
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
    const accountId = toAccountId(nearAccountId);
    const rpId = this.signingEngine.getRpId();
    if (!rpId) {
      throw new Error('Missing rpId for relay registration');
    }
    return await this.registerWalletDomain({
      wallet: {
        kind: 'provided',
        walletId: walletIdFromString(String(accountId)),
      },
      rpId,
      authMethod: { kind: 'passkey' },
      signerSelection: buildNearWalletRegistrationSignerSelection({
        configs: this.configs,
        nearAccountId: String(accountId),
        options,
      }),
      options,
    });
  }

  private createPasskeyRegistrationActivationSurfaceDomain(
    args: Parameters<RegistrationCapability['createPasskeyRegistrationActivationSurface']>[0],
  ): ReturnType<RegistrationCapability['createPasskeyRegistrationActivationSurface']> {
    if (!this.walletIframe.shouldUseWalletIframe()) {
      throw new Error(
        '[SeamsWeb] Registration activation surfaces require wallet iframe mode.',
      );
    }
    type Surface = ReturnType<RegistrationCapability['createPasskeyRegistrationActivationSurface']>;
    type SurfaceState = ReturnType<Surface['state']>;
    let state: SurfaceState = { kind: 'idle' };
    let inner: Surface | null = null;
    let disposed = false;
    const listeners = new Set<(next: SurfaceState) => void>();
    const setState = (next: SurfaceState): void => {
      state = next;
      for (const listener of listeners) {
        try {
          listener(next);
        } catch {}
      }
    };
    void this.initWalletIframe(args.nearAccountId).catch(() => {});
    return {
      kind: 'wallet_iframe_registration_activation_surface_v1',
      mount: (target: HTMLElement) => {
        void (async () => {
          try {
            if (disposed) return;
            const router = await this.walletIframe.requireRouter(args.nearAccountId);
            if (disposed) return;
            inner = router.createPasskeyRegistrationActivationSurface(args);
            inner.onStateChange(setState);
            inner.mount(target);
          } catch (error) {
            const message = error instanceof Error ? error.message : 'Registration activation failed';
            setState({ kind: 'failed', activationId: '', error: message });
          }
        })();
      },
      dispose: () => {
        disposed = true;
        inner?.dispose();
        if (state.kind === 'idle') {
          setState({ kind: 'cancelled', activationId: '', reason: 'disposed' });
        }
      },
      state: () => state,
      onStateChange: (listener) => {
        listeners.add(listener);
        return () => listeners.delete(listener);
      },
    };
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

  private async requestEmailOtpChallengeDomain(args: {
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

  private async requestEmailOtpEnrollmentChallengeDomain(args: {
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

  private async requestEmailOtpSigningSessionChallengeDomain(args: {
    walletSession: WalletSessionRef;
    chainTarget: ThresholdEcdsaChainTarget;
    onEvent?: (event: UnlockFlowEvent) => void;
  }): Promise<{ challengeId: string; emailHint?: string }> {
    const walletId = args.walletSession.walletId;
    const flowId = this.emailOtpUnlockFlowId(walletId);
    this.emitEmailOtpUnlockEvent(args.onEvent, {
      flowId,
      accountId: walletId,
      authMethod: 'email_otp',
      phase: UnlockEventPhase.STEP_03_EMAIL_OTP_CHALLENGE_STARTED,
      status: 'running',
    });
    try {
      if (this.walletIframe.shouldUseWalletIframe()) {
        const router = await this.walletIframe.requireRouter(walletId);
        const result = await router.requestEmailOtpSigningSessionChallenge({
          walletSession: args.walletSession,
          chainTarget: args.chainTarget,
        });
        this.emitEmailOtpUnlockEvent(args.onEvent, {
          flowId: this.emailOtpUnlockFlowId(walletId, result.challengeId),
          accountId: walletId,
          authMethod: 'email_otp',
          phase: UnlockEventPhase.STEP_03_EMAIL_OTP_CHALLENGE_SENT,
          status: 'succeeded',
          data: { challengeId: result.challengeId, otpChannel: 'email_otp' },
        });
        return result;
      }
      const result = await this.signingEngine.requestEmailOtpSigningSessionChallenge({
        walletSession: args.walletSession,
        chainTarget: args.chainTarget,
      });
      this.emitEmailOtpUnlockEvent(args.onEvent, {
        flowId: this.emailOtpUnlockFlowId(walletId, result.challengeId),
        accountId: walletId,
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
        accountId: walletId,
        authMethod: 'email_otp',
        error: e,
      });
      throw e;
    }
  }

  private async exchangeGoogleEmailOtpSessionDomain(args: {
    idToken: string;
    accountMode: 'register' | 'login';
    relayUrl?: string;
    sessionKind?: 'jwt' | 'cookie';
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

  private async enrollEmailOtpDomain(args: {
    nearAccountId: string;
    otpCode: string;
    relayUrl?: string;
    challengeId?: string;
    shamirPrimeB64u?: string;
    appSessionJwt?: string;
    clientSecret32?: Uint8Array;
    onEvent?: (event: RegistrationFlowEvent) => void;
  }): Promise<EnrollEmailOtpInternalResult | EmailOtpBackedUpEnrollmentResult> {
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
            '[SeamsWeb] Wallet iframe Email OTP enrollment owns client secret generation; clientSecret32 is not accepted from the app origin.',
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
        walletId: toWalletId(args.nearAccountId),
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

  private async getEmailOtpRecoveryCodeStatusDomain(args: {
    walletId: string;
    relayUrl?: string;
    appSessionJwt?: string;
  }) {
    const relayUrl = String(args.relayUrl || this.configs.network.relayer.url || '').trim();
    if (this.walletIframe.shouldUseWalletIframe()) {
      const router = await this.walletIframe.requireRouter(args.walletId);
      return await router.getEmailOtpRecoveryCodeStatus({
        walletId: args.walletId,
        relayUrl,
        ...(args.appSessionJwt ? { appSessionJwt: args.appSessionJwt } : {}),
      });
    }
    const appSessionJwt = await this.resolveEmailOtpRecoveryCodeAppSessionJwt({
      walletId: args.walletId,
      relayUrl,
      appSessionJwt: args.appSessionJwt,
    });
    return await getEmailOtpRecoveryCodeStatus({
      relayUrl,
      walletId: args.walletId,
      ...(appSessionJwt ? { appSessionJwt } : {}),
    });
  }

  async showEmailOtpRecoveryCodesForAccountMenu(args: {
    walletId: string;
  }) {
    return await this.showEmailOtpRecoveryCodesDomain({
      walletId: args.walletId,
    });
  }

  private async showEmailOtpRecoveryCodesDomain(args: {
    walletId: string;
    relayUrl?: string;
    appSessionJwt?: string;
  }) {
    const relayUrl = String(args.relayUrl || this.configs.network.relayer.url || '').trim();
    if (this.walletIframe.shouldUseWalletIframe()) {
      const router = await this.walletIframe.requireRouter(args.walletId);
      return await router.showEmailOtpRecoveryCodes({
        walletId: args.walletId,
        relayUrl,
        ...(args.appSessionJwt ? { appSessionJwt: args.appSessionJwt } : {}),
      });
    }
    const status = await this.getEmailOtpRecoveryCodeStatusDomain(args);
    return { status, displayedStoredCodes: false };
  }

  private async rotateEmailOtpRecoveryCodesDomain(args: {
    walletId: string;
    relayUrl?: string;
    appSessionJwt?: string;
  }) {
    const relayUrl = String(args.relayUrl || this.configs.network.relayer.url || '').trim();
    if (this.walletIframe.shouldUseWalletIframe()) {
      const router = await this.walletIframe.requireRouter(args.walletId);
      return await router.rotateEmailOtpRecoveryCodes({
        walletId: args.walletId,
        relayUrl,
        ...(args.appSessionJwt ? { appSessionJwt: args.appSessionJwt } : {}),
      });
    }
    const appSessionJwt = await this.resolveEmailOtpRecoveryCodeAppSessionJwt({
      walletId: args.walletId,
      relayUrl,
      appSessionJwt: args.appSessionJwt,
    });
    const rotation = await this.signingEngine.rotateEmailOtpRecoveryCodesInternal({
      walletId: toWalletId(args.walletId),
      relayUrl,
      ...(appSessionJwt ? { appSessionJwt } : {}),
    });
    const recoveryCodeBackup = await storeRotatedEmailOtpRecoveryCodes({
      walletId: args.walletId,
      rotation,
      storageScope: 'host_origin_indexeddb',
    });
    const status = await this.getEmailOtpRecoveryCodeStatusDomain({
      walletId: args.walletId,
      relayUrl,
      ...(appSessionJwt ? { appSessionJwt } : {}),
    });
    return { status, recoveryCodeBackup };
  }

  private async resolveEmailOtpRecoveryCodeAppSessionJwt(args: {
    walletId: string;
    relayUrl: string;
    appSessionJwt?: string;
  }): Promise<string> {
    const providedJwt = String(args.appSessionJwt || '').trim();
    if (providedJwt) return providedJwt;
    const walletId = toWalletId(args.walletId);
    const session = await getWalletSessionDomain(this.getAuthSessionDeps(), walletId);
    const walletSessionUserId = String(session.login.nearAccountId || walletId).trim();
    return await this.signingEngine.resolveEmailOtpAppSessionJwt({
      walletSession: walletSessionRefFromSession({
        walletId,
        walletSessionUserId,
      }),
      relayUrl: args.relayUrl,
    });
  }

  private async loginWithEmailOtpEcdsaCapabilityDomain(
    args: EmailOtpEcdsaCapabilityArgs,
  ): Promise<EmailOtpEcdsaCapabilityResult> {
    const walletId = args.walletSession.walletId;
    const flowId = this.emailOtpUnlockFlowId(walletId, args.challengeId);
    const chainTarget = requireConcreteEcdsaChainTarget(args.chainTarget, 'Email OTP ECDSA unlock');
    this.emitEmailOtpUnlockEvent(args.onEvent, {
      flowId,
      accountId: walletId,
      authMethod: 'email_otp',
      phase: UnlockEventPhase.STEP_03_EMAIL_OTP_VERIFY_STARTED,
      status: 'running',
      interaction: { kind: 'otp_input', overlay: 'none' },
      ...(args.challengeId ? { requestId: args.challengeId } : {}),
    });
    try {
      if (this.walletIframe.shouldUseWalletIframe()) {
        const router = await this.walletIframe.requireRouter(walletId);
        const iframeArgs = { ...args, chainTarget };
        delete iframeArgs.onEvent;
        const result = await router.loginWithEmailOtpEcdsaCapability(iframeArgs);
        this.emitEmailOtpUnlockEvent(args.onEvent, {
          flowId,
          accountId: walletId,
          authMethod: 'email_otp',
          phase: UnlockEventPhase.STEP_03_EMAIL_OTP_VERIFY_SUCCEEDED,
          status: 'succeeded',
          interaction: { kind: 'otp_input', overlay: 'hide' },
          ...(args.challengeId ? { requestId: args.challengeId } : {}),
        });
        this.emitEmailOtpUnlockEvent(args.onEvent, {
          flowId,
          accountId: walletId,
          authMethod: 'email_otp',
          phase: UnlockEventPhase.STEP_05_ECDSA_SIGNING_SESSION_READY,
          status: 'succeeded',
          ...(args.challengeId ? { requestId: args.challengeId } : {}),
          data: { chainTarget },
        });
        this.emitEmailOtpUnlockEvent(args.onEvent, {
          flowId,
          accountId: walletId,
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
          accountId: walletId,
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
      const ed25519SessionReconstruction =
        await resolveEmailOtpEd25519SessionReconstruction(args);
      const result = await this.signingEngine.loginWithEmailOtpEcdsaCapabilityInternal({
        ...args,
        chainTarget,
        ecdsaBootstrapAuthorization: { kind: 'route_plan_auth' },
        ed25519ReconstructionMode: 'await',
        ed25519SessionReconstruction,
        onProgress: markWorkerProgress,
      });
      await this.signingEngine
        .activateAuthenticatedWalletState({
          nearAccountId: toAccountId(walletId),
          nearClient: this.nearClient,
        })
        .catch(() => undefined);
      await assertWalletRuntimePostconditions({
        source: 'wallet_unlock',
        walletId,
        authMethod: 'email_otp',
        requiredTargets: [
          { curve: 'ed25519' },
          ...configuredEmailOtpEcdsaSnapshotChainTargets(this.configs).map((target) => ({
            curve: 'ecdsa' as const,
            chainTarget: target,
          })),
        ],
        readPersistedAvailableSigningLanes: async (input) =>
          await this.signingEngine.readPersistedAvailableSigningLanes(input),
      });
      emitIfWorkerProgressMissing({
        flowId,
        accountId: walletId,
        authMethod: 'email_otp',
        phase: UnlockEventPhase.STEP_03_EMAIL_OTP_VERIFY_SUCCEEDED,
        status: 'succeeded',
        interaction: { kind: 'otp_input', overlay: 'hide' },
        ...(args.challengeId ? { requestId: args.challengeId } : {}),
      });
      emitIfWorkerProgressMissing({
        flowId,
        accountId: walletId,
        authMethod: 'email_otp',
        phase: UnlockEventPhase.STEP_05_ECDSA_SIGNING_SESSION_READY,
        status: 'succeeded',
        ...(args.challengeId ? { requestId: args.challengeId } : {}),
        data: { chainTarget },
      });
      emitIfWorkerProgressMissing({
        flowId,
        accountId: walletId,
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
        accountId: walletId,
        authMethod: 'email_otp',
        ...(args.challengeId ? { requestId: args.challengeId } : {}),
        error: e,
      });
      throw e;
    }
  }

  private async refreshEmailOtpSigningSessionDomain(args: {
    walletSession: WalletSessionRef;
    chainTarget: ThresholdEcdsaChainTarget;
    challengeId: string;
    otpCode: string;
    ttlMs?: number;
    remainingUses?: number;
    onEvent?: (event: UnlockFlowEvent) => void;
  }): Promise<EmailOtpEcdsaCapabilityResult> {
    const walletId = args.walletSession.walletId;
    const flowId = this.emailOtpUnlockFlowId(walletId, args.challengeId);
    const chainTarget = requireConcreteEcdsaChainTarget(
      args.chainTarget,
      'Email OTP signing-session refresh',
    );
    this.emitEmailOtpUnlockEvent(args.onEvent, {
      flowId,
      accountId: walletId,
      authMethod: 'email_otp',
      phase: UnlockEventPhase.STEP_03_EMAIL_OTP_VERIFY_STARTED,
      status: 'running',
      interaction: { kind: 'otp_input', overlay: 'none' },
      requestId: args.challengeId,
    });
    try {
      const result = this.walletIframe.shouldUseWalletIframe()
        ? await (
            await this.walletIframe.requireRouter(walletId)
          ).refreshEmailOtpSigningSession({
            walletSession: args.walletSession,
            chainTarget,
            challengeId: args.challengeId,
            otpCode: args.otpCode,
            ...(typeof args.ttlMs === 'number' ? { ttlMs: args.ttlMs } : {}),
            ...(typeof args.remainingUses === 'number'
              ? { remainingUses: args.remainingUses }
              : {}),
          })
        : await this.signingEngine.refreshEmailOtpSigningSession({
            walletSession: args.walletSession,
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
        accountId: walletId,
        authMethod: 'email_otp',
        phase: UnlockEventPhase.STEP_03_EMAIL_OTP_VERIFY_SUCCEEDED,
        status: 'succeeded',
        interaction: { kind: 'otp_input', overlay: 'hide' },
        requestId: args.challengeId,
      });
      this.emitEmailOtpUnlockEvent(args.onEvent, {
        flowId,
        accountId: walletId,
        authMethod: 'email_otp',
        phase: UnlockEventPhase.STEP_05_ECDSA_SIGNING_SESSION_READY,
        status: 'succeeded',
        requestId: args.challengeId,
        data: { chainTarget },
      });
      this.emitEmailOtpUnlockEvent(args.onEvent, {
        flowId,
        accountId: walletId,
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
        accountId: walletId,
        authMethod: 'email_otp',
        requestId: args.challengeId,
        error: e,
      });
      throw e;
    }
  }

  private async enrollAndLoginWithEmailOtpEcdsaCapabilityDomain(
    args: EmailOtpEcdsaEnrollmentCapabilityArgs,
  ): Promise<EmailOtpEcdsaEnrollmentCapabilityResult> {
    const walletId = args.walletSession.walletId;
    const flowId = this.emailOtpRegistrationFlowId(walletId, args.challengeId);
    const chainTarget = requireConcreteEcdsaChainTarget(
      args.chainTarget,
      'Email OTP ECDSA enrollment',
    );
    this.emitEmailOtpRegistrationEvent(args.onEvent, {
      flowId,
      accountId: walletId,
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
            '[SeamsWeb] Wallet iframe Email OTP enrollment owns client secret generation; clientSecret32 is not accepted from the app origin.',
          );
        }
        const router = await this.walletIframe.requireRouter(walletId);
        const iframeArgs = { ...args, chainTarget };
        delete iframeArgs.clientSecret32;
        delete iframeArgs.onEvent;
        const result = await router.enrollAndLoginWithEmailOtpEcdsaCapability(iframeArgs);
        this.emitEmailOtpRegistrationEvent(args.onEvent, {
          flowId,
          accountId: walletId,
          authMethod: 'email_otp',
          phase: RegistrationEventPhase.STEP_04_OTP_VERIFY_SUCCEEDED,
          status: 'succeeded',
          interaction: { kind: 'otp_input', overlay: 'hide' },
          ...(args.challengeId ? { requestId: args.challengeId } : {}),
          data: { otpChannel: result.enrollment.otpChannel },
        });
        this.emitEmailOtpRegistrationEvent(args.onEvent, {
          flowId,
          accountId: walletId,
          authMethod: 'email_otp',
          phase: RegistrationEventPhase.STEP_09_EMAIL_OTP_SIGNER_ENROLL_STARTED,
          status: 'running',
          ...(args.challengeId ? { requestId: args.challengeId } : {}),
        });
        this.emitEmailOtpRegistrationEvent(args.onEvent, {
          flowId,
          accountId: walletId,
          authMethod: 'email_otp',
          phase: RegistrationEventPhase.STEP_09_EMAIL_OTP_SIGNER_ENROLL_SUCCEEDED,
          status: 'succeeded',
          ...(args.challengeId ? { requestId: args.challengeId } : {}),
          data: { otpChannel: result.enrollment.otpChannel },
        });
        this.emitEmailOtpRegistrationEvent(args.onEvent, {
          flowId,
          accountId: walletId,
          authMethod: 'email_otp',
          phase: RegistrationEventPhase.STEP_10_ECDSA_SIGNER_PROVISION_STARTED,
          status: 'running',
          ...(args.challengeId ? { requestId: args.challengeId } : {}),
          data: { chainTarget },
        });
        this.emitEmailOtpRegistrationEvent(args.onEvent, {
          flowId,
          accountId: walletId,
          authMethod: 'email_otp',
          phase: RegistrationEventPhase.STEP_10_ECDSA_SIGNER_PROVISION_SUCCEEDED,
          status: 'succeeded',
          ...(args.challengeId ? { requestId: args.challengeId } : {}),
          data: { chainTarget },
        });
        this.emitEmailOtpRegistrationEvent(args.onEvent, {
          flowId,
          accountId: walletId,
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
          accountId: walletId,
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
        accountId: walletId,
        authMethod: 'email_otp',
        phase: RegistrationEventPhase.STEP_04_OTP_VERIFY_SUCCEEDED,
        status: 'succeeded',
        interaction: { kind: 'otp_input', overlay: 'hide' },
        ...(args.challengeId ? { requestId: args.challengeId } : {}),
        data: { otpChannel: result.enrollment.otpChannel },
      });
      emitIfWorkerProgressMissing({
        flowId,
        accountId: walletId,
        authMethod: 'email_otp',
        phase: RegistrationEventPhase.STEP_09_EMAIL_OTP_SIGNER_ENROLL_STARTED,
        status: 'running',
        ...(args.challengeId ? { requestId: args.challengeId } : {}),
      });
      emitIfWorkerProgressMissing({
        flowId,
        accountId: walletId,
        authMethod: 'email_otp',
        phase: RegistrationEventPhase.STEP_09_EMAIL_OTP_SIGNER_ENROLL_SUCCEEDED,
        status: 'succeeded',
        ...(args.challengeId ? { requestId: args.challengeId } : {}),
        data: { otpChannel: result.enrollment.otpChannel },
      });
      emitIfWorkerProgressMissing({
        flowId,
        accountId: walletId,
        authMethod: 'email_otp',
        phase: RegistrationEventPhase.STEP_10_ECDSA_SIGNER_PROVISION_STARTED,
        status: 'running',
        ...(args.challengeId ? { requestId: args.challengeId } : {}),
        data: { chainTarget },
      });
      emitIfWorkerProgressMissing({
        flowId,
        accountId: walletId,
        authMethod: 'email_otp',
        phase: RegistrationEventPhase.STEP_10_ECDSA_SIGNER_PROVISION_SUCCEEDED,
        status: 'succeeded',
        ...(args.challengeId ? { requestId: args.challengeId } : {}),
        data: { chainTarget },
      });
      this.emitEmailOtpRegistrationEvent(args.onEvent, {
        flowId,
        accountId: walletId,
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
        accountId: walletId,
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
            chainTarget: input.chainTarget,
            walletSession: input.walletSession,
            options: resolvedOptions,
          };
    const routerAccountId =
      resolvedInput.kind === 'near'
        ? resolvedInput.nearAccount.accountId
        : String(
            resolvedInput.walletSession.walletSessionUserId || resolvedInput.walletSession.walletId,
          ).trim();
    if (!routerAccountId) {
      throw new Error('[SeamsWeb] key export requires wallet session user context');
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
  private async deleteDeviceKeyDomain(
    accountId: string,
    publicKeyToDelete: string,
    options: ActionHooksOptions,
  ): Promise<ActionResult> {
    // Validate that we're not deleting the last key
    const keysView = await this.viewAccessKeyListDomain(accountId);
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
      nearAccount: nearAccountRefFromAccountId(accountId),
      receiverId: accountId,
      actionArgs: {
        type: ActionType.DeleteKey,
        publicKey: publicKeyToDelete,
      },
      options: options,
    });
  }
}
