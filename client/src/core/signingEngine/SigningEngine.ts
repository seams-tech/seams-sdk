import {
  getLastSelectedNearAccountProjection,
  getNearAccountProjection,
  listNearAccountProjections,
} from '../accountData/near/accountProjection';
import { buildNearAccountRefs } from '../accountData/near/accountRefs';
import { getNearThresholdKeyMaterial } from '../accountData/near/keyMaterial';
import type { ClientAuthenticatorData, ClientUserData, StoreUserDataInput } from '../accountData/near/types';
import { resolveProfileAccountContextFromCandidates } from '../indexedDB/profileAccountProjection';
import type { ProfileAuthenticatorRecord } from '../indexedDB/passkeyClientDB.types';
import type { NearClient, SignedTransaction } from '../rpcClients/near/NearClient';
import type { NonceManager } from '../rpcClients/near/nonceManager';
import { toAccountId, type AccountId } from '../types/accountIds';
import type { ActionArgsWasm } from '../types/actions';
import type { AuthenticatorOptions } from '../types/authenticatorOptions';
import type { ConfirmationConfig } from '../types/signer-worker';
import type {
  EmailOtpAuthPolicy,
  SigningSessionStatus,
  TatchiConfigsReadonly,
  ThemeName,
} from '../types/tatchi';
import type { WebAuthnAuthenticationCredential, WebAuthnRegistrationCredential } from '../types';
import type { UserPreferencesManager } from './api/userPreferences';
import type {
  ThresholdEcdsaCanonicalExportArtifact,
  ThresholdEcdsaSecp256k1KeyRef,
} from './interfaces/signing';
import type {
  ThresholdEcdsaActivationChain,
  ThresholdEcdsaSessionBootstrapResult,
} from './orchestration/thresholdActivation';
import type { SignerWorkerManager } from './workerManager';
import type { RegistrationCredentialConfirmationPayload } from './workerManager/validation';
import type {
  TouchConfirmRuntimeBridgePort,
  WarmSessionMaterialClearAll,
  WarmSessionClaimResult,
  WarmSessionStatusResult,
} from './touchConfirm/types';
import type { WarmSessionStatusBatchResult } from '../types/secure-confirm-worker';
import {
  UserConfirmationType,
  type ExportPrivateKeyDisplayEntry,
} from './touchConfirm/shared/confirmTypes';
import type { TouchIdPrompt } from './signers/webauthn/prompt/touchIdPrompt';
import type { WebAuthnAllowCredential } from './signers/webauthn/credentials';
import type { EvmSigningRequest } from './chainAdaptors/evm/types';
import type { EvmSignedResult } from './chainAdaptors/evm/evmAdapter';
import type { TempoSigningRequest } from './chainAdaptors/tempo/types';
import type { TempoSignedResult } from './chainAdaptors/tempo/tempoAdapter';
import { getPrfResultsFromCredential } from './signers/webauthn/credentials/credentialExtensions';
import {
  bootstrapEcdsaSessionValue,
} from './api/thresholdLifecycle/thresholdSessionActivation';
import {
  buildThresholdEd25519SeedExportArtifactFromHssReport as buildThresholdEd25519SeedExportArtifactFromHssReportValue,
  completeThresholdEd25519HssClientCeremony as completeThresholdEd25519HssClientCeremonyValue,
  deriveThresholdEd25519ClientVerifyingShareFromCredential as deriveThresholdEd25519ClientVerifyingShareFromCredentialValue,
  deriveThresholdEd25519HssClientInputsFromCredential as deriveThresholdEd25519HssClientInputsFromCredentialValue,
  openThresholdEd25519HssSeedOutput as openThresholdEd25519HssSeedOutputValue,
  prepareThresholdEd25519HssClientCeremonyFromCredential as prepareThresholdEd25519HssClientCeremonyFromCredentialValue,
  runThresholdEd25519HssCeremonyWithSession as runThresholdEd25519HssCeremonyWithSessionValue,
} from './api/thresholdLifecycle/thresholdEd25519Lifecycle';
import {
  persistThresholdEcdsaBootstrapChainAccount as persistThresholdEcdsaBootstrapChainAccountValue,
  type ThresholdEcdsaSmartAccountBootstrapInput,
} from './api/thresholdLifecycle/thresholdEcdsaBootstrapPersistence';
import {
  clearAllThresholdEcdsaSessionRecords as clearAllThresholdEcdsaSessionRecordsValue,
  clearThresholdEcdsaSessionRecordForLane as clearThresholdEcdsaSessionRecordForLaneValue,
  clearThresholdEcdsaSessionRecordForAccount as clearThresholdEcdsaSessionRecordForAccountValue,
  getThresholdEcdsaKeyRefForSigning as getThresholdEcdsaKeyRefForSigningValue,
  getThresholdEcdsaSessionRecordForSigning as getThresholdEcdsaSessionRecordForSigningValue,
  getStoredThresholdEd25519SessionRecordForAccount as getStoredThresholdEd25519SessionRecordForAccountValue,
  markThresholdEcdsaEmailOtpSessionConsumedForAccount as markThresholdEcdsaEmailOtpSessionConsumedForAccountValue,
  upsertThresholdEcdsaSessionFromBootstrap as upsertThresholdEcdsaSessionFromBootstrapValue,
  type ThresholdEcdsaEmailOtpAuthContext,
  type ThresholdEcdsaSessionRecord,
  type ThresholdEcdsaSessionStoreSource,
} from './api/thresholdLifecycle/thresholdSessionStore';
import {
  scheduleThresholdEcdsaLoginPresignPrefill as scheduleThresholdEcdsaLoginPresignPrefillValue,
  type ThresholdEcdsaLoginPrefillResult,
} from './api/thresholdLifecycle/thresholdEcdsaLoginPrefill';
import { clearThresholdEcdsaClientPresignaturesForLane } from './orchestration/walletOrigin/thresholdEcdsaCoordinator';
import {
  signNear as signNearValue,
  type NearSignIntentRequest,
  type NearSignIntentResult,
  type SignTransactionsWithActionsInput,
} from './api/nearSigning';
import {
  reconcileTempoNonceLane as reconcileTempoNonceLaneValue,
  reportTempoBroadcastAccepted as reportTempoBroadcastAcceptedValue,
  reportTempoBroadcastRejected as reportTempoBroadcastRejectedValue,
  reportTempoDroppedOrReplaced as reportTempoDroppedOrReplacedValue,
  reportTempoFinalized as reportTempoFinalizedValue,
  signTempo as signTempoValue,
  type ReconcileTempoNonceLaneArgs,
  type ReportTempoBroadcastAcceptedArgs,
  type ReportTempoBroadcastRejectedArgs,
  type ReportTempoDroppedOrReplacedArgs,
  type ReportTempoFinalizedArgs,
  type TempoNonceLaneStatus,
} from './api/tempoSigning';
import {
  cacheSigningSessionPrfFirst as cacheSigningSessionPrfFirstValue,
  clearSigningSessionPrfFirstBestEffort as clearSigningSessionPrfFirstBestEffortValue,
  generateSessionId as generateSessionIdValue,
} from './api/session/signingSessionState';
import {
  clearThresholdEcdsaCommitQueue,
  withThresholdEcdsaCommitQueue,
  type ThresholdEcdsaCommitQueueByKey,
} from './api/thresholdLifecycle/thresholdEcdsaCommitQueue';
import {
  clearThresholdEd25519CommitQueue,
  withThresholdEd25519CommitQueue,
  type ThresholdEd25519CommitQueueByKey,
} from './api/thresholdLifecycle/thresholdEd25519CommitQueue';
import {
  exportNearEd25519SeedArtifactWithUI as exportNearEd25519SeedArtifactWithUIValue,
} from './api/recovery/privateKeyExportRecovery';
import { getLastLoggedInDeviceNumber } from './signers/webauthn/device/getDeviceNumber';
import { removeExportViewerHostIfPresent } from './touchConfirm/ui/export-viewer-host';
import {
  thresholdEcdsaHssFinalize,
  thresholdEcdsaHssPrepare,
  thresholdEcdsaHssRespond,
} from '../rpcClients/relayer/thresholdEcdsa';
import {
  getAuthenticationCredentialsSerialized as getAuthenticationCredentialsSerializedValue,
  requestRegistrationCredentialConfirmation as requestRegistrationCredentialConfirmationValue,
} from './api/registration/registrationSession';
import {
  atomicStoreRegistrationData as atomicStoreRegistrationDataValue,
  hasPasskeyCredential as hasPasskeyCredentialValue,
  initializeCurrentUser as initializeCurrentUserValue,
  rollbackUserRegistration as rollbackUserRegistrationValue,
  storeAuthenticator as storeAuthenticatorValue,
  storeUserData as storeUserDataValue,
  type StoreAuthenticatorInput,
} from './api/registration/registrationAccountLifecycle';
import { initializeRuntimeBootstrap } from './bootstrap/runtimeBootstrap';
import { createManagerAssembly } from './bootstrap/managerAssembly';
import { verifySealedRefreshStartupParity } from '../rpcClients/relayer/sealedRefreshCapabilities';
import {
  createWarmSessionManager,
  type WarmSessionSensitiveOperationPolicy,
} from './session/WarmSessionManager';
import type { WarmSessionEcdsaCapabilityState } from './session/warmSessionTypes';
import type {
  ProvisionWarmEd25519CapabilityArgs,
  ProvisionWarmEd25519CapabilityResult,
} from './session/WarmSessionManager';
import {
  deriveThresholdEd25519HssClientInputsWasm,
  finalizeThresholdEcdsaHssClientRequestWasm,
  prepareThresholdEcdsaHssClientRequestWasm,
  prepareThresholdEcdsaHssSessionWasm,
  prepareThresholdEd25519HssClientRequestWasm,
  prepareThresholdEd25519HssSessionWasm,
} from './signers/wasm/hssClientSignerWasm';
import {
  createThresholdEcdsaHssHiddenEvalFinalizeMessage,
  encodeThresholdEcdsaHssHiddenEvalRequestMessage,
  parseThresholdEcdsaHssHiddenEvalServerResponseMessage,
} from './threshold/workflows/thresholdEcdsaHssTransport';
import { connectEd25519Session } from './threshold/workflows/connectEd25519Session';
import {
  THRESHOLD_ED25519_HSS_DERIVATION_VERSION,
  THRESHOLD_ED25519_HSS_SIGNING_KEY_PURPOSE,
} from './orchestration/near/shared/ensureThresholdEd25519HssClientBase';
import {
  createOrchestrationDependencyBundle,
  type OrchestrationDependencyBundle,
} from './bootstrap/orchestrationDependencyFactory';
import { enrollEmailOtpWallet } from '../TatchiPasskey/emailOtp';

export type {
  ThresholdEcdsaActivationChain,
  ThresholdEcdsaSessionBootstrapResult,
} from './orchestration/thresholdActivation';
export type { NearSignIntentRequest, NearSignIntentResult } from './api/nearSigning';
export type { ThresholdEcdsaLoginPrefillResult } from './api/thresholdLifecycle/thresholdEcdsaLoginPrefill';

type EmailOtpBootstrapRecovery = {
  loginGrant: string;
  challengeId: string;
  emailOtpKeyVersion: string;
  unlockChallengeId: string;
  unlockChallengeB64u: string;
  unlockPublicKeyB64u: string;
  unlockSignatureB64u: string;
};

function hasWarmSessionMaterialClearAll(
  value: unknown,
): value is WarmSessionMaterialClearAll {
  return (
    typeof (value as { clearAllWarmSessionMaterial?: unknown })
      ?.clearAllWarmSessionMaterial === 'function'
  );
}

function createExportUiRequestId(prefix: string): string {
  const randomPart =
    typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
      ? crypto.randomUUID()
      : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  return `${prefix}-${randomPart}`;
}

function mapProfileAuthenticatorToClient(
  profileAuthenticator: ProfileAuthenticatorRecord,
  nearAccountId: AccountId,
): ClientAuthenticatorData {
  return {
    nearAccountId,
    deviceNumber: profileAuthenticator.deviceNumber,
    credentialId: profileAuthenticator.credentialId,
    credentialPublicKey: profileAuthenticator.credentialPublicKey,
    transports: profileAuthenticator.transports,
    name: profileAuthenticator.name,
    registered: profileAuthenticator.registered,
    syncedAt: profileAuthenticator.syncedAt,
  };
}

/**
 * SigningEngine is the signing composition root:
 * - owns bootstrap/lifecycle for worker managers
 * - exposes direct public signing/session/recovery/persistence methods
 * - keeps only shared runtime/config helpers and orchestration deps internally
 */
export class SigningEngine {
  // Kept as fields for low-level tests that intentionally access internals.
  private readonly touchConfirm: TouchConfirmRuntimeBridgePort;
  private readonly signerWorkerManager: SignerWorkerManager;
  private readonly touchIdPrompt: TouchIdPrompt;
  private readonly userPreferencesManager: UserPreferencesManager;
  private readonly nearClient: NearClient;
  private readonly nonceManager: NonceManager;
  private workerBaseOrigin: string = '';
  private theme: ThemeName = 'dark';
  private readonly thresholdEcdsaBootstrapQueueByAccount: Map<string, Promise<void>> = new Map();
  private readonly thresholdEcdsaCommitQueueByKey: ThresholdEcdsaCommitQueueByKey = new Map();
  private readonly thresholdEd25519CommitQueueByKey: ThresholdEd25519CommitQueueByKey = new Map();
  private readonly thresholdEcdsaSessionByLane: Map<string, ThresholdEcdsaSessionRecord> =
    new Map();
  private readonly thresholdEcdsaExportArtifactByLane: Map<
    string,
    ThresholdEcdsaCanonicalExportArtifact
  > = new Map();
  private readonly sealedRefreshStartupParityPromise: Promise<void>;
  private sealedRefreshStartupParityError: Error | null = null;
  private readonly orchestrationDeps: OrchestrationDependencyBundle;

  readonly tatchiPasskeyConfigs: TatchiConfigsReadonly;

  constructor(tatchiPasskeyConfigs: TatchiConfigsReadonly, nearClient: NearClient) {
    this.tatchiPasskeyConfigs = tatchiPasskeyConfigs;
    this.nearClient = nearClient;
    this.sealedRefreshStartupParityPromise = verifySealedRefreshStartupParity({
      configs: this.tatchiPasskeyConfigs,
    }).catch((error: unknown) => {
      this.sealedRefreshStartupParityError =
        error instanceof Error
          ? error
          : new Error(String(error || 'sealed refresh parity check failed'));
    });

    const assembly = createManagerAssembly({
      tatchiPasskeyConfigs: this.tatchiPasskeyConfigs,
      nearClient: this.nearClient,
      getTheme: () => this.theme,
      getAppearanceTokens: () => this.tatchiPasskeyConfigs.ui.appearance?.tokens,
    });

    this.touchIdPrompt = assembly.touchIdPrompt;
    this.userPreferencesManager = assembly.userPreferencesManager;
    this.nonceManager = assembly.nonceManager;
    this.signerWorkerManager = assembly.signerWorkerManager;
    this.touchConfirm = this.createWarmSessionAwareTouchConfirm(assembly.touchConfirm);

    this.orchestrationDeps = createOrchestrationDependencyBundle({
      tatchiPasskeyConfigs: this.tatchiPasskeyConfigs,
      nearClient: this.nearClient,
      touchIdPrompt: this.touchIdPrompt,
      userPreferencesManager: this.userPreferencesManager,
      nonceManager: this.nonceManager,
      evmNonceManager: assembly.evmNonceManager,
      touchConfirm: this.touchConfirm,
      signerWorkerManager: this.signerWorkerManager,
      getWorkerBaseOrigin: () => this.workerBaseOrigin,
      getTheme: () => this.theme,
      signTempo: (args) => this.signTempo(args),
      extractCosePublicKey: (attestationObjectBase64url: string) =>
        this.extractCosePublicKey(attestationObjectBase64url),
      initializeCurrentUser: (nearAccountId: AccountId, nearClientArg?: NearClient) =>
        this.initializeCurrentUser(nearAccountId, nearClientArg),
      persistThresholdEcdsaBootstrapChainAccount: (args) =>
        this.persistThresholdEcdsaBootstrapChainAccount(args),
      upsertThresholdEcdsaSessionFromBootstrap: (args) =>
        this.upsertThresholdEcdsaSessionFromBootstrap(args),
      getThresholdEcdsaKeyRefForSigning: (args) => this.getThresholdEcdsaKeyRefForSigning(args),
      getThresholdEcdsaSessionRecordForSigning: (args) =>
        this.getThresholdEcdsaSessionRecordForSigning(args),
      markThresholdEcdsaEmailOtpSessionConsumedForAccount: (args) =>
        this.markThresholdEcdsaEmailOtpSessionConsumedForAccount(args),
      clearThresholdEcdsaSessionRecordForLane: (args) =>
        this.clearThresholdEcdsaSessionRecordForLane(args),
      provisionThresholdEcdsaSession: (args) => this.bootstrapEcdsaSession(args),
      withThresholdEcdsaCommitQueue: (queueArgs) => this.withThresholdEcdsaCommitQueue(queueArgs),
      withThresholdEd25519CommitQueue: (queueArgs) =>
        this.withThresholdEd25519CommitQueue(queueArgs),
    });

    initializeRuntimeBootstrap({
      tatchiPasskeyConfigs: this.tatchiPasskeyConfigs,
      userPreferencesManager: this.userPreferencesManager,
      getWorkerBaseOrigin: () => this.workerBaseOrigin,
      setWorkerBaseOrigin: (origin: string) => {
        this.workerBaseOrigin = origin;
        this.signerWorkerManager.setWorkerBaseOrigin(origin);
        this.touchConfirm.setWorkerBaseOrigin?.(origin);
      },
    });
  }

  private createWarmSessionAwareTouchConfirm(
    base: TouchConfirmRuntimeBridgePort,
  ): TouchConfirmRuntimeBridgePort {
    const getWarmSessionStatus = async (args: {
      sessionId: string;
    }): Promise<WarmSessionStatusResult> => {
      const primary = await base.getWarmSessionStatus(args);
      if (primary.ok || primary.code !== 'not_found') return primary;
      const secondary = await this.getEmailOtpWarmSessionStatus(args.sessionId);
      return secondary.ok || secondary.code !== 'not_found' ? secondary : primary;
    };

    const getWarmSessionStatuses = async (args: {
      sessionIds: string[];
    }): Promise<WarmSessionStatusBatchResult> => {
      const primary =
        typeof base.getWarmSessionStatuses === 'function'
          ? await base.getWarmSessionStatuses(args)
          : {
              results: await Promise.all(
                args.sessionIds.map(async (sessionId) => ({
                  sessionId,
                  result: await base.getWarmSessionStatus({ sessionId }),
                })),
              ),
            };
      const results = await Promise.all(
        primary.results.map(async (entry) => {
          if (entry.result.ok || entry.result.code !== 'not_found') return entry;
          const fallback = await this.getEmailOtpWarmSessionStatus(entry.sessionId);
          return {
            sessionId: entry.sessionId,
            result: fallback.ok || fallback.code !== 'not_found' ? fallback : entry.result,
          };
        }),
      );
      return { results };
    };

    const claimWarmSessionMaterial = async (args: {
      sessionId: string;
      uses?: number;
    }): Promise<WarmSessionClaimResult> => {
      const primary = await base.claimWarmSessionMaterial(args);
      if (primary.ok || primary.code !== 'not_found') return primary;
      const secondary = await this.claimEmailOtpWarmSessionMaterial(args);
      return secondary.ok || secondary.code !== 'not_found' ? secondary : primary;
    };

    const clearWarmSessionMaterial = async (args: { sessionId: string }): Promise<void> => {
      await Promise.all([
        base.clearWarmSessionMaterial(args).catch(() => undefined),
        this.clearEmailOtpWarmSessionMaterial(args.sessionId).catch(() => undefined),
      ]);
    };

    return new Proxy(base, {
      get: (target, prop, receiver) => {
        if (prop === 'getWarmSessionStatus') return getWarmSessionStatus;
        if (prop === 'getWarmSessionStatuses') return getWarmSessionStatuses;
        if (prop === 'claimWarmSessionMaterial') return claimWarmSessionMaterial;
        if (prop === 'clearWarmSessionMaterial') return clearWarmSessionMaterial;
        const value = Reflect.get(target, prop, receiver);
        return typeof value === 'function' ? value.bind(target) : value;
      },
    }) as TouchConfirmRuntimeBridgePort;
  }

  private async getEmailOtpWarmSessionStatus(
    sessionId: string,
  ): Promise<WarmSessionStatusResult> {
    const normalizedSessionId = String(sessionId || '').trim();
    if (!normalizedSessionId) {
      return { ok: false, code: 'invalid_args', message: 'Missing sessionId' };
    }
    try {
      return await this.signerWorkerManager.requestWorkerOperation({
        kind: 'emailOtp',
        request: {
          type: 'getEmailOtpWarmSessionStatus',
          timeoutMs: 5_000,
          payload: { sessionId: normalizedSessionId },
        },
      });
    } catch (error) {
      return {
        ok: false,
        code: 'worker_error',
        message: error instanceof Error ? error.message : String(error || 'Email OTP worker error'),
      };
    }
  }

  private async claimEmailOtpWarmSessionMaterial(args: {
    sessionId: string;
    uses?: number;
  }): Promise<WarmSessionClaimResult> {
    const normalizedSessionId = String(args.sessionId || '').trim();
    if (!normalizedSessionId) {
      return { ok: false, code: 'invalid_args', message: 'Missing sessionId' };
    }
    try {
      return await this.signerWorkerManager.requestWorkerOperation({
        kind: 'emailOtp',
        request: {
          type: 'claimEmailOtpWarmSessionMaterial',
          timeoutMs: 5_000,
          payload: {
            sessionId: normalizedSessionId,
            ...(typeof args.uses === 'number' ? { uses: args.uses } : {}),
          },
        },
      });
    } catch (error) {
      return {
        ok: false,
        code: 'worker_error',
        message: error instanceof Error ? error.message : String(error || 'Email OTP worker error'),
      };
    }
  }

  private async clearEmailOtpWarmSessionMaterial(sessionId: string): Promise<void> {
    const normalizedSessionId = String(sessionId || '').trim();
    if (!normalizedSessionId) return;
    await this.signerWorkerManager
      .requestWorkerOperation({
        kind: 'emailOtp',
        request: {
          type: 'clearEmailOtpWarmSessionMaterial',
          timeoutMs: 5_000,
          payload: { sessionId: normalizedSessionId },
        },
      })
      .catch(() => undefined);
  }

  private async ensureSealedRefreshStartupParity(): Promise<void> {
    await this.sealedRefreshStartupParityPromise;
    if (this.sealedRefreshStartupParityError) {
      throw this.sealedRefreshStartupParityError;
    }
  }

  async assertSealedRefreshStartupParity(): Promise<void> {
    await this.ensureSealedRefreshStartupParity();
  }

  private async ensureSealedRefreshStartupParityForThresholdEcdsaBootstrap(
    args: Parameters<typeof bootstrapEcdsaSessionValue>[1],
  ): Promise<void> {
    try {
      await this.ensureSealedRefreshStartupParity();
    } catch (error: unknown) {
      if (args.source === 'registration') {
        const message = error instanceof Error ? error.message : String(error || 'unknown error');
        console.warn(
          '[threshold-ecdsa] registration bootstrap skipped sealed-refresh startup parity enforcement',
          {
            nearAccountId: String(args.nearAccountId || '').trim(),
            chain: args.chain || 'tempo',
            error: message,
          },
        );
        return;
      }
      throw error;
    }
  }

  private async withThresholdEcdsaBootstrapQueue<T>(
    nearAccountId: AccountId,
    task: () => Promise<T>,
  ): Promise<T> {
    const accountKey = String(toAccountId(String(nearAccountId || '').trim()));
    const previous =
      this.thresholdEcdsaBootstrapQueueByAccount.get(accountKey) || Promise.resolve();
    const waitForPrevious = previous.catch(() => undefined);

    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const next = waitForPrevious.then(() => gate);
    this.thresholdEcdsaBootstrapQueueByAccount.set(accountKey, next);

    await waitForPrevious;
    try {
      return await task();
    } finally {
      release();
      if (this.thresholdEcdsaBootstrapQueueByAccount.get(accountKey) === next) {
        this.thresholdEcdsaBootstrapQueueByAccount.delete(accountKey);
      }
    }
  }

  prewarmSignerWorkers(): void {
    this.orchestrationDeps.getManagerConvenienceDeps().prewarmSignerWorkers();
  }

  async warmCriticalResources(nearAccountId?: string): Promise<void> {
    await this.ensureSealedRefreshStartupParity();
    await this.orchestrationDeps.getManagerConvenienceDeps().warmCriticalResources(nearAccountId);
  }

  getRpId(): string {
    return this.touchIdPrompt.getRpId();
  }

  getNonceManager(): NonceManager {
    return this.nonceManager;
  }

  setTheme(next: ThemeName): void {
    if (next !== 'light' && next !== 'dark') return;
    this.theme = next;
  }

  getTheme(): ThemeName {
    return this.theme;
  }

  getUserPreferences(): UserPreferencesManager {
    return this.userPreferencesManager;
  }

  async signNear<TRequest extends NearSignIntentRequest>(
    request: TRequest,
  ): Promise<NearSignIntentResult<TRequest>> {
    return await signNearValue(this.orchestrationDeps.nearSigningDeps, request);
  }

  async signTempo(args: {
    nearAccountId: string;
    request: TempoSigningRequest | EvmSigningRequest;
    confirmationConfigOverride?: Partial<ConfirmationConfig>;
    shouldAbort?: () => boolean;
    onEvent?: (event: {
      step: number;
      phase: string;
      status: 'progress' | 'success' | 'error';
      message?: string;
      data?: unknown;
    }) => void;
  }): Promise<TempoSignedResult | EvmSignedResult> {
    await this.ensureSealedRefreshStartupParity();
    return await signTempoValue(this.orchestrationDeps.tempoSigningDeps, args);
  }

  async reportTempoBroadcastAccepted(args: ReportTempoBroadcastAcceptedArgs): Promise<void> {
    await reportTempoBroadcastAcceptedValue(this.orchestrationDeps.tempoSigningDeps, args);
  }

  async reportTempoBroadcastRejected(args: ReportTempoBroadcastRejectedArgs): Promise<void> {
    await reportTempoBroadcastRejectedValue(this.orchestrationDeps.tempoSigningDeps, args);
  }

  async reportTempoFinalized(args: ReportTempoFinalizedArgs): Promise<void> {
    await reportTempoFinalizedValue(this.orchestrationDeps.tempoSigningDeps, args);
  }

  async reportTempoDroppedOrReplaced(args: ReportTempoDroppedOrReplacedArgs): Promise<void> {
    await reportTempoDroppedOrReplacedValue(this.orchestrationDeps.tempoSigningDeps, args);
  }

  async reconcileTempoNonceLane(args: ReconcileTempoNonceLaneArgs): Promise<TempoNonceLaneStatus> {
    return await reconcileTempoNonceLaneValue(this.orchestrationDeps.tempoSigningDeps, args);
  }

  storeUserData(userData: StoreUserDataInput): Promise<void> {
    return storeUserDataValue(this.orchestrationDeps.registrationAccountLifecycleDeps, userData);
  }

  getAllUsers(): Promise<ClientUserData[]> {
    return listNearAccountProjections(this.orchestrationDeps.indexedDB.clientDB);
  }

  getUserByDevice(nearAccountId: AccountId, deviceNumber: number): Promise<ClientUserData | null> {
    return getNearAccountProjection(
      this.orchestrationDeps.indexedDB.clientDB,
      nearAccountId,
      deviceNumber,
    );
  }

  getLastUser(): Promise<ClientUserData | null> {
    return getLastSelectedNearAccountProjection(this.orchestrationDeps.indexedDB.clientDB);
  }

  getAuthenticatorsByUser(nearAccountId: AccountId): Promise<ClientAuthenticatorData[]> {
    return (async () => {
      const accountId = toAccountId(nearAccountId);
      const context = await resolveProfileAccountContextFromCandidates(
        this.orchestrationDeps.indexedDB.clientDB,
        buildNearAccountRefs(accountId),
      ).catch(() => null);
      if (!context?.profileId) return [];
      const rows = await this.orchestrationDeps.indexedDB.clientDB.listProfileAuthenticators(
        context.profileId,
      );
      return rows.map((row) => mapProfileAuthenticatorToClient(row, accountId));
    })();
  }

  updateLastLogin(nearAccountId: AccountId): Promise<void> {
    return (async () => {
      const accountId = toAccountId(nearAccountId);
      const context = await resolveProfileAccountContextFromCandidates(
        this.orchestrationDeps.indexedDB.clientDB,
        buildNearAccountRefs(accountId),
      ).catch(() => null);
      if (!context?.profileId) return;
      const [lastProfileState, profile] = await Promise.all([
        this.orchestrationDeps.indexedDB.clientDB.getLastProfileState().catch(() => null),
        this.orchestrationDeps.indexedDB.clientDB.getProfile(context.profileId).catch(() => null),
      ]);
      const defaultDeviceNumber = Number(profile?.defaultDeviceNumber);
      const deviceNumber =
        lastProfileState?.profileId === context.profileId
          ? lastProfileState.deviceNumber
          : Number.isSafeInteger(defaultDeviceNumber) && defaultDeviceNumber >= 1
            ? defaultDeviceNumber
            : 1;
      await this.orchestrationDeps.indexedDB.clientDB.setLastProfileStateForProfile(
        context.profileId,
        deviceNumber,
      );
    })();
  }

  setLastUser(nearAccountId: AccountId, deviceNumber: number = 1): Promise<void> {
    return (async () => {
      const normalizedDeviceNumber = Number(deviceNumber);
      if (!Number.isSafeInteger(normalizedDeviceNumber) || normalizedDeviceNumber < 1) {
        throw new Error('PasskeyClientDB: deviceNumber must be an integer >= 1');
      }
      const accountId = toAccountId(nearAccountId);
      const context = await resolveProfileAccountContextFromCandidates(
        this.orchestrationDeps.indexedDB.clientDB,
        buildNearAccountRefs(accountId),
      ).catch(() => null);
      if (!context?.profileId) {
        throw new Error(
          `PasskeyClientDB: Missing profile/account mapping for NEAR account ${String(accountId)}`,
        );
      }
      await this.orchestrationDeps.indexedDB.clientDB.setLastProfileStateForProfile(
        context.profileId,
        normalizedDeviceNumber,
      );
    })();
  }

  initializeCurrentUser(nearAccountId: AccountId, nearClientArg?: NearClient): Promise<void> {
    return initializeCurrentUserValue(this.orchestrationDeps.registrationAccountLifecycleDeps, {
      nearAccountId,
      nearClient: nearClientArg,
    });
  }

  storeAuthenticator(authenticatorData: StoreAuthenticatorInput): Promise<void> {
    return storeAuthenticatorValue(
      this.orchestrationDeps.registrationAccountLifecycleDeps,
      authenticatorData,
    );
  }

  rollbackUserRegistration(nearAccountId: AccountId): Promise<void> {
    return rollbackUserRegistrationValue(
      this.orchestrationDeps.registrationAccountLifecycleDeps,
      nearAccountId,
    );
  }

  hasPasskeyCredential(nearAccountId: AccountId): Promise<boolean> {
    return hasPasskeyCredentialValue(
      this.orchestrationDeps.registrationAccountLifecycleDeps,
      nearAccountId,
    );
  }

  atomicStoreRegistrationData(args: {
    nearAccountId: AccountId;
    credential: WebAuthnRegistrationCredential;
    operationalPublicKey: string;
  }): Promise<void> {
    return atomicStoreRegistrationDataValue(
      this.orchestrationDeps.registrationAccountLifecycleDeps,
      args,
    );
  }

  requestRegistrationCredentialConfirmation(params: {
    nearAccountId: string;
    deviceNumber: number;
    confirmerText?: { title?: string; body?: string };
    confirmationConfigOverride?: Partial<ConfirmationConfig>;
  }): Promise<RegistrationCredentialConfirmationPayload> {
    return requestRegistrationCredentialConfirmationValue(
      this.orchestrationDeps.registrationSessionDeps,
      params,
    );
  }

  getAuthenticationCredentialsSerialized(args: {
    nearAccountId: AccountId;
    challengeB64u: string;
    allowCredentials: WebAuthnAllowCredential[];
    includeSecondPrfOutput?: boolean;
  }): Promise<WebAuthnAuthenticationCredential> {
    return getAuthenticationCredentialsSerializedValue(
      this.orchestrationDeps.registrationSessionDeps,
      args,
    );
  }

  extractCosePublicKey(attestationObjectBase64url: string): Promise<Uint8Array> {
    return this.orchestrationDeps.nearKeyOpsDeps.signingKeyOps.extractCosePublicKey(
      attestationObjectBase64url,
    );
  }

  exportKeypairWithUI(
    nearAccountId: AccountId,
    options: {
      chain: 'near' | 'evm' | 'tempo';
      variant?: 'drawer' | 'modal';
      theme?: 'dark' | 'light';
    },
  ): Promise<{ accountId: string; exportedSchemes: Array<'ed25519' | 'secp256k1'> }> {
    return this.exportKeypairWithUIInternal({
      nearAccountId,
      options,
    });
  }

  private async exportKeypairWithUIInternal(args: {
    nearAccountId: AccountId;
    options: {
      chain: 'near' | 'evm' | 'tempo';
      variant?: 'drawer' | 'modal';
      theme?: 'dark' | 'light';
    };
  }): Promise<{ accountId: string; exportedSchemes: Array<'ed25519' | 'secp256k1'> }> {
    if (args.options.chain === 'near') {
      const optionAResult = await this.tryExportNearEd25519OptionAWithAuthorization({
        nearAccountId: args.nearAccountId,
        options: {
          variant: args.options.variant,
          theme: args.options.theme,
        },
      });
      if (optionAResult) return optionAResult;
      throw new Error('NEAR Ed25519 export now requires the canonical Option A HSS export path');
    }

    const thresholdEcdsaKeyRef = this.getThresholdEcdsaKeyRefForSigning({
      nearAccountId: args.nearAccountId,
      chain: args.options.chain === 'tempo' ? 'tempo' : 'evm',
    });
    return await this.exportThresholdEcdsaKeyWithAuthorization({
      nearAccountId: args.nearAccountId,
      chain: args.options.chain === 'tempo' ? 'tempo' : 'evm',
      keyRef: thresholdEcdsaKeyRef,
      options: {
        variant: args.options.variant,
        theme: args.options.theme,
      },
    });
  }

  private async exportThresholdEcdsaKeyWithAuthorization(args: {
    nearAccountId: AccountId;
    chain: 'evm' | 'tempo';
    keyRef: ThresholdEcdsaSecp256k1KeyRef;
    options: {
      variant?: 'drawer' | 'modal';
      theme?: 'dark' | 'light';
    };
  }): Promise<{ accountId: string; exportedSchemes: Array<'ed25519' | 'secp256k1'> }> {
    await createWarmSessionManager({
      touchConfirm: this.touchConfirm,
      clearThresholdEcdsaSigningArtifactsForLane: ({ nearAccountId, chain }) =>
        this.clearThresholdEcdsaSigningArtifactsForLane({ nearAccountId, chain }),
      clearThresholdEcdsaSessionRecordForLane: ({ nearAccountId, chain }) =>
        this.clearThresholdEcdsaSessionRecordForLane({ nearAccountId, chain }),
      getThresholdEcdsaSessionRecordForSigning: ({ nearAccountId, chain }) =>
        this.getThresholdEcdsaSessionRecordForSigning({ nearAccountId, chain }),
    }).assertEcdsaOperationAllowed({
      nearAccountId: args.nearAccountId,
      chain: args.chain,
      thresholdSessionId: args.keyRef.thresholdSessionId,
      operationLabel: 'threshold-ecdsa key export',
      sensitivePolicy: 'passkey',
    });
    const rpId = String(this.getRpId() || '').trim();
    if (!rpId) {
      throw new Error('Missing rpId for threshold-ecdsa explicit export');
    }
    let thresholdEcdsaKeyRef = args.keyRef;
    const exportPublicKey =
      String(thresholdEcdsaKeyRef.ecdsaHssExportArtifact?.publicKeyHex || '').trim() ||
      String(thresholdEcdsaKeyRef.ecdsaThresholdKeyId || '').trim() ||
      String(thresholdEcdsaKeyRef.ethereumAddress || '').trim() ||
      '(threshold export key)';
    const exportCredential = await this.requestThresholdEcdsaExportAuthorization({
      nearAccountId: args.nearAccountId,
      publicKey: exportPublicKey,
      chain: args.chain,
    });
    const yClient32LeB64u = this.requirePrfFirstForPrivateKeyExport({
      credential: exportCredential,
      errorContext: 'threshold-ecdsa explicit export',
    });

    const cachedArtifact = thresholdEcdsaKeyRef.ecdsaHssExportArtifact;
    if (cachedArtifact) {
      await this.showThresholdEcdsaExportViewer({
        nearAccountId: args.nearAccountId,
        chain: args.chain,
        publicKeyHex: cachedArtifact.publicKeyHex,
        privateKeyHex: cachedArtifact.privateKeyHex,
        ethereumAddress: cachedArtifact.ethereumAddress,
        variant: args.options.variant,
        theme: args.options.theme,
      });
      return {
        accountId: String(args.nearAccountId),
        exportedSchemes: ['secp256k1'],
      };
    }

    const resolveCanonicalExportTransport = async (): Promise<{
      thresholdSessionId: string;
      thresholdSessionJwt: string;
      relayerUrl: string;
      ecdsaThresholdKeyId: string;
      sessionKind: 'jwt' | 'cookie';
    }> => {
      const currentThresholdSessionId = String(
        thresholdEcdsaKeyRef.thresholdSessionId || '',
      ).trim();
      const currentThresholdSessionJwt = String(
        thresholdEcdsaKeyRef.thresholdSessionJwt || '',
      ).trim();
      const currentRelayerUrl = String(thresholdEcdsaKeyRef.relayerUrl || '').trim();
      const currentThresholdKeyId = String(
        thresholdEcdsaKeyRef.ecdsaThresholdKeyId || '',
      ).trim();
      const currentSessionKind =
        thresholdEcdsaKeyRef.thresholdSessionKind === 'cookie' ? 'cookie' : 'jwt';
      if (
        currentThresholdSessionId &&
        currentThresholdSessionJwt &&
        currentRelayerUrl &&
        currentThresholdKeyId
      ) {
        return {
          thresholdSessionId: currentThresholdSessionId,
          thresholdSessionJwt: currentThresholdSessionJwt,
          relayerUrl: currentRelayerUrl,
          ecdsaThresholdKeyId: currentThresholdKeyId,
          sessionKind: currentSessionKind,
        };
      }

      const bootstrap = await this.provisionThresholdEcdsaSession({
        nearAccountId: args.nearAccountId,
        chain: args.chain,
        source: 'manual-bootstrap',
        ...(currentRelayerUrl ? { relayerUrl: currentRelayerUrl } : {}),
        ...(currentThresholdKeyId ? { ecdsaThresholdKeyId: currentThresholdKeyId } : {}),
        ...(Array.isArray(thresholdEcdsaKeyRef.participantIds) &&
        thresholdEcdsaKeyRef.participantIds.length > 0
          ? { participantIds: thresholdEcdsaKeyRef.participantIds }
          : {}),
        ...(thresholdEcdsaKeyRef.thresholdSessionKind
          ? { sessionKind: thresholdEcdsaKeyRef.thresholdSessionKind }
          : {}),
      });
      thresholdEcdsaKeyRef = bootstrap.thresholdEcdsaKeyRef;
      const thresholdSessionId = String(thresholdEcdsaKeyRef.thresholdSessionId || '').trim();
      const thresholdSessionJwt = String(thresholdEcdsaKeyRef.thresholdSessionJwt || '').trim();
      const relayerUrl = String(thresholdEcdsaKeyRef.relayerUrl || '').trim();
      const ecdsaThresholdKeyId = String(
        thresholdEcdsaKeyRef.ecdsaThresholdKeyId || '',
      ).trim();
      if (!thresholdSessionId || !thresholdSessionJwt || !relayerUrl || !ecdsaThresholdKeyId) {
        throw new Error('Missing canonical threshold-ecdsa export session prerequisites');
      }
      return {
        thresholdSessionId,
        thresholdSessionJwt,
        relayerUrl,
        ecdsaThresholdKeyId,
        sessionKind:
          thresholdEcdsaKeyRef.thresholdSessionKind === 'cookie' ? 'cookie' : 'jwt',
      };
    };

    const {
      thresholdSessionJwt,
      relayerUrl,
      ecdsaThresholdKeyId,
      sessionKind,
    } = await resolveCanonicalExportTransport();

    const signerWorkerCtx =
      this.orchestrationDeps.thresholdSessionActivationDeps.getSignerWorkerContext();

    const prepare = await thresholdEcdsaHssPrepare(relayerUrl, {
      userId: String(args.nearAccountId),
      rpId,
      operation: 'explicit_key_export',
      ecdsaThresholdKeyId,
      authorizationJwt: thresholdSessionJwt,
      sessionKind,
    });
    if (!prepare.ok) {
      throw new Error(
        prepare.error || prepare.message || 'Threshold explicit export prepare failed',
      );
    }
    const ceremonyId = String(prepare.ceremonyId || '').trim();
    const preparedServerSessionB64u = String(prepare.preparedServerSessionB64u || '').trim();
    const serverAssistInitB64u = String(prepare.serverAssistInitB64u || '').trim();
    if (!ceremonyId || !preparedServerSessionB64u || !serverAssistInitB64u) {
      throw new Error('Threshold explicit export prepare response missing staged transport inputs');
    }

    const preparedClientSession = await prepareThresholdEcdsaHssSessionWasm({
      context: {
        nearAccountId: String(args.nearAccountId),
        keyPurpose: 'evm-signing',
        keyVersion: 'v1',
      },
      clientRootShare32B64u: yClient32LeB64u,
      workerCtx: signerWorkerCtx,
    });
    const evaluatorDriverStateB64u = String(
      preparedClientSession.evaluatorDriverStateB64u || '',
    ).trim();
    if (!evaluatorDriverStateB64u) {
      throw new Error(
        'Threshold explicit export client session preparation returned incomplete staged transport data',
      );
    }

    const clientRequest = await prepareThresholdEcdsaHssClientRequestWasm({
      evaluatorDriverStateB64u,
      serverAssistInitMessageB64u: serverAssistInitB64u,
      clientRootShare32B64u: yClient32LeB64u,
      workerCtx: signerWorkerCtx,
    });
    const clientEvalRequestB64u = String(clientRequest.clientEvalRequestB64u || '').trim();
    if (!clientEvalRequestB64u) {
      throw new Error(
        'Threshold explicit export client request preparation returned incomplete staged transport data',
      );
    }

    const requestMessageB64u = encodeThresholdEcdsaHssHiddenEvalRequestMessage({
      ceremonyId,
      preparedServerSessionB64u,
      serverAssistInitB64u,
      clientEvalRequestB64u,
    });

    const respond = await thresholdEcdsaHssRespond(relayerUrl, {
      ceremonyId,
      requestMessageB64u,
      authorizationJwt: thresholdSessionJwt,
      sessionKind,
    });
    if (!respond.ok) {
      throw new Error(
        respond.error || respond.message || 'Threshold explicit export respond failed',
      );
    }
    const responseMessageB64u = String(respond.responseMessageB64u || '').trim();
    if (!responseMessageB64u) {
      throw new Error(
        'Threshold explicit export respond response missing responseMessageB64u',
      );
    }
    const responseEnvelope = parseThresholdEcdsaHssHiddenEvalServerResponseMessage(
      responseMessageB64u,
    );
    if (!responseEnvelope) {
      throw new Error(
        'Threshold explicit export respond response did not contain a valid hidden-eval staged payload',
      );
    }
    const serverEvalResponseB64u = String(responseEnvelope.serverEvalResponseB64u || '').trim();
    if (!serverEvalResponseB64u) {
      throw new Error(
        'Threshold explicit export respond response missing hidden-eval serverEvalResponseB64u',
      );
    }

    const clientFinalize = await finalizeThresholdEcdsaHssClientRequestWasm({
      evaluatorDriverStateB64u,
      serverEvalResponseB64u,
      workerCtx: signerWorkerCtx,
    });
    const clientEvalFinalizeB64u = String(clientFinalize.clientEvalFinalizeB64u || '').trim();
    if (!clientEvalFinalizeB64u) {
      throw new Error(
        'Threshold explicit export client finalize preparation returned incomplete staged transport data',
      );
    }

    const clientFinalizeMessageB64u =
      await createThresholdEcdsaHssHiddenEvalFinalizeMessage({
      ceremonyId,
      requestMessageB64u,
      responseMessageB64u,
      clientEvalFinalizeB64u,
    });

    const finalized = await thresholdEcdsaHssFinalize(relayerUrl, {
      ceremonyId,
      clientFinalizeMessageB64u,
      authorizationJwt: thresholdSessionJwt,
      sessionKind,
    });
    if (!finalized.ok) {
      throw new Error(
        finalized.error || finalized.message || 'Threshold explicit export finalize failed',
      );
    }
    const publicKeyHex = String(finalized.canonicalPublicKeyHex || '').trim();
    const privateKeyHex = String(finalized.privateKeyHex || '').trim();
    const ethereumAddress = String(finalized.canonicalEthereumAddress || '').trim();
    if (!publicKeyHex || !privateKeyHex || !ethereumAddress) {
      throw new Error('Threshold explicit export finalize returned incomplete export material');
    }

    await this.showThresholdEcdsaExportViewer({
      nearAccountId: args.nearAccountId,
      chain: args.chain,
      publicKeyHex,
      privateKeyHex,
      ethereumAddress,
      variant: args.options.variant,
      theme: args.options.theme,
    });
    return {
      accountId: String(args.nearAccountId),
      exportedSchemes: ['secp256k1'],
    };
  }

  exportNearEd25519SeedArtifactWithUI(args: {
    nearAccountId: AccountId;
    seedB64u: string;
    expectedPublicKey: string;
    options: {
      variant?: 'drawer' | 'modal';
      theme?: 'dark' | 'light';
    };
  }): Promise<{ accountId: string; exportedSchemes: Array<'ed25519' | 'secp256k1'> }> {
    return exportNearEd25519SeedArtifactWithUIValue(
      this.orchestrationDeps.privateKeyExportRecoveryDeps,
      args,
    );
  }

  private requirePrfFirstForPrivateKeyExport(args: {
    credential: WebAuthnAuthenticationCredential | undefined;
    errorContext: string;
  }): string {
    const prfFirstB64u = String(getPrfResultsFromCredential(args.credential).first || '').trim();
    if (!prfFirstB64u) {
      throw new Error(`Missing PRF.first output for ${args.errorContext}`);
    }
    return prfFirstB64u;
  }

  private async requestNearEd25519ExportAuthorization(args: {
    nearAccountId: AccountId;
    expectedPublicKey: string;
  }): Promise<WebAuthnAuthenticationCredential> {
    removeExportViewerHostIfPresent();
    const decision = await this.touchConfirm.requestUserConfirmation({
      requestId: createExportUiRequestId('export-near-ed25519-auth'),
      type: UserConfirmationType.DECRYPT_PRIVATE_KEY_WITH_PRF,
      summary: {
        operation: 'Export Private Key',
        accountId: args.nearAccountId,
        publicKey: args.expectedPublicKey,
        warning: 'Confirm to reveal your NEAR private key export.',
      },
      payload: {
        nearAccountId: args.nearAccountId,
        publicKey: args.expectedPublicKey,
      },
      intentDigest: `export-keys:${args.nearAccountId}:near-ed25519`,
    });
    if (!decision.confirmed) {
      throw new Error(decision.error || 'User cancelled export request');
    }
    return decision.credential as WebAuthnAuthenticationCredential;
  }

  private async showNearEd25519ExportViewer(args: {
    nearAccountId: AccountId;
    expectedPublicKey: string;
    privateKey?: string;
    variant?: 'drawer' | 'modal';
    theme?: 'dark' | 'light';
    loading?: boolean;
  }): Promise<void> {
    const keys: ExportPrivateKeyDisplayEntry[] = [
      {
        scheme: 'ed25519',
        label: 'NEAR private key',
        publicKey: args.expectedPublicKey,
        privateKey: String(args.privateKey || '').trim(),
      },
    ];
    await this.touchConfirm.requestUserConfirmation({
      requestId: createExportUiRequestId('export-near-ed25519-view'),
      type: UserConfirmationType.SHOW_SECURE_PRIVATE_KEY_UI,
      summary: {
        operation: 'Export Private Key',
        accountId: args.nearAccountId,
        publicKey: args.expectedPublicKey,
        warning: 'Anyone with your private key can fully control your account. Never share it.',
      },
      payload: {
        nearAccountId: args.nearAccountId,
        publicKey: args.expectedPublicKey,
        keys,
        variant: args.variant,
        theme: args.theme ?? this.theme ?? 'dark',
        loading: args.loading === true,
      },
      intentDigest: `export-keys:${args.nearAccountId}:near-ed25519`,
    });
  }

  private async requestThresholdEcdsaExportAuthorization(args: {
    nearAccountId: AccountId;
    publicKey: string;
    chain: 'evm' | 'tempo';
  }): Promise<WebAuthnAuthenticationCredential> {
    removeExportViewerHostIfPresent();
    const decision = await this.touchConfirm.requestUserConfirmation({
      requestId: createExportUiRequestId('export-threshold-ecdsa-auth'),
      type: UserConfirmationType.DECRYPT_PRIVATE_KEY_WITH_PRF,
      summary: {
        operation: 'Export Private Key',
        accountId: args.nearAccountId,
        publicKey: args.publicKey,
        warning:
          args.chain === 'tempo'
            ? 'Confirm to reveal your Tempo private key export.'
            : 'Confirm to reveal your EVM private key export.',
      },
      payload: {
        nearAccountId: args.nearAccountId,
        publicKey: args.publicKey,
      },
      intentDigest: `export-keys:${args.nearAccountId}:${args.chain}:secp256k1`,
    });
    if (!decision.confirmed) {
      throw new Error(decision.error || 'User cancelled export request');
    }
    return decision.credential as WebAuthnAuthenticationCredential;
  }

  private async showThresholdEcdsaExportViewer(args: {
    nearAccountId: AccountId;
    chain: 'evm' | 'tempo';
    publicKeyHex: string;
    privateKeyHex: string;
    ethereumAddress: string;
    variant?: 'drawer' | 'modal';
    theme?: 'dark' | 'light';
  }): Promise<void> {
    const label = args.chain === 'tempo' ? 'Tempo private key' : 'EVM private key';
    const keys: ExportPrivateKeyDisplayEntry[] = [
      {
        scheme: 'secp256k1',
        label,
        publicKey: args.publicKeyHex,
        privateKey: args.privateKeyHex,
        address: args.ethereumAddress,
      },
    ];
    await this.touchConfirm.requestUserConfirmation({
      requestId: createExportUiRequestId('export-threshold-ecdsa-view'),
      type: UserConfirmationType.SHOW_SECURE_PRIVATE_KEY_UI,
      summary: {
        operation: 'Export Private Key',
        accountId: args.nearAccountId,
        publicKey: args.publicKeyHex,
        warning: 'Anyone with your private key can fully control your account. Never share it.',
      },
      payload: {
        nearAccountId: args.nearAccountId,
        publicKey: args.publicKeyHex,
        keys,
        variant: args.variant,
        theme: args.theme ?? this.theme ?? 'dark',
      },
      intentDigest: `export-keys:${args.nearAccountId}:${args.chain}:secp256k1`,
    });
  }

  private async runNearEd25519OptionAHssExport(args: {
    orgId: string;
    nearAccountId: AccountId;
    keyVersion: string;
    participantIds: number[];
    thresholdSessionId: string;
    thresholdSessionJwt: string;
    relayerUrl: string;
    relayerKeyId: string;
    prfFirstB64u: string;
  }): Promise<{
    preparedSession: Parameters<
      typeof buildThresholdEd25519SeedExportArtifactFromHssReportValue
    >[0]['preparedSession'];
    finalizedReport: Parameters<
      typeof buildThresholdEd25519SeedExportArtifactFromHssReportValue
    >[0]['finalizedReport'];
  }> {
    const clientInputs = await deriveThresholdEd25519HssClientInputsWasm({
      sessionId: `${args.thresholdSessionId}:hss-export-client-inputs`,
      orgId: args.orgId,
      nearAccountId: args.nearAccountId,
      keyPurpose: THRESHOLD_ED25519_HSS_SIGNING_KEY_PURPOSE,
      keyVersion: args.keyVersion,
      participantIds: args.participantIds,
      derivationVersion: THRESHOLD_ED25519_HSS_DERIVATION_VERSION,
      prfFirstB64u: args.prfFirstB64u,
      workerCtx: this.orchestrationDeps.thresholdSessionActivationDeps.getSignerWorkerContext(),
    });

    const completed = await runThresholdEd25519HssCeremonyWithSessionValue({
      relayerUrl: args.relayerUrl,
      thresholdSessionJwt: args.thresholdSessionJwt,
      relayerKeyId: args.relayerKeyId,
      operation: 'explicit_key_export',
      context: {
        orgId: args.orgId,
        nearAccountId: args.nearAccountId,
        keyPurpose: THRESHOLD_ED25519_HSS_SIGNING_KEY_PURPOSE,
        keyVersion: args.keyVersion,
        participantIds: args.participantIds,
        derivationVersion: THRESHOLD_ED25519_HSS_DERIVATION_VERSION,
      },
      clientInputs,
      workerCtx: this.orchestrationDeps.thresholdSessionActivationDeps.getSignerWorkerContext(),
    });
    if (!completed.success || !completed.finalizedReport || !completed.preparedSession) {
      throw new Error(completed.error || 'Failed to finalize Option A Ed25519 export ceremony');
    }

    return {
      preparedSession: completed.preparedSession,
      finalizedReport: completed.finalizedReport,
    };
  }

  async exportThresholdEd25519SeedFromHssReport(args: {
    nearAccountId: AccountId;
    preparedSession: Parameters<
      typeof buildThresholdEd25519SeedExportArtifactFromHssReportValue
    >[0]['preparedSession'];
    finalizedReport: Parameters<
      typeof buildThresholdEd25519SeedExportArtifactFromHssReportValue
    >[0]['finalizedReport'];
    expectedPublicKey: string;
    options: {
      variant?: 'drawer' | 'modal';
      theme?: 'dark' | 'light';
    };
  }): Promise<{ accountId: string; exportedSchemes: Array<'ed25519' | 'secp256k1'> }> {
    const artifactResult = await buildThresholdEd25519SeedExportArtifactFromHssReportValue({
      preparedSession: args.preparedSession,
      finalizedReport: args.finalizedReport,
      expectedPublicKey: args.expectedPublicKey,
      workerCtx: this.orchestrationDeps.thresholdSessionActivationDeps.getSignerWorkerContext(),
    });
    if (!artifactResult.success || !artifactResult.artifact) {
      throw new Error(
        artifactResult.error || 'Failed to build Option A Ed25519 seed export artifact',
      );
    }
    return exportNearEd25519SeedArtifactWithUIValue(
      this.orchestrationDeps.privateKeyExportRecoveryDeps,
      {
        nearAccountId: args.nearAccountId,
        seedB64u: artifactResult.artifact.seedB64u,
        expectedPublicKey: artifactResult.artifact.publicKey,
        options: args.options,
      },
    );
  }

  private async tryExportNearEd25519OptionAWithAuthorization(args: {
    nearAccountId: AccountId;
    options: {
      variant?: 'drawer' | 'modal';
      theme?: 'dark' | 'light';
    };
  }): Promise<{ accountId: string; exportedSchemes: Array<'ed25519' | 'secp256k1'> } | null> {
    const nearAccountId = toAccountId(args.nearAccountId);
    const sessionRecord = getStoredThresholdEd25519SessionRecordForAccountValue(nearAccountId);
    const orgId = String(sessionRecord?.runtimeSnapshotScope?.orgId || '').trim();
    const environmentId = String(sessionRecord?.runtimeSnapshotScope?.environmentId || '').trim();
    const thresholdSessionId = String(sessionRecord?.thresholdSessionId || '').trim();
    const thresholdSessionJwt = String(sessionRecord?.thresholdSessionJwt || '').trim();
    const relayerUrl = String(sessionRecord?.relayerUrl || '').trim();
    const relayerKeyId = String(sessionRecord?.relayerKeyId || '').trim();
    const participantIds = Array.isArray(sessionRecord?.participantIds)
      ? sessionRecord.participantIds.map((value) => Number(value))
      : [];
    const hasCanonicalRuntimeScope = Boolean(orgId && environmentId);

    const requireOptionAExportPrerequisite = (condition: boolean, message: string): void => {
      if (condition) return;
      if (hasCanonicalRuntimeScope) {
        throw new Error(message);
      }
    };

    if (
      !orgId ||
      !environmentId ||
      !thresholdSessionId ||
      !thresholdSessionJwt ||
      !relayerUrl ||
      !relayerKeyId ||
      participantIds.length === 0
    ) {
      requireOptionAExportPrerequisite(
        false,
        'Missing canonical Option A Ed25519 export session prerequisites',
      );
      return null;
    }

    const deviceNumber = await getLastLoggedInDeviceNumber(
      nearAccountId,
      this.orchestrationDeps.indexedDB.clientDB,
    ).catch(() => null as number | null);
    if (deviceNumber == null) {
      requireOptionAExportPrerequisite(false, 'Missing device number for Option A Ed25519 export');
      return null;
    }

    const thresholdKeyMaterial = await getNearThresholdKeyMaterial(
      {
        clientDB: this.orchestrationDeps.indexedDB.clientDB,
        accountKeyMaterialDB: this.orchestrationDeps.indexedDB.accountKeyMaterialDB,
      },
      nearAccountId,
      deviceNumber,
    ).catch(() => null);
    const keyVersion = String(thresholdKeyMaterial?.keyVersion || '').trim();
    const expectedPublicKey = String(thresholdKeyMaterial?.publicKey || '').trim();
    if (!keyVersion || !expectedPublicKey) {
      requireOptionAExportPrerequisite(
        false,
        'Missing canonical public key material for Option A Ed25519 export',
      );
      return null;
    }

    try {
      const exportCredential = await this.requestNearEd25519ExportAuthorization({
        nearAccountId,
        expectedPublicKey,
      });
      const prfFirstB64u = this.requirePrfFirstForPrivateKeyExport({
        credential: exportCredential,
        errorContext: 'Option A Ed25519 export',
      });
      const hssTask = this.runNearEd25519OptionAHssExport({
        orgId,
        nearAccountId,
        keyVersion,
        participantIds,
        thresholdSessionId,
        thresholdSessionJwt,
        relayerUrl,
        relayerKeyId,
        prfFirstB64u,
      });
      await this.showNearEd25519ExportViewer({
        nearAccountId,
        expectedPublicKey,
        variant: args.options.variant,
        theme: args.options.theme,
        loading: true,
      });

      const { preparedSession, finalizedReport } = await hssTask;
      const artifactResult = await buildThresholdEd25519SeedExportArtifactFromHssReportValue({
        preparedSession,
        finalizedReport,
        expectedPublicKey,
        workerCtx: this.orchestrationDeps.thresholdSessionActivationDeps.getSignerWorkerContext(),
      });
      if (!artifactResult.success || !artifactResult.artifact) {
        throw new Error(
          artifactResult.error || 'Failed to build Option A Ed25519 seed export artifact',
        );
      }

      await this.showNearEd25519ExportViewer({
        nearAccountId,
        expectedPublicKey: artifactResult.artifact.publicKey,
        privateKey: artifactResult.artifact.privateKey,
        variant: args.options.variant,
        theme: args.options.theme,
      });

      return {
        accountId: nearAccountId,
        exportedSchemes: ['ed25519'],
      };
    } catch (error: unknown) {
      removeExportViewerHostIfPresent();
      throw error;
    }
  }

  signTransactionWithKeyPair(args: {
    nearPrivateKey: string;
    signerAccountId: string;
    receiverId: string;
    nonce: string;
    blockHash: string;
    actions: ActionArgsWasm[];
  }): Promise<{
    signedTransaction: SignedTransaction;
    logs?: string[];
  }> {
    return this.orchestrationDeps.nearKeyOpsDeps.signingKeyOps.signTransactionWithKeyPair({
      nearPrivateKey: args.nearPrivateKey,
      signerAccountId: args.signerAccountId,
      receiverId: args.receiverId,
      nonce: args.nonce,
      blockHash: args.blockHash,
      actions: args.actions,
    });
  }

  generateEphemeralNearKeypair(): Promise<{
    publicKey: string;
    privateKey: string;
  }> {
    return this.orchestrationDeps.nearKeyOpsDeps.signingKeyOps.generateEphemeralNearKeypair();
  }

  async connectEd25519Session(
    args: Omit<ProvisionWarmEd25519CapabilityArgs, 'beforeProvision' | 'assertNotCancelled'>,
  ): Promise<ProvisionWarmEd25519CapabilityResult> {
    const warmSessionManager = createWarmSessionManager({
      touchConfirm: this.touchConfirm,
      signingSessionSeal: this.tatchiPasskeyConfigs.signing.sessionSeal,
      provisionThresholdEd25519Session: async (provisionArgs) =>
        await this.provisionThresholdEd25519Session(provisionArgs),
    });
    return await warmSessionManager.provisionEd25519Capability(args);
  }

  async bootstrapEcdsaSession(
    args: Parameters<typeof bootstrapEcdsaSessionValue>[1],
  ): Promise<ThresholdEcdsaSessionBootstrapResult> {
    await this.ensureSealedRefreshStartupParityForThresholdEcdsaBootstrap(args);
    const nearAccountId = toAccountId(args.nearAccountId);
    const chain: ThresholdEcdsaActivationChain = args.chain || 'tempo';
    const warmSessionManager = createWarmSessionManager({
      touchConfirm: this.touchConfirm,
      clearThresholdEcdsaSigningArtifactsForLane: ({ nearAccountId, chain }) =>
        this.clearThresholdEcdsaSigningArtifactsForLane({ nearAccountId, chain }),
      clearThresholdEcdsaSessionRecordForLane: ({ nearAccountId, chain }) =>
        this.clearThresholdEcdsaSessionRecordForLane({ nearAccountId, chain }),
      getThresholdEcdsaSessionRecordForSigning: ({ nearAccountId, chain }) =>
        this.getThresholdEcdsaSessionRecordForSigning({ nearAccountId, chain }),
      signingSessionSeal: this.tatchiPasskeyConfigs.signing.sessionSeal,
      getThresholdEcdsaKeyRefForSigning: (readyArgs) =>
        this.getThresholdEcdsaKeyRefForSigning(readyArgs),
      provisionThresholdEcdsaSession: async (provisionArgs) =>
        await this.provisionThresholdEcdsaSession({
          ...args,
          nearAccountId,
          chain,
          ...(provisionArgs.relayerUrl ? { relayerUrl: provisionArgs.relayerUrl } : {}),
          ...(provisionArgs.clientRootShare32
            ? { clientRootShare32: provisionArgs.clientRootShare32 }
            : {}),
          ...(provisionArgs.clientRootShare32B64u
            ? { clientRootShare32B64u: provisionArgs.clientRootShare32B64u }
            : {}),
          ...(provisionArgs.ecdsaThresholdKeyId
            ? { ecdsaThresholdKeyId: provisionArgs.ecdsaThresholdKeyId }
            : {}),
          ...(provisionArgs.authorizationJwt
            ? { authorizationJwt: provisionArgs.authorizationJwt }
            : {}),
          ...(provisionArgs.sessionId ? { sessionId: provisionArgs.sessionId } : {}),
          ...(Array.isArray(provisionArgs.participantIds) && provisionArgs.participantIds.length > 0
            ? { participantIds: provisionArgs.participantIds }
            : {}),
          ...(provisionArgs.sessionKind ? { sessionKind: provisionArgs.sessionKind } : {}),
          ...(typeof provisionArgs.ttlMs === 'number' ? { ttlMs: provisionArgs.ttlMs } : {}),
          ...(typeof provisionArgs.remainingUses === 'number'
            ? { remainingUses: provisionArgs.remainingUses }
            : {}),
          ...(provisionArgs.smartAccount ? { smartAccount: provisionArgs.smartAccount } : {}),
        }),
    });
    return await warmSessionManager.provisionEcdsaCapability({
      nearAccountId,
      chain,
      source: args.source,
      ecdsaThresholdKeyId: args.ecdsaThresholdKeyId,
      participantIds: args.participantIds,
      sessionKind: args.sessionKind,
      sessionId: args.sessionId,
      authorizationJwt: args.authorizationJwt,
      clientRootShare32: args.clientRootShare32,
      clientRootShare32B64u: args.clientRootShare32B64u,
      ttlMs: args.ttlMs,
      remainingUses: args.remainingUses,
      smartAccount: args.smartAccount,
    });
  }

  /**
   * Internal Email OTP login bridge.
   * Kept off `SigningEnginePublic` until the Email OTP abstraction is stable.
   */
  async loginWithEmailOtpEcdsaCapabilityInternal(args: {
    nearAccountId: AccountId | string;
    chain?: ThresholdEcdsaActivationChain;
    emailOtpAuthPolicy?: EmailOtpAuthPolicy;
    relayUrl?: string;
    challengeId?: string;
    otpCode: string;
    shamirPrimeB64u?: string;
    appSessionJwt?: string;
    authorizationJwt?: string;
    ecdsaThresholdKeyId?: string;
    participantIds?: number[];
    sessionKind?: 'jwt' | 'cookie';
    sessionId?: string;
    ttlMs?: number;
    remainingUses?: number;
    smartAccount?: ThresholdEcdsaSmartAccountBootstrapInput;
  }): Promise<{
    recovery: EmailOtpBootstrapRecovery;
    bootstrap: ThresholdEcdsaSessionBootstrapResult;
    warmCapability: WarmSessionEcdsaCapabilityState;
  }> {
    const nearAccountId = toAccountId(args.nearAccountId);
    const chain: ThresholdEcdsaActivationChain = args.chain || 'evm';
    const emailOtpAuthPolicy: EmailOtpAuthPolicy =
      args.emailOtpAuthPolicy || this.tatchiPasskeyConfigs.signing.emailOtp.authPolicy;
    const emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext = {
      policy: emailOtpAuthPolicy,
      retention: emailOtpAuthPolicy === 'per_operation' ? 'single_use' : 'session',
      reason: 'login',
      authMethod: 'email_otp',
      stepUpRequired: true,
    };
    const relayUrl = String(
      args.relayUrl || this.tatchiPasskeyConfigs.network.relayer?.url || '',
    ).trim();
    if (!relayUrl) {
      throw new Error('Missing relayer url (configs.network.relayer.url)');
    }
    const shamirPrimeB64u = String(
      args.shamirPrimeB64u || this.tatchiPasskeyConfigs.signing.sessionSeal?.shamirPrimeB64u || '',
    ).trim();
    if (!shamirPrimeB64u) {
      throw new Error('Missing shamir prime for Email OTP runtime');
    }
    const remainingUses =
      typeof args.remainingUses === 'number'
        ? args.remainingUses
        : emailOtpAuthPolicy === 'per_operation'
          ? 1
          : undefined;
    const workerCtx =
      this.orchestrationDeps.thresholdSessionActivationDeps.getSignerWorkerContext();
    const authorizationJwt = String(args.authorizationJwt || '').trim();
    const rpId =
      typeof (this.touchIdPrompt as { getRpId?: unknown } | undefined)?.getRpId === 'function'
        ? String(this.touchIdPrompt.getRpId() || '').trim()
        : '';

    if (!workerCtx) {
      throw new Error('Email OTP login requires the dedicated emailOtp worker');
    }
    if (!authorizationJwt) {
      throw new Error('Email OTP login requires an authorization JWT for ECDSA bootstrap');
    }
    if (!rpId) {
      throw new Error('Email OTP login requires an RP ID for ECDSA bootstrap');
    }
    const workerResult = await workerCtx.requestWorkerOperation({
      kind: 'emailOtp',
      request: {
        type: 'loginWithEmailOtpAndBootstrapEcdsaSession',
        timeoutMs: 60_000,
        payload: {
          relayUrl,
          walletId: String(nearAccountId),
          userId: String(nearAccountId),
          ...(args.challengeId ? { challengeId: args.challengeId } : {}),
          otpCode: args.otpCode,
          shamirPrimeB64u,
          ...(args.appSessionJwt ? { appSessionJwt: args.appSessionJwt } : {}),
          otpChannel: 'email_otp',
          rpId,
          ...(args.ecdsaThresholdKeyId ? { ecdsaThresholdKeyId: args.ecdsaThresholdKeyId } : {}),
          ...(Array.isArray(args.participantIds) && args.participantIds.length > 0
            ? { participantIds: args.participantIds }
            : {}),
          ...(args.sessionKind ? { sessionKind: args.sessionKind } : {}),
          ...(args.sessionId ? { sessionId: args.sessionId } : {}),
          authorizationJwt,
          ...(typeof args.ttlMs === 'number' ? { ttlMs: args.ttlMs } : {}),
          ...(typeof remainingUses === 'number' ? { remainingUses } : {}),
        },
      },
    });
    const bootstrap = await this.commitWorkerProvisionedThresholdEcdsaSession({
      nearAccountId,
      chain,
      bootstrap: workerResult.bootstrap,
      source: 'email_otp',
      emailOtpAuthContext,
      smartAccount: args.smartAccount,
      requiresSealPersistence: true,
    });
    const warmCapability = await this.assertWarmThresholdEcdsaCapabilityReady({
      nearAccountId,
      chain,
    });
    return {
      recovery: workerResult.recovery,
      bootstrap,
      warmCapability,
    };
  }

  /**
   * Internal Email OTP enrollment bridge.
   * Kept off `SigningEnginePublic` until the Email OTP abstraction is stable.
   */
  async enrollEmailOtpInternal(args: {
    nearAccountId: AccountId | string;
    otpCode: string;
    relayUrl?: string;
    challengeId?: string;
    shamirPrimeB64u?: string;
    appSessionJwt?: string;
    clientSecret32?: Uint8Array;
    otpChannel?: 'email_otp';
  }): Promise<Awaited<ReturnType<typeof enrollEmailOtpWallet>>> {
    const nearAccountId = toAccountId(args.nearAccountId);
    const relayUrl = String(
      args.relayUrl || this.tatchiPasskeyConfigs.network.relayer?.url || '',
    ).trim();
    if (!relayUrl) {
      throw new Error('Missing relayer url (configs.network.relayer.url)');
    }
    const shamirPrimeB64u = String(
      args.shamirPrimeB64u || this.tatchiPasskeyConfigs.signing.sessionSeal?.shamirPrimeB64u || '',
    ).trim();
    if (!shamirPrimeB64u) {
      throw new Error('Missing shamir prime for Email OTP runtime');
    }
    return await enrollEmailOtpWallet({
      relayUrl,
      walletId: String(nearAccountId),
      userId: String(nearAccountId),
      challengeId: args.challengeId,
      otpCode: args.otpCode,
      shamirPrimeB64u,
      workerCtx: this.orchestrationDeps.thresholdSessionActivationDeps.getSignerWorkerContext(),
      appSessionJwt: args.appSessionJwt,
      otpChannel: args.otpChannel,
      ...(args.clientSecret32 ? { clientSecret32: args.clientSecret32 } : {}),
    });
  }

  private async assertWarmThresholdEcdsaCapabilityReady(args: {
    nearAccountId: AccountId | string;
    chain: ThresholdEcdsaActivationChain;
  }): Promise<WarmSessionEcdsaCapabilityState> {
    const warmSession = await createWarmSessionManager({
      touchConfirm: this.touchConfirm,
      clearThresholdEcdsaSigningArtifactsForLane: ({ nearAccountId, chain }) =>
        this.clearThresholdEcdsaSigningArtifactsForLane({ nearAccountId, chain }),
      clearThresholdEcdsaSessionRecordForLane: ({ nearAccountId, chain }) =>
        this.clearThresholdEcdsaSessionRecordForLane({ nearAccountId, chain }),
      getThresholdEcdsaSessionRecordForSigning: ({ nearAccountId, chain }) =>
        this.getThresholdEcdsaSessionRecordForSigning({ nearAccountId, chain }),
      signingSessionSeal: this.tatchiPasskeyConfigs.signing.sessionSeal,
    }).getWarmSession(args.nearAccountId);
    const capability = warmSession.capabilities.ecdsa[args.chain];
    if (capability.state !== 'ready') {
      throw new Error(
        `[SigningEngine] Email OTP bootstrap did not reach warm-session ready state for ${String(
          args.nearAccountId,
        )} (${args.chain}, state=${capability.state})`,
      );
    }
    return capability;
  }

  private async provisionThresholdEcdsaSession(
    args: Parameters<typeof bootstrapEcdsaSessionValue>[1],
  ): Promise<ThresholdEcdsaSessionBootstrapResult> {
    const nearAccountId = toAccountId(args.nearAccountId);
    const chain: ThresholdEcdsaActivationChain = args.chain || 'tempo';
    return await this.withThresholdEcdsaBootstrapQueue(nearAccountId, async () => {
      const bootstrap = await bootstrapEcdsaSessionValue(
        this.orchestrationDeps.thresholdSessionActivationDeps,
        {
          ...args,
          nearAccountId,
          chain,
        },
      );
      const thresholdSessionId = String(
        bootstrap.thresholdEcdsaKeyRef.thresholdSessionId || '',
      ).trim();
      if (thresholdSessionId) {
        const warmSessionManager = createWarmSessionManager({
          touchConfirm: this.touchConfirm,
          clearThresholdEcdsaSigningArtifactsForLane: ({ nearAccountId, chain }) =>
            this.clearThresholdEcdsaSigningArtifactsForLane({ nearAccountId, chain }),
          clearThresholdEcdsaSessionRecordForLane: ({ nearAccountId, chain }) =>
            this.clearThresholdEcdsaSessionRecordForLane({ nearAccountId, chain }),
          getThresholdEcdsaSessionRecordForSigning: ({ nearAccountId, chain }) =>
            this.getThresholdEcdsaSessionRecordForSigning({ nearAccountId, chain }),
          signingSessionSeal: this.tatchiPasskeyConfigs.signing.sessionSeal,
        });
        await warmSessionManager.ensureEcdsaPrfSealPersistedByThresholdSessionId({
          chain,
          thresholdSessionId,
          required: Boolean(String(args.authorizationJwt || '').trim()),
          errorContext: 'threshold-ecdsa bootstrap seal persistence',
        });
      }
      return bootstrap;
    });
  }

  private async commitWorkerProvisionedThresholdEcdsaSession(args: {
    nearAccountId: AccountId | string;
    chain: ThresholdEcdsaActivationChain;
    bootstrap: ThresholdEcdsaSessionBootstrapResult;
    source: ThresholdEcdsaSessionStoreSource;
    emailOtpAuthContext?: ThresholdEcdsaEmailOtpAuthContext;
    smartAccount?: ThresholdEcdsaSmartAccountBootstrapInput;
    requiresSealPersistence?: boolean;
  }): Promise<ThresholdEcdsaSessionBootstrapResult> {
    const nearAccountId = toAccountId(args.nearAccountId);
    await this.ensureSealedRefreshStartupParityForThresholdEcdsaBootstrap({
      nearAccountId,
      chain: args.chain,
      source: args.source,
      emailOtpAuthContext: args.emailOtpAuthContext,
      smartAccount: args.smartAccount,
    });
    return await this.withThresholdEcdsaBootstrapQueue(nearAccountId, async () => {
      const ecdsaThresholdKeyId = String(
        args.bootstrap.thresholdEcdsaKeyRef.ecdsaThresholdKeyId || '',
      ).trim();
      if (!ecdsaThresholdKeyId) {
        throw new Error(
          '[SigningEngine] threshold-ecdsa bootstrap did not provide canonical ecdsaThresholdKeyId',
        );
      }
      const canonicalBootstrap: ThresholdEcdsaSessionBootstrapResult = {
        ...args.bootstrap,
        thresholdEcdsaKeyRef: {
          ...args.bootstrap.thresholdEcdsaKeyRef,
          ecdsaThresholdKeyId,
        },
      };
      await this.persistThresholdEcdsaBootstrapChainAccount({
        nearAccountId,
        chain: args.chain,
        bootstrap: canonicalBootstrap,
        smartAccount: args.smartAccount,
      });
      this.upsertThresholdEcdsaSessionFromBootstrap({
        nearAccountId,
        chain: args.chain,
        bootstrap: canonicalBootstrap,
        source: args.source,
        ...(args.emailOtpAuthContext ? { emailOtpAuthContext: args.emailOtpAuthContext } : {}),
      });
      const thresholdSessionId = String(
        canonicalBootstrap.thresholdEcdsaKeyRef.thresholdSessionId || '',
      ).trim();
      if (thresholdSessionId) {
        const warmSessionManager = createWarmSessionManager({
          touchConfirm: this.touchConfirm,
          clearThresholdEcdsaSigningArtifactsForLane: ({ nearAccountId, chain }) =>
            this.clearThresholdEcdsaSigningArtifactsForLane({ nearAccountId, chain }),
          clearThresholdEcdsaSessionRecordForLane: ({ nearAccountId, chain }) =>
            this.clearThresholdEcdsaSessionRecordForLane({ nearAccountId, chain }),
          getThresholdEcdsaSessionRecordForSigning: ({ nearAccountId, chain }) =>
            this.getThresholdEcdsaSessionRecordForSigning({ nearAccountId, chain }),
          signingSessionSeal: this.tatchiPasskeyConfigs.signing.sessionSeal,
        });
        await warmSessionManager.ensureEcdsaPrfSealPersistedByThresholdSessionId({
          chain: args.chain,
          thresholdSessionId,
          required: Boolean(args.requiresSealPersistence),
          errorContext: 'threshold-ecdsa bootstrap seal persistence',
        });
      }
      return canonicalBootstrap;
    });
  }

  private async provisionThresholdEd25519Session(
    args: ProvisionWarmEd25519CapabilityArgs,
  ): Promise<ProvisionWarmEd25519CapabilityResult> {
    const nearAccountId = toAccountId(args.nearAccountId);
    const relayerUrl = String(
      args.relayerUrl || this.tatchiPasskeyConfigs.network.relayer?.url || '',
    ).trim();
    if (!relayerUrl) {
      throw new Error('Missing relayer url (configs.network.relayer.url)');
    }
    const workerCtx = this.orchestrationDeps.thresholdSessionActivationDeps.getSignerWorkerContext();
    const sessionId =
      String(args.sessionId || '').trim() ||
      generateSessionIdValue('threshold-ed25519');
    return await connectEd25519Session({
      indexedDB: this.orchestrationDeps.indexedDB,
      touchIdPrompt: this.touchIdPrompt,
      prfFirstCache: this.touchConfirm,
      relayerUrl,
      relayerKeyId: args.relayerKeyId,
      ...(args.runtimeSnapshotScope ? { runtimeSnapshotScope: args.runtimeSnapshotScope } : {}),
      ...(args.runtimeScopeBootstrap ? { runtimeScopeBootstrap: args.runtimeScopeBootstrap } : {}),
      nearAccountId,
      participantIds: args.participantIds,
      sessionKind: args.sessionKind,
      sessionId,
      ttlMs: args.ttlMs,
      remainingUses: args.remainingUses,
      workerCtx,
    });
  }

  upsertThresholdEcdsaSessionFromBootstrap(args: {
    nearAccountId: AccountId | string;
    chain: ThresholdEcdsaActivationChain;
    bootstrap: ThresholdEcdsaSessionBootstrapResult;
    source: ThresholdEcdsaSessionStoreSource;
    emailOtpAuthContext?: ThresholdEcdsaEmailOtpAuthContext;
  }): void {
    upsertThresholdEcdsaSessionFromBootstrapValue(
      {
        recordsByLane: this.thresholdEcdsaSessionByLane,
        exportArtifactsByLane: this.thresholdEcdsaExportArtifactByLane,
      },
      {
        ...args,
        signingSessionSeal: this.tatchiPasskeyConfigs.signing.sessionSeal,
      },
    );
  }

  getThresholdEcdsaKeyRefForSigning(args: {
    nearAccountId: AccountId | string;
    chain: ThresholdEcdsaActivationChain;
  }): ThresholdEcdsaSecp256k1KeyRef {
    return getThresholdEcdsaKeyRefForSigningValue(
      {
        recordsByLane: this.thresholdEcdsaSessionByLane,
        exportArtifactsByLane: this.thresholdEcdsaExportArtifactByLane,
      },
      args,
    );
  }

  getThresholdEcdsaSessionRecordForSigning(args: {
    nearAccountId: AccountId | string;
    chain: ThresholdEcdsaActivationChain;
  }): ThresholdEcdsaSessionRecord {
    return getThresholdEcdsaSessionRecordForSigningValue(
      {
        recordsByLane: this.thresholdEcdsaSessionByLane,
      },
      args,
    );
  }

  clearThresholdEcdsaSessionRecordForAccount(nearAccountId: AccountId | string): void {
    clearThresholdEcdsaSessionRecordForAccountValue(
      {
        recordsByLane: this.thresholdEcdsaSessionByLane,
        exportArtifactsByLane: this.thresholdEcdsaExportArtifactByLane,
      },
      nearAccountId,
    );
  }

  clearThresholdEcdsaSessionRecordForLane(args: {
    nearAccountId: AccountId | string;
    chain: ThresholdEcdsaActivationChain;
  }): void {
    clearThresholdEcdsaSessionRecordForLaneValue(
      {
        recordsByLane: this.thresholdEcdsaSessionByLane,
        exportArtifactsByLane: this.thresholdEcdsaExportArtifactByLane,
      },
      args,
    );
  }

  markThresholdEcdsaEmailOtpSessionConsumedForAccount(args: {
    nearAccountId: AccountId | string;
    chain: ThresholdEcdsaActivationChain;
  }): void {
    markThresholdEcdsaEmailOtpSessionConsumedForAccountValue(
      {
        recordsByLane: this.thresholdEcdsaSessionByLane,
        exportArtifactsByLane: this.thresholdEcdsaExportArtifactByLane,
      },
      args,
    );
  }

  clearThresholdEcdsaSigningArtifactsForLane(args: {
    nearAccountId: AccountId | string;
    chain: ThresholdEcdsaActivationChain;
  }): void {
    const record = this.getThresholdEcdsaSessionRecordForSigning(args);
    clearThresholdEcdsaClientPresignaturesForLane({
      relayerUrl: record.relayerUrl,
      ecdsaThresholdKeyId: String(record.ecdsaThresholdKeyId || '').trim(),
      participantIds: record.participantIds,
    });
  }

  clearAllThresholdEcdsaSessionRecords(): void {
    clearAllThresholdEcdsaSessionRecordsValue({
      recordsByLane: this.thresholdEcdsaSessionByLane,
      exportArtifactsByLane: this.thresholdEcdsaExportArtifactByLane,
    });
  }

  persistThresholdEcdsaBootstrapChainAccount(args: {
    nearAccountId: AccountId | string;
    chain: ThresholdEcdsaActivationChain;
    bootstrap: ThresholdEcdsaSessionBootstrapResult;
    smartAccount?: ThresholdEcdsaSmartAccountBootstrapInput;
    deployment?: {
      deployed: boolean;
      deploymentTxHash?: string;
    };
  }): Promise<void> {
    return persistThresholdEcdsaBootstrapChainAccountValue({
      indexedDB: this.orchestrationDeps.indexedDB,
      nearAccountId: toAccountId(args.nearAccountId),
      chain: args.chain,
      bootstrap: args.bootstrap,
      smartAccount: args.smartAccount,
      deployment: args.deployment,
    });
  }

  getWarmThresholdEd25519SessionStatus(
    nearAccountId: AccountId | string,
  ): Promise<SigningSessionStatus | null> {
    return createWarmSessionManager({
      touchConfirm: this.touchConfirm,
      signingSessionSeal: this.tatchiPasskeyConfigs.signing.sessionSeal,
    }).getEd25519SigningSessionStatus(nearAccountId);
  }

  getWarmThresholdEcdsaSessionStatus(
    nearAccountId: AccountId | string,
    chain: 'tempo' | 'evm',
  ): Promise<SigningSessionStatus | null> {
    return createWarmSessionManager({
      touchConfirm: this.touchConfirm,
      clearThresholdEcdsaSigningArtifactsForLane: ({ nearAccountId, chain }) =>
        this.clearThresholdEcdsaSigningArtifactsForLane({ nearAccountId, chain }),
      clearThresholdEcdsaSessionRecordForLane: ({ nearAccountId, chain }) =>
        this.clearThresholdEcdsaSessionRecordForLane({ nearAccountId, chain }),
      getThresholdEcdsaSessionRecordForSigning: ({ nearAccountId, chain }) =>
        this.getThresholdEcdsaSessionRecordForSigning({ nearAccountId, chain }),
      signingSessionSeal: this.tatchiPasskeyConfigs.signing.sessionSeal,
    }).getEcdsaSigningSessionStatus({ nearAccountId, chain });
  }

  async assertThresholdEcdsaOperationAllowed(args: {
    nearAccountId: AccountId | string;
    chain: 'tempo' | 'evm';
    operationLabel: string;
    thresholdSessionId?: string;
    sensitivePolicy?: WarmSessionSensitiveOperationPolicy;
  }): Promise<void> {
    await createWarmSessionManager({
      touchConfirm: this.touchConfirm,
      clearThresholdEcdsaSigningArtifactsForLane: ({ nearAccountId, chain }) =>
        this.clearThresholdEcdsaSigningArtifactsForLane({ nearAccountId, chain }),
      clearThresholdEcdsaSessionRecordForLane: ({ nearAccountId, chain }) =>
        this.clearThresholdEcdsaSessionRecordForLane({ nearAccountId, chain }),
      markThresholdEcdsaEmailOtpSessionConsumedForAccount: ({ nearAccountId, chain }) =>
        this.markThresholdEcdsaEmailOtpSessionConsumedForAccount({ nearAccountId, chain }),
      getThresholdEcdsaSessionRecordForSigning: ({ nearAccountId, chain }) =>
        this.getThresholdEcdsaSessionRecordForSigning({ nearAccountId, chain }),
      signingSessionSeal: this.tatchiPasskeyConfigs.signing.sessionSeal,
    }).assertEcdsaOperationAllowed(args);
  }

  async applyThresholdEcdsaPostSignPolicy(args: {
    nearAccountId: AccountId | string;
    chain: 'tempo' | 'evm';
    thresholdSessionId?: string;
  }): Promise<void> {
    await createWarmSessionManager({
      touchConfirm: this.touchConfirm,
      clearThresholdEcdsaSigningArtifactsForLane: ({ nearAccountId, chain }) =>
        this.clearThresholdEcdsaSigningArtifactsForLane({ nearAccountId, chain }),
      clearThresholdEcdsaSessionRecordForLane: ({ nearAccountId, chain }) =>
        this.clearThresholdEcdsaSessionRecordForLane({ nearAccountId, chain }),
      markThresholdEcdsaEmailOtpSessionConsumedForAccount: ({ nearAccountId, chain }) =>
        this.markThresholdEcdsaEmailOtpSessionConsumedForAccount({ nearAccountId, chain }),
      getThresholdEcdsaSessionRecordForSigning: ({ nearAccountId, chain }) =>
        this.getThresholdEcdsaSessionRecordForSigning({ nearAccountId, chain }),
      signingSessionSeal: this.tatchiPasskeyConfigs.signing.sessionSeal,
    }).applyEcdsaPostSignPolicy(args);
  }

  async scheduleThresholdEcdsaLoginPresignPrefill(args: {
    nearAccountId: AccountId | string;
    chain?: 'tempo' | 'evm';
    thresholdEcdsaKeyRef: ThresholdEcdsaSecp256k1KeyRef;
    minRemainingUsesBeforePrefill?: number;
  }): Promise<ThresholdEcdsaLoginPrefillResult> {
    const chain: 'tempo' | 'evm' = args.chain === 'evm' ? 'evm' : 'tempo';
    const warmSessionManager = createWarmSessionManager({
      touchConfirm: this.touchConfirm,
      clearThresholdEcdsaSigningArtifactsForLane: ({ nearAccountId, chain }) =>
        this.clearThresholdEcdsaSigningArtifactsForLane({ nearAccountId, chain }),
      clearThresholdEcdsaSessionRecordForLane: ({ nearAccountId, chain }) =>
        this.clearThresholdEcdsaSessionRecordForLane({ nearAccountId, chain }),
      getThresholdEcdsaSessionRecordForSigning: ({ nearAccountId, chain }) =>
        this.getThresholdEcdsaSessionRecordForSigning({ nearAccountId, chain }),
      signingSessionSeal: this.tatchiPasskeyConfigs.signing.sessionSeal,
    });
    return await scheduleThresholdEcdsaLoginPresignPrefillValue(
      {
        getWarmThresholdEcdsaSessionStatus: async (
          nearAccountId: AccountId | string,
          thresholdSessionId: string,
          chain: 'tempo' | 'evm',
        ) => {
          const canonicalSessionId =
            this.orchestrationDeps.resolveCanonicalThresholdEcdsaSessionIdForChain(
              nearAccountId,
              chain,
            );
          if (
            canonicalSessionId &&
            canonicalSessionId !== String(thresholdSessionId || '').trim()
          ) {
            return {
              sessionId: canonicalSessionId,
              status: 'not_found',
            };
          }
          return await warmSessionManager.getEcdsaSigningSessionStatus({
            nearAccountId,
            chain,
            thresholdSessionId,
          });
        },
        getSignerWorkerContext: () =>
          this.orchestrationDeps.thresholdSessionActivationDeps.getSignerWorkerContext(),
        thresholdEcdsaPresignPoolPolicy:
          this.tatchiPasskeyConfigs.signing.thresholdEcdsa.presignPool,
      },
      { ...args, chain },
    );
  }

  async hydrateSigningSession(args: {
    sessionId: string;
    prfFirstB64u: string;
    expiresAtMs: number;
    remainingUses: number;
    transport?: {
      curve?: 'ed25519' | 'ecdsa';
      relayerUrl?: string;
      thresholdSessionJwt?: string;
      keyVersion?: string;
      shamirPrimeB64u?: string;
    };
  }): Promise<void> {
    await cacheSigningSessionPrfFirstValue(this.touchConfirm, args);
  }

  async clearWarmSigningSessions(nearAccountId?: AccountId | string): Promise<void> {
    if (nearAccountId == null && hasWarmSessionMaterialClearAll(this.touchConfirm)) {
      await this.touchConfirm.clearAllWarmSessionMaterial().catch(() => undefined);
      return;
    }

    const sessionIds =
      nearAccountId != null ? this.collectWarmSigningSessionIdsForAccount(nearAccountId) : [];

    await Promise.all(
      sessionIds.map((sessionId) =>
        clearSigningSessionPrfFirstBestEffortValue(this.touchConfirm, sessionId),
      ),
    );
  }

  private async withThresholdEcdsaCommitQueue<T>(args: {
    queueKey: string;
    nearAccountId: AccountId | string;
    enabled: boolean;
    shouldAbort?: () => boolean;
    maxQueueLength?: number;
    queueTimeoutMs?: number;
    task: () => Promise<T>;
  }): Promise<T> {
    return await withThresholdEcdsaCommitQueue({
      queueByKey: this.thresholdEcdsaCommitQueueByKey,
      queueKey: args.queueKey,
      nearAccountId: args.nearAccountId,
      enabled: args.enabled,
      shouldAbort: args.shouldAbort,
      maxQueueLength: args.maxQueueLength,
      queueTimeoutMs: args.queueTimeoutMs,
      task: args.task,
    });
  }

  private async withThresholdEd25519CommitQueue<T>(args: {
    queueKey: string;
    nearAccountId: AccountId | string;
    enabled: boolean;
    shouldAbort?: () => boolean;
    maxQueueLength?: number;
    queueTimeoutMs?: number;
    task: () => Promise<T>;
  }): Promise<T> {
    return await withThresholdEd25519CommitQueue({
      queueByKey: this.thresholdEd25519CommitQueueByKey,
      queueKey: args.queueKey,
      nearAccountId: args.nearAccountId,
      enabled: args.enabled,
      shouldAbort: args.shouldAbort,
      maxQueueLength: args.maxQueueLength,
      queueTimeoutMs: args.queueTimeoutMs,
      task: args.task,
    });
  }

  clearThresholdEcdsaCommitQueue(): void {
    clearThresholdEcdsaCommitQueue(this.thresholdEcdsaCommitQueueByKey);
  }

  clearThresholdEd25519CommitQueue(): void {
    clearThresholdEd25519CommitQueue(this.thresholdEd25519CommitQueueByKey);
  }

  deriveThresholdEd25519ClientVerifyingShareFromCredential(
    args: Parameters<typeof deriveThresholdEd25519ClientVerifyingShareFromCredentialValue>[1],
  ): ReturnType<typeof deriveThresholdEd25519ClientVerifyingShareFromCredentialValue> {
    return deriveThresholdEd25519ClientVerifyingShareFromCredentialValue(
      this.orchestrationDeps.thresholdEd25519LifecycleDeps,
      args,
    );
  }

  deriveThresholdEd25519HssClientInputsFromCredential(
    args: Parameters<typeof deriveThresholdEd25519HssClientInputsFromCredentialValue>[1],
  ): ReturnType<typeof deriveThresholdEd25519HssClientInputsFromCredentialValue> {
    return deriveThresholdEd25519HssClientInputsFromCredentialValue(
      this.orchestrationDeps.thresholdEd25519LifecycleDeps,
      args,
    );
  }

  prepareThresholdEd25519HssClientCeremonyFromCredential(
    args: Parameters<typeof prepareThresholdEd25519HssClientCeremonyFromCredentialValue>[1],
  ): ReturnType<typeof prepareThresholdEd25519HssClientCeremonyFromCredentialValue> {
    return prepareThresholdEd25519HssClientCeremonyFromCredentialValue(
      this.orchestrationDeps.thresholdEd25519LifecycleDeps,
      args,
    );
  }

  prepareThresholdEd25519HssClientRequest(
    args: Omit<Parameters<typeof prepareThresholdEd25519HssClientRequestWasm>[0], 'workerCtx'>,
  ): ReturnType<typeof prepareThresholdEd25519HssClientRequestWasm> {
    return prepareThresholdEd25519HssClientRequestWasm({
      ...args,
      workerCtx: this.orchestrationDeps.thresholdSessionActivationDeps.getSignerWorkerContext(),
    });
  }

  completeThresholdEd25519HssClientCeremony(
    args: Omit<Parameters<typeof completeThresholdEd25519HssClientCeremonyValue>[0], 'workerCtx'>,
  ): ReturnType<typeof completeThresholdEd25519HssClientCeremonyValue> {
    return completeThresholdEd25519HssClientCeremonyValue({
      ...args,
      workerCtx: this.orchestrationDeps.thresholdSessionActivationDeps.getSignerWorkerContext(),
    });
  }

  runThresholdEd25519HssCeremonyWithSession(
    args: Omit<Parameters<typeof runThresholdEd25519HssCeremonyWithSessionValue>[0], 'workerCtx'>,
  ): ReturnType<typeof runThresholdEd25519HssCeremonyWithSessionValue> {
    return runThresholdEd25519HssCeremonyWithSessionValue({
      ...args,
      workerCtx: this.orchestrationDeps.thresholdSessionActivationDeps.getSignerWorkerContext(),
    });
  }

  openThresholdEd25519HssSeedOutput(
    args: Omit<Parameters<typeof openThresholdEd25519HssSeedOutputValue>[0], 'workerCtx'>,
  ): ReturnType<typeof openThresholdEd25519HssSeedOutputValue> {
    return openThresholdEd25519HssSeedOutputValue({
      ...args,
      workerCtx: this.orchestrationDeps.thresholdSessionActivationDeps.getSignerWorkerContext(),
    });
  }

  buildThresholdEd25519SeedExportArtifactFromHssReport(
    args: Omit<
      Parameters<typeof buildThresholdEd25519SeedExportArtifactFromHssReportValue>[0],
      'workerCtx'
    >,
  ): ReturnType<typeof buildThresholdEd25519SeedExportArtifactFromHssReportValue> {
    return buildThresholdEd25519SeedExportArtifactFromHssReportValue({
      ...args,
      workerCtx: this.orchestrationDeps.thresholdSessionActivationDeps.getSignerWorkerContext(),
    });
  }

  destroy(): void {
    this.userPreferencesManager.destroy();
    this.nonceManager.clear();
    this.clearThresholdEcdsaCommitQueue();
    this.clearAllThresholdEcdsaSessionRecords();
  }

  private collectWarmSigningSessionIdsForAccount(nearAccountId: AccountId | string): string[] {
    const sessionIds = new Set<string>();
    const ed25519SessionId = String(
      getStoredThresholdEd25519SessionRecordForAccountValue(nearAccountId)?.thresholdSessionId ||
        '',
    ).trim();
    if (ed25519SessionId) {
      sessionIds.add(ed25519SessionId);
    }
    for (const chain of ['tempo', 'evm'] as const) {
      try {
        const ecdsaSessionId = String(
          getThresholdEcdsaSessionRecordForSigningValue(
            {
              recordsByLane: this.thresholdEcdsaSessionByLane,
              exportArtifactsByLane: this.thresholdEcdsaExportArtifactByLane,
            },
            { nearAccountId, chain },
          )?.thresholdSessionId || '',
        ).trim();
        if (ecdsaSessionId) {
          sessionIds.add(ecdsaSessionId);
        }
      } catch {}
    }
    return [...sessionIds];
  }
}

/**
 * Boundary-facing API contract for SigningEngine consumers.
 * Keep this narrow and intentional; prefer adding methods here explicitly.
 */
export type SigningEnginePublic = Pick<
  SigningEngine,
  | 'tatchiPasskeyConfigs'
  | 'setTheme'
  | 'getUserPreferences'
  | 'getRpId'
  | 'getNonceManager'
  | 'warmCriticalResources'
  | 'assertSealedRefreshStartupParity'
  | 'signNear'
  | 'signTempo'
  | 'reportTempoBroadcastAccepted'
  | 'reportTempoBroadcastRejected'
  | 'reportTempoFinalized'
  | 'reportTempoDroppedOrReplaced'
  | 'reconcileTempoNonceLane'
  | 'storeUserData'
  | 'getAllUsers'
  | 'getUserByDevice'
  | 'getLastUser'
  | 'getAuthenticatorsByUser'
  | 'updateLastLogin'
  | 'setLastUser'
  | 'initializeCurrentUser'
  | 'storeAuthenticator'
  | 'rollbackUserRegistration'
  | 'hasPasskeyCredential'
  | 'atomicStoreRegistrationData'
  | 'requestRegistrationCredentialConfirmation'
  | 'getAuthenticationCredentialsSerialized'
  | 'extractCosePublicKey'
  | 'exportKeypairWithUI'
  | 'exportNearEd25519SeedArtifactWithUI'
  | 'exportThresholdEd25519SeedFromHssReport'
  | 'signTransactionWithKeyPair'
  | 'generateEphemeralNearKeypair'
  | 'connectEd25519Session'
  | 'bootstrapEcdsaSession'
  | 'upsertThresholdEcdsaSessionFromBootstrap'
  | 'getThresholdEcdsaKeyRefForSigning'
  | 'getThresholdEcdsaSessionRecordForSigning'
  | 'clearThresholdEcdsaSessionRecordForAccount'
  | 'clearAllThresholdEcdsaSessionRecords'
  | 'persistThresholdEcdsaBootstrapChainAccount'
  | 'getWarmThresholdEd25519SessionStatus'
  | 'getWarmThresholdEcdsaSessionStatus'
  | 'assertThresholdEcdsaOperationAllowed'
  | 'applyThresholdEcdsaPostSignPolicy'
  | 'scheduleThresholdEcdsaLoginPresignPrefill'
  | 'hydrateSigningSession'
  | 'clearWarmSigningSessions'
  | 'clearThresholdEcdsaCommitQueue'
  | 'deriveThresholdEd25519ClientVerifyingShareFromCredential'
  | 'deriveThresholdEd25519HssClientInputsFromCredential'
  | 'prepareThresholdEd25519HssClientCeremonyFromCredential'
  | 'prepareThresholdEd25519HssClientRequest'
  | 'completeThresholdEd25519HssClientCeremony'
  | 'runThresholdEd25519HssCeremonyWithSession'
  | 'openThresholdEd25519HssSeedOutput'
  | 'buildThresholdEd25519SeedExportArtifactFromHssReport'
>;
