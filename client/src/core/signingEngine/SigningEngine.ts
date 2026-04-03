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
import type { SigningSessionStatus, TatchiConfigsReadonly, ThemeName } from '../types/tatchi';
import type { WebAuthnAuthenticationCredential, WebAuthnRegistrationCredential } from '../types';
import type { UserPreferencesManager } from './api/userPreferences';
import type { ThresholdEcdsaSecp256k1KeyRef } from './interfaces/signing';
import type {
  ThresholdEcdsaActivationChain,
  ThresholdEcdsaSessionBootstrapResult,
} from './orchestration/thresholdActivation';
import type { SignerWorkerManager } from './workerManager';
import type { RegistrationCredentialConfirmationPayload } from './workerManager/validation';
import type {
  TouchConfirmRuntimeBridgePort,
  ThresholdPrfFirstCacheClearAllPort,
} from './touchConfirm/types';
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
import { deriveThresholdSecp256k1ClientShareWasm } from './signers/wasm/ethSignerWasm';
import {
  connectEd25519SessionValue,
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
  clearThresholdEcdsaSessionRecordForAccount as clearThresholdEcdsaSessionRecordForAccountValue,
  getThresholdEcdsaKeyRefForSigning as getThresholdEcdsaKeyRefForSigningValue,
  getThresholdEcdsaSessionRecordForSigning as getThresholdEcdsaSessionRecordForSigningValue,
  getStoredThresholdEd25519SessionRecordForAccount as getStoredThresholdEd25519SessionRecordForAccountValue,
  upsertThresholdEcdsaSessionFromBootstrap as upsertThresholdEcdsaSessionFromBootstrapValue,
  type ThresholdEcdsaSessionRecord,
  type ThresholdEcdsaSessionStoreSource,
} from './api/thresholdLifecycle/thresholdSessionStore';
import {
  scheduleThresholdEcdsaLoginPresignPrefill as scheduleThresholdEcdsaLoginPresignPrefillValue,
  type ThresholdEcdsaLoginPrefillResult,
} from './api/thresholdLifecycle/thresholdEcdsaLoginPrefill';
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
  clearSigningSessionPrfFirstBestEffort as clearSigningSessionPrfFirstBestEffortValue,
  clearAllActiveSigningSessionIds as clearAllActiveSigningSessionIdsValue,
  clearAllActiveSigningSessionIdsForAccount as clearAllActiveSigningSessionIdsForAccountValue,
  getWarmSigningSessionStatusForKind as getWarmSigningSessionStatusForKindValue,
  hydrateSigningSession as hydrateSigningSessionValue,
  type ActiveSigningSessionKind,
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
  exportKeypairWithUI as exportKeypairWithUIValue,
  exportNearEd25519SeedArtifactWithUI as exportNearEd25519SeedArtifactWithUIValue,
} from './api/recovery/privateKeyExportRecovery';
import { getLastLoggedInDeviceNumber } from './signers/webauthn/device/getDeviceNumber';
import { removeExportViewerHostIfPresent } from './touchConfirm/ui/export-viewer-host';
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
import { deriveThresholdEd25519HssClientInputsWasm } from './signers/wasm/nearSignerWasm';
import {
  prepareThresholdEd25519HssClientRequestWasm,
  prepareThresholdEd25519HssSessionWasm,
} from './signers/wasm/nearSignerHssWasm';
import {
  THRESHOLD_ED25519_HSS_DERIVATION_VERSION,
  THRESHOLD_ED25519_HSS_SIGNING_KEY_PURPOSE,
} from './orchestration/near/shared/ensureThresholdEd25519HssClientBase';
import {
  createOrchestrationDependencyBundle,
  type OrchestrationDependencyBundle,
} from './bootstrap/orchestrationDependencyFactory';

export type {
  ThresholdEcdsaActivationChain,
  ThresholdEcdsaSessionBootstrapResult,
} from './orchestration/thresholdActivation';
export type { NearSignIntentRequest, NearSignIntentResult } from './api/nearSigning';
export type { ThresholdEcdsaLoginPrefillResult } from './api/thresholdLifecycle/thresholdEcdsaLoginPrefill';

function hasThresholdPrfFirstCacheClearAllPort(
  value: unknown,
): value is ThresholdPrfFirstCacheClearAllPort {
  return (
    typeof (value as { clearAllPrfFirstForThresholdSessions?: unknown })
      ?.clearAllPrfFirstForThresholdSessions === 'function'
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
    this.touchConfirm = assembly.touchConfirm;
    this.signerWorkerManager = assembly.signerWorkerManager;

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
      bootstrapThresholdEcdsaSession: (args) => this.bootstrapEcdsaSession(args),
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

  private async ensureSealedRefreshStartupParity(): Promise<void> {
    await this.sealedRefreshStartupParityPromise;
    if (this.sealedRefreshStartupParityError) {
      throw this.sealedRefreshStartupParityError;
    }
  }

  async assertSealedRefreshStartupParity(): Promise<void> {
    await this.ensureSealedRefreshStartupParity();
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
      const optionAResult = await this.tryExportNearEd25519OptionAFromWarmSession({
        nearAccountId: args.nearAccountId,
        options: {
          variant: args.options.variant,
          theme: args.options.theme,
        },
      });
      if (optionAResult) return optionAResult;
      throw new Error('NEAR Ed25519 export now requires the canonical Option A HSS export path');
    }

    return exportKeypairWithUIValue(this.orchestrationDeps.privateKeyExportRecoveryDeps, {
      nearAccountId: args.nearAccountId,
      options: args.options,
    });
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

  private async requestNearEd25519ExportAuthorization(args: {
    nearAccountId: AccountId;
    expectedPublicKey: string;
  }): Promise<void> {
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

  private async runNearEd25519OptionAHssExport(args: {
    orgId: string;
    nearAccountId: AccountId;
    keyVersion: string;
    participantIds: number[];
    thresholdSessionId: string;
    thresholdSessionJwt: string;
    relayerUrl: string;
    relayerKeyId: string;
  }): Promise<{
    preparedSession: Parameters<
      typeof buildThresholdEd25519SeedExportArtifactFromHssReportValue
    >[0]['preparedSession'];
    finalizedReport: Parameters<
      typeof buildThresholdEd25519SeedExportArtifactFromHssReportValue
    >[0]['finalizedReport'];
  }> {
    const dispensed = await this.touchConfirm.dispensePrfFirstForThresholdSession({
      sessionId: args.thresholdSessionId,
    });
    if (!dispensed.ok || !String(dispensed.prfFirstB64u || '').trim()) {
      throw new Error('Missing warm PRF material for Option A Ed25519 export');
    }

    const preparedSession = await prepareThresholdEd25519HssSessionWasm({
      context: {
        orgId: args.orgId,
        nearAccountId: args.nearAccountId,
        keyPurpose: THRESHOLD_ED25519_HSS_SIGNING_KEY_PURPOSE,
        keyVersion: args.keyVersion,
        participantIds: args.participantIds,
        derivationVersion: THRESHOLD_ED25519_HSS_DERIVATION_VERSION,
      },
    });

    const clientInputs = await deriveThresholdEd25519HssClientInputsWasm({
      sessionId: `${args.thresholdSessionId}:hss-export-client-inputs`,
      orgId: args.orgId,
      nearAccountId: args.nearAccountId,
      keyPurpose: THRESHOLD_ED25519_HSS_SIGNING_KEY_PURPOSE,
      keyVersion: args.keyVersion,
      participantIds: preparedSession.participantIds,
      derivationVersion: THRESHOLD_ED25519_HSS_DERIVATION_VERSION,
      prfFirstB64u: String(dispensed.prfFirstB64u || '').trim(),
      workerCtx: this.orchestrationDeps.thresholdSessionActivationDeps.getSignerWorkerContext(),
    });

    const clientRequest = await prepareThresholdEd25519HssClientRequestWasm({
      preparedSession,
      clientInputs,
    });

    const completed = await runThresholdEd25519HssCeremonyWithSessionValue({
      relayerUrl: args.relayerUrl,
      thresholdSessionJwt: args.thresholdSessionJwt,
      relayerKeyId: args.relayerKeyId,
      preparedSession,
      clientRequest,
    });
    if (!completed.success || !completed.finalizedReport) {
      throw new Error(completed.error || 'Failed to finalize Option A Ed25519 export ceremony');
    }

    return {
      preparedSession,
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

  private async tryExportNearEd25519OptionAFromWarmSession(args: {
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

    const warmStatus = await getWarmSigningSessionStatusForKindValue(
      this.orchestrationDeps.signingSessionStateDeps,
      {
        nearAccountId,
        signerKind: 'threshold-ed25519',
      },
    );
    if (
      !warmStatus ||
      warmStatus.status !== 'active' ||
      String(warmStatus.sessionId || '').trim() !== thresholdSessionId
    ) {
      requireOptionAExportPrerequisite(
        false,
        'Missing active warm threshold session for Option A Ed25519 export',
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

    const hssTask = this.runNearEd25519OptionAHssExport({
      orgId,
      nearAccountId,
      keyVersion,
      participantIds,
      thresholdSessionId,
      thresholdSessionJwt,
      relayerUrl,
      relayerKeyId,
    });
    let hssSettled = false;
    const trackedHssTask = hssTask.finally(() => {
      hssSettled = true;
    });
    void trackedHssTask.catch(() => undefined);

    try {
      await this.requestNearEd25519ExportAuthorization({
        nearAccountId,
        expectedPublicKey,
      });

      if (!hssSettled) {
        await this.showNearEd25519ExportViewer({
          nearAccountId,
          expectedPublicKey,
          variant: args.options.variant,
          theme: args.options.theme,
          loading: true,
        });
      }

      const { preparedSession, finalizedReport } = await trackedHssTask;
      const artifactResult = await buildThresholdEd25519SeedExportArtifactFromHssReportValue({
        preparedSession,
        finalizedReport,
        expectedPublicKey,
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
      if (!hssSettled) {
        void trackedHssTask.catch(() => undefined);
      }
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

  connectEd25519Session(
    args: Parameters<typeof connectEd25519SessionValue>[1],
  ): ReturnType<typeof connectEd25519SessionValue> {
    return connectEd25519SessionValue(this.orchestrationDeps.thresholdSessionActivationDeps, args);
  }

  async bootstrapEcdsaSession(
    args: Parameters<typeof bootstrapEcdsaSessionValue>[1],
  ): Promise<ThresholdEcdsaSessionBootstrapResult> {
    await this.ensureSealedRefreshStartupParity();
    const nearAccountId = toAccountId(args.nearAccountId);
    const chain: ThresholdEcdsaActivationChain = args.chain || 'tempo';
    const normalizedAuthorizationJwt = String(args.authorizationJwt || '').trim();
    const normalizedSessionId = String(args.sessionId || '').trim();
    const normalizedClientVerifyingShareB64u = String(
      args.clientVerifyingShareB64u || '',
    ).trim();
    const normalizedParticipantIds = Array.isArray(args.participantIds)
      ? args.participantIds.map((value) => Number(value)).filter((value) => Number.isFinite(value))
      : [];

    let inferredAuthorizationJwt = normalizedAuthorizationJwt;
    let inferredSessionId = normalizedSessionId;
    let inferredClientVerifyingShareB64u = normalizedClientVerifyingShareB64u;
    let inferredParticipantIds = normalizedParticipantIds;

    const ed25519Record = getStoredThresholdEd25519SessionRecordForAccountValue(nearAccountId);
    if (!inferredAuthorizationJwt) {
      const ed25519Jwt = String(ed25519Record?.thresholdSessionJwt || '').trim();
      if (ed25519Jwt && ed25519Record?.thresholdSessionKind === 'jwt') {
        inferredAuthorizationJwt = ed25519Jwt;
      }
    }
    if (!inferredSessionId) {
      inferredSessionId = String(ed25519Record?.thresholdSessionId || '').trim();
    }
    if (inferredParticipantIds.length === 0 && Array.isArray(ed25519Record?.participantIds)) {
      inferredParticipantIds = ed25519Record.participantIds
        .map((value) => Number(value))
        .filter((value) => Number.isFinite(value));
    }

    const candidateChains: ThresholdEcdsaActivationChain[] =
      chain === 'tempo' ? ['tempo', 'evm'] : ['evm', 'tempo'];
    for (const candidateChain of candidateChains) {
      if (
        inferredAuthorizationJwt &&
        inferredSessionId &&
        inferredClientVerifyingShareB64u &&
        inferredParticipantIds.length > 0
      ) {
        break;
      }
      try {
        const record = getThresholdEcdsaSessionRecordForSigningValue(
          {
            recordsByLane: this.thresholdEcdsaSessionByLane,
          },
          {
            nearAccountId,
            chain: candidateChain,
          },
        );
        if (!inferredAuthorizationJwt && record.thresholdSessionKind === 'jwt') {
          inferredAuthorizationJwt = String(record.thresholdSessionJwt || '').trim();
        }
        if (!inferredSessionId) {
          inferredSessionId = String(record.thresholdSessionId || '').trim();
        }
        if (!inferredClientVerifyingShareB64u) {
          inferredClientVerifyingShareB64u = String(record.clientVerifyingShareB64u || '').trim();
        }
        if (inferredParticipantIds.length === 0 && Array.isArray(record.participantIds)) {
          inferredParticipantIds = record.participantIds
            .map((value) => Number(value))
            .filter((value) => Number.isFinite(value));
        }
      } catch {}
    }

    return await this.withThresholdEcdsaBootstrapQueue(nearAccountId, async () => {
      return await bootstrapEcdsaSessionValue(
        this.orchestrationDeps.thresholdSessionActivationDeps,
        {
          ...args,
          nearAccountId,
          chain,
          ...(inferredAuthorizationJwt ? { authorizationJwt: inferredAuthorizationJwt } : {}),
          ...(inferredSessionId ? { sessionId: inferredSessionId } : {}),
          ...(inferredClientVerifyingShareB64u
            ? { clientVerifyingShareB64u: inferredClientVerifyingShareB64u }
            : {}),
          ...(inferredParticipantIds.length > 0 ? { participantIds: inferredParticipantIds } : {}),
        },
      );
    });
  }

  upsertThresholdEcdsaSessionFromBootstrap(args: {
    nearAccountId: AccountId | string;
    chain: ThresholdEcdsaActivationChain;
    bootstrap: ThresholdEcdsaSessionBootstrapResult;
    source: ThresholdEcdsaSessionStoreSource;
  }): void {
    upsertThresholdEcdsaSessionFromBootstrapValue(
      {
        recordsByLane: this.thresholdEcdsaSessionByLane,
      },
      args,
    );
  }

  getThresholdEcdsaKeyRefForSigning(args: {
    nearAccountId: AccountId | string;
    chain: ThresholdEcdsaActivationChain;
  }): ThresholdEcdsaSecp256k1KeyRef {
    return getThresholdEcdsaKeyRefForSigningValue(
      {
        recordsByLane: this.thresholdEcdsaSessionByLane,
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
      },
      nearAccountId,
    );
  }

  clearAllThresholdEcdsaSessionRecords(): void {
    clearAllThresholdEcdsaSessionRecordsValue({
      recordsByLane: this.thresholdEcdsaSessionByLane,
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
    return this.orchestrationDeps
      .getManagerConvenienceDeps()
      .getWarmThresholdEd25519SessionStatus(nearAccountId);
  }

  getWarmThresholdEcdsaSessionStatus(
    nearAccountId: AccountId | string,
    chain: 'tempo' | 'evm',
  ): Promise<SigningSessionStatus | null> {
    return getWarmSigningSessionStatusForKindValue(this.orchestrationDeps.signingSessionStateDeps, {
      nearAccountId,
      signerKind: chain === 'tempo' ? 'threshold-ecdsa-tempo' : 'threshold-ecdsa-evm',
    });
  }

  async scheduleThresholdEcdsaLoginPresignPrefill(args: {
    nearAccountId: AccountId | string;
    chain?: 'tempo' | 'evm';
    thresholdEcdsaKeyRef: ThresholdEcdsaSecp256k1KeyRef;
    minRemainingUsesBeforePrefill?: number;
  }): Promise<ThresholdEcdsaLoginPrefillResult> {
    const chain: 'tempo' | 'evm' = args.chain === 'evm' ? 'evm' : 'tempo';
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
          return await getWarmSigningSessionStatusForKindValue(
            this.orchestrationDeps.signingSessionStateDeps,
            {
              nearAccountId,
              signerKind: chain === 'tempo' ? 'threshold-ecdsa-tempo' : 'threshold-ecdsa-evm',
            },
          );
        },
        dispensePrfFirstForThresholdSession: (payload) =>
          this.touchConfirm.dispensePrfFirstForThresholdSession(payload),
        getSignerWorkerContext: () =>
          this.orchestrationDeps.thresholdSessionActivationDeps.getSignerWorkerContext(),
        thresholdEcdsaPresignPoolPolicy:
          this.tatchiPasskeyConfigs.signing.thresholdEcdsa.presignPool,
      },
      { ...args, chain },
    );
  }

  async hydrateSigningSession(args: {
    nearAccountId: AccountId | string;
    signerKind: ActiveSigningSessionKind;
    sessionId: string;
    prfFirstB64u: string;
    expiresAtMs: number;
    remainingUses: number;
    setActiveSigningSessionId?: boolean;
  }): Promise<void> {
    await hydrateSigningSessionValue(this.orchestrationDeps.signingSessionStateDeps, args);
  }

  async clearWarmSigningSessions(nearAccountId?: AccountId | string): Promise<void> {
    const sessionIds =
      nearAccountId != null
        ? clearAllActiveSigningSessionIdsForAccountValue(
            this.orchestrationDeps.signingSessionStateDeps,
            nearAccountId,
          )
        : clearAllActiveSigningSessionIdsValue(this.orchestrationDeps.signingSessionStateDeps);

    if (nearAccountId == null && hasThresholdPrfFirstCacheClearAllPort(this.touchConfirm)) {
      await this.touchConfirm.clearAllPrfFirstForThresholdSessions().catch(() => undefined);
      return;
    }

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

  completeThresholdEd25519HssClientCeremony(
    args: Parameters<typeof completeThresholdEd25519HssClientCeremonyValue>[0],
  ): ReturnType<typeof completeThresholdEd25519HssClientCeremonyValue> {
    return completeThresholdEd25519HssClientCeremonyValue(args);
  }

  runThresholdEd25519HssCeremonyWithSession(
    args: Parameters<typeof runThresholdEd25519HssCeremonyWithSessionValue>[0],
  ): ReturnType<typeof runThresholdEd25519HssCeremonyWithSessionValue> {
    return runThresholdEd25519HssCeremonyWithSessionValue(args);
  }

  openThresholdEd25519HssSeedOutput(
    args: Parameters<typeof openThresholdEd25519HssSeedOutputValue>[0],
  ): ReturnType<typeof openThresholdEd25519HssSeedOutputValue> {
    return openThresholdEd25519HssSeedOutputValue(args);
  }

  buildThresholdEd25519SeedExportArtifactFromHssReport(
    args: Parameters<typeof buildThresholdEd25519SeedExportArtifactFromHssReportValue>[0],
  ): ReturnType<typeof buildThresholdEd25519SeedExportArtifactFromHssReportValue> {
    return buildThresholdEd25519SeedExportArtifactFromHssReportValue(args);
  }

  async deriveThresholdEcdsaClientVerifyingShareFromCredential(args: {
    credential: WebAuthnRegistrationCredential | WebAuthnAuthenticationCredential;
    nearAccountId: AccountId | string;
  }): Promise<
    Awaited<ReturnType<typeof deriveThresholdEd25519ClientVerifyingShareFromCredentialValue>>
  > {
    const nearAccountId = toAccountId(args.nearAccountId);
    try {
      const prfFirstB64u = String(getPrfResultsFromCredential(args.credential).first || '').trim();
      if (!prfFirstB64u) {
        throw new Error(
          'Missing PRF.first output from credential (requires a PRF-enabled passkey)',
        );
      }
      const workerCtx =
        this.orchestrationDeps.thresholdSessionActivationDeps.getSignerWorkerContext();
      const derived = await deriveThresholdSecp256k1ClientShareWasm({
        prfFirstB64u,
        userId: nearAccountId,
        workerCtx,
      });
      return {
        success: true,
        nearAccountId,
        clientVerifyingShareB64u: derived.clientVerifyingShareB64u,
      };
    } catch (error: unknown) {
      const message = String((error as { message?: unknown })?.message ?? error);
      return {
        success: false,
        nearAccountId,
        clientVerifyingShareB64u: '',
        error: message,
      };
    }
  }

  destroy(): void {
    this.userPreferencesManager.destroy();
    this.nonceManager.clear();
    clearAllActiveSigningSessionIdsValue(this.orchestrationDeps.signingSessionStateDeps);
    this.clearThresholdEcdsaCommitQueue();
    this.clearAllThresholdEcdsaSessionRecords();
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
  | 'scheduleThresholdEcdsaLoginPresignPrefill'
  | 'hydrateSigningSession'
  | 'clearWarmSigningSessions'
  | 'clearThresholdEcdsaCommitQueue'
  | 'deriveThresholdEd25519ClientVerifyingShareFromCredential'
  | 'deriveThresholdEd25519HssClientInputsFromCredential'
  | 'prepareThresholdEd25519HssClientCeremonyFromCredential'
  | 'completeThresholdEd25519HssClientCeremony'
  | 'runThresholdEd25519HssCeremonyWithSession'
  | 'openThresholdEd25519HssSeedOutput'
  | 'buildThresholdEd25519SeedExportArtifactFromHssReport'
  | 'deriveThresholdEcdsaClientVerifyingShareFromCredential'
>;
