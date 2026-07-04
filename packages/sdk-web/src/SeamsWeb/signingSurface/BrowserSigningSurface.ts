import type { DurableRecordStore, RuntimePorts } from '@/core/platform';
import type { NearClient } from '@/core/rpcClients/near/NearClient';
import type { NonceCoordinator } from '@/core/signingEngine/nonce/NonceCoordinator';
import { toAccountId, type AccountId } from '@/core/types/accountIds';
import type { SigningFlowEvent } from '@/core/types/sdkSentEvents';
import type {
  SigningSessionStatus,
  SeamsConfigsReadonly,
  ThemeName,
} from '@/core/types/seams';
import type { WebAuthnAuthenticationCredential } from '@/core/types';
import { type WalletEmailOtpChannel } from '@shared/utils/emailOtpDomain';
import type { UserPreferencesManager } from '@/core/signingEngine/session/userPreferences';
import type { ThresholdEcdsaCanonicalExportArtifact } from '@/core/signingEngine/interfaces/signing';
import type { ThresholdEcdsaSessionBootstrapResult } from '@/core/signingEngine/threshold/ecdsa/activation';
import type { SignerWorkerManager } from '@/core/signingEngine/workerManager/SignerWorkerManager';
import type { SigningRuntime } from '@/core/runtime/runtime.types';
import type {
  SignerWorkerKind,
  SignerWorkerOperationRequest,
  SignerWorkerOperationResult,
  SignerWorkerOperationType,
} from '@/core/signingEngine/workerManager/workerTypes';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import type { UiConfirmRuntimeBridgePort } from '@/core/signingEngine/uiConfirm/uiConfirm.types';
import type { TouchIdPrompt } from '@/core/signingEngine/stepUpConfirmation/passkeyPrompt/touchIdPrompt';
import type { RegistrationActivationProof } from '@/core/signingEngine/stepUpConfirmation/channel/confirmTypes';
import type { WarmSessionEd25519UnsealAuthorizationPutPayload } from '@/core/types/secure-confirm-worker';
import type { WebAuthnAllowCredential } from '@/core/signingEngine/webauthnAuth/credentials/collectAuthenticationCredentialForChallengeB64u';
import type { EvmSigningRequest } from '@/core/signingEngine/chains/evm/evmSigning.types';
import type { EvmSignedResult } from '@/core/signingEngine/chains/evm/evmAdapter';
import type { TempoSigningRequest } from '@/core/signingEngine/chains/tempo/tempoSigning.types';
import type { TempoSignedResult } from '@/core/signingEngine/chains/tempo/tempoAdapter';
import type { EcdsaBootstrapRequest } from '@/core/signingEngine/session/passkey/ecdsaBootstrap';
import * as thresholdEd25519Public from '@/core/signingEngine/threshold/ed25519/public';
import { type ThresholdEcdsaBootstrapStorePort } from '@/core/signingEngine/session/warmCapabilities/ecdsaBootstrapPersistence';
import { type ThresholdEcdsaSessionRecord } from '@/core/signingEngine/session/persistence/records';
import {
  type ThresholdEcdsaChainTarget,
  type WalletId,
  type WalletSessionRef,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { type RouterAbEcdsaHssLoginPresignaturePrefillResult } from '@/core/signingEngine/session/warmCapabilities/ecdsaLoginPrefill';
import {
  signNear as signNearOperation,
  type NearSignIntentRequest,
  type NearSignIntentResult,
} from '@/core/signingEngine/flows/signNear/signNear';
import {
  reconcileTempoNonceLane as reconcileTempoNonceLaneOperation,
  reportTempoBroadcastAccepted as reportTempoBroadcastAcceptedOperation,
  reportTempoBroadcastRejected as reportTempoBroadcastRejectedOperation,
  reportTempoDroppedOrReplaced as reportTempoDroppedOrReplacedOperation,
  reportTempoFinalized as reportTempoFinalizedOperation,
  signEvmFamily as signEvmFamilyOperation,
  type ReconcileTempoNonceLaneArgs,
  type ReportTempoBroadcastAcceptedArgs,
  type ReportTempoBroadcastRejectedArgs,
  type ReportTempoDroppedOrReplacedArgs,
  type ReportTempoFinalizedArgs,
  type TempoNonceLaneStatus,
} from '@/core/signingEngine/flows/signEvmFamily/signEvmFamily';
import {
  clearThresholdEcdsaCommitQueue,
  type ThresholdEcdsaCommitQueueByKey,
} from '@/core/signingEngine/threshold/ecdsa/commitQueue';
import { type ThresholdEd25519CommitQueueByKey } from '@/core/signingEngine/threshold/ed25519/commitQueue';
import { clearAllRouterAbEd25519ClientPresigns } from '@/core/signingEngine/threshold/ed25519/presignPool';
import * as recoveryPublic from '@/core/signingEngine/flows/recovery/public';
import type {
  SigningEngineResolveExactKeyExportLaneInput,
  SigningEngineResolveExactKeyExportLaneResult,
  RecoveryPublicDeps,
  SigningEngineExportKeypairWithUIInput,
  KeyExportEventCallback,
} from '@/core/signingEngine/flows/recovery/public';
import type { RegistrationCredentialConfirmationPayload } from '@/core/signingEngine/workerManager/validation';
import type { ConfirmationConfig } from '@/core/types/signer-worker';
import * as registrationPublic from '@/core/signingEngine/flows/registration/public';
import {
  type EmailOtpPublicDeps,
  type EnrollAndLoginWithEmailOtpEcdsaCapabilityInternalArgs,
  type EnrollAndLoginWithEmailOtpEcdsaCapabilityInternalResult,
  type LoginWithEmailOtpEd25519CapabilityInternalArgs,
  type LoginWithEmailOtpEd25519CapabilityInternalResult,
  type LoginWithEmailOtpEcdsaCapabilityInternalArgs,
  type LoginWithEmailOtpEcdsaCapabilityInternalResult,
  type PrepareEmailOtpRegistrationEnrollmentMaterialInternalArgs,
  type PrepareEmailOtpRegistrationEnrollmentMaterialInternalResult,
} from '@/core/signingEngine/flows/signEvmFamily/emailOtpPublic';
import * as emailOtpPublic from '@/core/signingEngine/flows/signEvmFamily/emailOtpPublic';
import { createManagerAssembly } from '@/core/signingEngine/assembly/createManagers';
import { verifySealedRefreshStartupParity } from '@/core/rpcClients/relayer/sealedRefreshCapabilities';
import {
  ensureSealedRefreshStartupParityForThresholdEcdsaBootstrap,
  isRetryableSealedRefreshCapabilityFetchError,
  type ThresholdEcdsaBootstrapParityArgs,
} from '@/core/signingEngine/session/warmCapabilities/sealedRefreshParity';
import type { EmailOtpWalletSessionCoordinator } from '@/core/signingEngine/session/emailOtp/EmailOtpWalletSessionCoordinator';
import type { WarmSessionEcdsaCapabilityState } from '@/core/signingEngine/session/warmCapabilities/types';
import type {
  ProvisionWarmEd25519CapabilityResult,
  WarmEcdsaSigningSessionStatus,
} from '@/core/signingEngine/session/warmCapabilities/types';
import type { EmailOtpBootstrapRecovery } from '@/core/signingEngine/stepUpConfirmation/otpPrompt/bootstrapRecovery';
import type {
  DiscoverPersistedSessionsForWalletInput,
  DiscoverPersistedSessionsForWalletResult,
  ReadAvailableSigningLanesInput,
  AvailableSigningLanes,
  SessionPublicDeps,
  ThresholdEcdsaSessionRecord as SessionPublicThresholdEcdsaSessionRecord,
  ListThresholdEcdsaSessionRecordsForWalletTargetInput,
} from '@/core/signingEngine/session/public';
import * as sessionPublic from '@/core/signingEngine/session/public';
import {
  createWarmSigningPorts,
  type WarmSigningPorts,
} from '@/core/signingEngine/assembly/ports/warmSigning';
import { createSessionPublicDeps } from '@/core/signingEngine/assembly/ports/session';
import * as warmCapabilitiesPublic from '@/core/signingEngine/session/warmCapabilities/public';
import type { WarmCapabilitiesPublicDeps } from '@/core/signingEngine/session/warmCapabilities/public';
import * as passkeyPublic from '@/core/signingEngine/session/passkey/public';
import type {
  ConnectEd25519SessionArgs,
  PasskeyPublicDeps,
} from '@/core/signingEngine/session/passkey/public';
import { createBrowserRecoveryPublicDeps } from '../assembly/createBrowserRecoveryPublicDeps';
import { createBrowserStepUpRuntime } from '../assembly/createBrowserStepUpRuntime';
import { createBrowserWarmSessionPublicDeps } from '../assembly/createBrowserWarmSessionPublicDeps';
import {
  createBrowserSigningSurfaceEnginePorts,
  type BrowserSigningSurfaceEnginePorts,
} from '../assembly/browserSigningSurfaceAssembly';
import type { BrowserSigningSurfaceConstructorDeps } from '../assembly/browserSigningSurfacePorts';
import {
  finalizeWalletRegistrationEcdsaClientBootstrap,
  prepareEmailOtpWalletRegistrationEcdsaClientBootstrap,
  preparePasskeyWalletRegistrationEcdsaClientBootstrap,
  storeWalletRegistrationEcdsaClientSigningMaterial,
} from '@/core/signingEngine/flows/registration/services/ecdsaRegistrationBootstrap';
import {
  finalizeWalletRegistrationEcdsaSessions as finalizeWalletRegistrationEcdsaSessionsOperation,
  type FinalizeWalletRegistrationEcdsaSessionsDeps,
} from '@/core/signingEngine/flows/registration/services/ecdsaRegistrationSessions';
import { commitEvmFamilyThresholdEcdsaSessions } from '@/core/signingEngine/session/emailOtp/ecdsaBootstrapCommit';
import type {
  WorkerResourceWarmupAccountContext,
  WorkerResourceWarmupDiagnostics,
} from '@/core/signingEngine/assembly/warmup';
import {
  restoreThresholdEd25519WorkerMaterialFromCredential,
} from '../operations/session/thresholdWarmSessionBootstrap';

type RuntimePortsRef = {
  current: RuntimePorts | null;
};

async function loadEcdsaRoleLocalReadyRecordFromRuntimePorts(
  runtimePortsRef: RuntimePortsRef,
  input: Parameters<DurableRecordStore['loadEcdsaRoleLocalReadyRecord']>[0],
): ReturnType<DurableRecordStore['loadEcdsaRoleLocalReadyRecord']> {
  if (!runtimePortsRef.current) {
    return {
      ok: false,
      code: 'unavailable',
      message: 'Signing runtime storage is not initialized',
    };
  }
  return await runtimePortsRef.current.storage.loadEcdsaRoleLocalReadyRecord(input);
}

/**
 * BrowserSigningSurface owns browser signing assembly state and exposes the SeamsWeb signing surface.
 */
export class BrowserSigningSurface {
  // Kept as fields for low-level tests that intentionally access internals.
  private readonly touchConfirm: UiConfirmRuntimeBridgePort;
  private readonly signerWorkerManager: SignerWorkerManager;
  private readonly touchIdPrompt: TouchIdPrompt;
  private readonly userPreferencesManager: UserPreferencesManager;
  private readonly nearClient: NearClient;
  private readonly nonceCoordinator: NonceCoordinator;
  private workerBaseOrigin: string = '';
  private theme: ThemeName = 'dark';
  private readonly thresholdEcdsaBootstrapQueueByWallet: Map<string, Promise<void>> = new Map();
  private readonly thresholdEcdsaCommitQueueByKey: ThresholdEcdsaCommitQueueByKey = new Map();
  private readonly thresholdEd25519CommitQueueByKey: ThresholdEd25519CommitQueueByKey = new Map();
  private readonly emailOtpSessions: EmailOtpWalletSessionCoordinator;
  private readonly thresholdEcdsaSessionByLane: Map<string, ThresholdEcdsaSessionRecord>;
  private readonly thresholdEcdsaExportArtifactByLane: Map<
    string,
    ThresholdEcdsaCanonicalExportArtifact
  >;
  private readonly warmSigning: WarmSigningPorts;
  private readonly passkeyPublicDeps: PasskeyPublicDeps;
  private readonly warmCapabilitiesPublicDeps: WarmCapabilitiesPublicDeps;
  private readonly sessionPublicDeps: SessionPublicDeps;
  private readonly emailOtpPublicDeps: EmailOtpPublicDeps;
  private readonly recoveryPublicDeps: RecoveryPublicDeps;
  private readonly registrationPublicDeps: registrationPublic.RegistrationPublicDeps;
  private readonly thresholdEd25519PublicDeps: thresholdEd25519Public.ThresholdEd25519PublicDeps;
  private readonly sealedRefreshStartupParityPromise: Promise<void>;
  private sealedRefreshStartupParityError: Error | null = null;
  private readonly signingRuntime: SigningRuntime;
  private readonly runtimePorts: RuntimePorts;
  private readonly enginePorts: BrowserSigningSurfaceEnginePorts;
  private readonly ecdsaBootstrapStore: ThresholdEcdsaBootstrapStorePort;

  readonly seamsWebConfigs: SeamsConfigsReadonly;

  constructor(
    seamsWebConfigs: SeamsConfigsReadonly,
    nearClient: NearClient,
    deps: BrowserSigningSurfaceConstructorDeps,
  ) {
    this.seamsWebConfigs = seamsWebConfigs;
    this.nearClient = nearClient;
    this.ecdsaBootstrapStore =
      deps.signingEngineStores.walletProfileAndSignerRecords.ecdsaBootstrapStore;
    this.sealedRefreshStartupParityPromise = verifySealedRefreshStartupParity({
      configs: this.seamsWebConfigs,
    }).catch((error: unknown) => {
      this.sealedRefreshStartupParityError =
        error instanceof Error
          ? error
          : new Error(String(error || 'sealed refresh parity check failed'));
    });
    const runtimePortsForUiConfirm: RuntimePortsRef = { current: null };
    const loadEcdsaRoleLocalReadyRecord: DurableRecordStore['loadEcdsaRoleLocalReadyRecord'] =
      loadEcdsaRoleLocalReadyRecordFromRuntimePorts.bind(null, runtimePortsForUiConfirm);

    const assembly = createManagerAssembly({
      stores: deps.managerStores,
      seamsWebConfigs: this.seamsWebConfigs,
      nearClient: this.nearClient,
      loadEcdsaRoleLocalReadyRecord,
      getTheme: () => this.theme,
      getAppearanceTokens: () => this.seamsWebConfigs.ui.appearance?.tokens,
    });

    this.touchIdPrompt = assembly.touchIdPrompt;
    this.userPreferencesManager = assembly.userPreferencesManager;
    this.nonceCoordinator = assembly.nonceCoordinator;
    this.signerWorkerManager = assembly.signerWorkerManager;
    const signingRuntime = deps.createRuntime({
      config: this.seamsWebConfigs,
      workerCtx: this.signerWorkerManager.getContext(),
      accountLifecycle: {
        accountStore: deps.signingEngineStores.walletProfileAndSignerRecords.accountStore,
        userPreferencesManager: this.userPreferencesManager,
        nonceCoordinator: this.nonceCoordinator,
      },
      ecdsaBootstrapStore: this.ecdsaBootstrapStore,
      getWarmSessionMaterialWriter: () => this.touchConfirm,
      getNearSigningDeps: () => this.enginePorts.nearSigningDeps,
      getEvmFamilySigningDeps: () => this.enginePorts.tempoSigningDeps,
    });
    this.signingRuntime = signingRuntime;
    runtimePortsForUiConfirm.current = signingRuntime.runtimePorts;
    const ecdsaRoleLocalReadyRecordStore = signingRuntime.state.ecdsaSessions;
    this.runtimePorts = signingRuntime.runtimePorts;
    this.thresholdEcdsaSessionByLane = signingRuntime.state.ecdsaSessions.recordsByLane;
    this.thresholdEcdsaExportArtifactByLane =
      signingRuntime.state.ecdsaSessions.exportArtifactsByLane;
    const stepUpRuntime = createBrowserStepUpRuntime({
      seamsWebConfigs: this.seamsWebConfigs,
      touchIdPrompt: this.touchIdPrompt,
      signerWorkerManager: this.signerWorkerManager,
      stores: deps.signingEngineStores,
      runtimePorts: this.runtimePorts,
      sealedSigningSessionStore: deps.sealedSigningSessionStore,
      baseTouchConfirm: assembly.touchConfirm,
      getEnginePorts: () => this.enginePorts,
      thresholdEcdsaBootstrapQueueByWallet: this.thresholdEcdsaBootstrapQueueByWallet,
      getWarmSigning: () => this.warmSigning,
      ensureSealedRefreshStartupParity: () => this.ensureSealedRefreshStartupParity(),
    });
    this.emailOtpSessions = stepUpRuntime.emailOtpSessions;
    this.touchConfirm = stepUpRuntime.touchConfirm;
    this.warmSigning = createWarmSigningPorts({
      touchConfirm: this.touchConfirm,
      getEmailOtpWarmSessionStatus: (sessionId) =>
        this.emailOtpSessions.readWarmSessionStatusOnly(sessionId),
      signingSessionSeal: this.seamsWebConfigs.signing.sessionSeal,
      ecdsaRoleLocalReadyRecords: ecdsaRoleLocalReadyRecordStore,
    });
    this.sessionPublicDeps = createSessionPublicDeps({
      seamsWebConfigs: this.seamsWebConfigs,
      touchConfirm: this.touchConfirm,
      emailOtpSessions: this.emailOtpSessions,
      warmSigning: this.warmSigning,
    });
    this.emailOtpPublicDeps = {
      ecdsaSessions: this.warmSigning.ecdsaSessions,
      relayerUrl: this.seamsWebConfigs.network.relayer?.url || '',
      shamirPrimeB64u: this.seamsWebConfigs.signing.sessionSeal?.shamirPrimeB64u || '',
      getSignerWorkerContext: () =>
        this.enginePorts.walletSessionActivationDeps.getSignerWorkerContext(),
      emailOtpSessions: this.emailOtpSessions,
    };
    this.recoveryPublicDeps = createBrowserRecoveryPublicDeps({
      seamsWebConfigs: this.seamsWebConfigs,
      runtimePorts: this.runtimePorts,
      touchIdPrompt: this.touchIdPrompt,
      signerWorkerManager: this.signerWorkerManager,
      credentialStore: deps.signingEngineStores.recoveryAndDeviceLinking.credentialStore,
      keyMaterialStore: deps.signingEngineStores.recoveryAndDeviceLinking.keyMaterialStore,
      warmSigning: this.warmSigning,
      touchConfirm: this.touchConfirm,
      emailOtpSessions: this.emailOtpSessions,
      thresholdEcdsaBootstrapQueueByWallet: this.thresholdEcdsaBootstrapQueueByWallet,
      getWalletSessionActivationDeps: () => this.enginePorts.walletSessionActivationDeps,
      getTheme: () => this.theme,
    });

    this.enginePorts = createBrowserSigningSurfaceEnginePorts({
      runtimePorts: this.runtimePorts,
      stores: deps.signingEngineStores,
      seamsWebConfigs: this.seamsWebConfigs,
      nearClient: this.nearClient,
      touchIdPrompt: this.touchIdPrompt,
      userPreferencesManager: this.userPreferencesManager,
      nonceCoordinator: this.nonceCoordinator,
      touchConfirm: this.touchConfirm,
      signerWorkerManager: this.signerWorkerManager,
      emailOtpSessions: this.emailOtpSessions,
      warmSigning: this.warmSigning,
      ecdsaBootstrapStore: this.ecdsaBootstrapStore,
      thresholdEcdsaBootstrapQueueByWallet: this.thresholdEcdsaBootstrapQueueByWallet,
      thresholdEcdsaCommitQueueByKey: this.thresholdEcdsaCommitQueueByKey,
      thresholdEd25519CommitQueueByKey: this.thresholdEd25519CommitQueueByKey,
      getWorkerBaseOrigin: () => this.workerBaseOrigin,
      shouldPrewarmWorkers: deps.shouldPrewarmWorkers,
      getTheme: () => this.theme,
      ensureSealedRefreshStartupParity: () => this.ensureSealedRefreshStartupParity(),
      restorePasskeyEd25519SigningMaterial:
        this.restorePasskeyEd25519SigningMaterialForReconnect.bind(this),
      getEnginePorts: () => this.enginePorts,
      getRegistrationPublicDeps: () => this.registrationPublicDeps,
    });
    const warmSessionPublicDeps = createBrowserWarmSessionPublicDeps({
      seamsWebConfigs: this.seamsWebConfigs,
      stores: deps.signingEngineStores,
      touchIdPrompt: this.touchIdPrompt,
      touchConfirm: this.touchConfirm,
      warmSigning: this.warmSigning,
      runtimePorts: this.runtimePorts,
      thresholdEcdsaBootstrapQueueByWallet: this.thresholdEcdsaBootstrapQueueByWallet,
      ensureSealedRefreshStartupParity: () => this.ensureSealedRefreshStartupParity(),
      enginePorts: this.enginePorts,
    });
    this.passkeyPublicDeps = warmSessionPublicDeps.passkeyPublicDeps;
    this.warmCapabilitiesPublicDeps = warmSessionPublicDeps.warmCapabilitiesPublicDeps;
    this.registrationPublicDeps = {
      accountLifecycle: this.enginePorts.registrationAccountLifecycleDeps,
      session: this.enginePorts.registrationSessionDeps,
    };
    this.thresholdEd25519PublicDeps = this.enginePorts.thresholdEd25519LifecycleDeps;

    deps.initializeRuntime({
      config: this.seamsWebConfigs,
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

  async discoverPersistedSessionsForWallet(
    args: DiscoverPersistedSessionsForWalletInput,
  ): Promise<DiscoverPersistedSessionsForWalletResult> {
    return await sessionPublic.discoverPersistedSessionsForWallet(this.sessionPublicDeps, args);
  }

  async readPersistedAvailableSigningLanes(
    args: Omit<ReadAvailableSigningLanesInput, 'ecdsaChainTargets'>,
  ): Promise<AvailableSigningLanes> {
    return await sessionPublic.readPersistedAvailableSigningLanes(this.sessionPublicDeps, args);
  }

  async warmCriticalResources(
    accountContext?: WorkerResourceWarmupAccountContext,
  ): Promise<WorkerResourceWarmupDiagnostics> {
    try {
      await this.ensureSealedRefreshStartupParity();
    } catch (error: unknown) {
      if (!isRetryableSealedRefreshCapabilityFetchError(error)) throw error;
      console.warn(
        '[BrowserSigningSurface] warmCriticalResources skipped retryable sealed-refresh capability fetch failure',
        error instanceof Error ? error.message : String(error || 'unknown error'),
      );
    }
    return await this.enginePorts.getManagerConveniencePorts().warmCriticalResources(accountContext);
  }

  getRpId(): string {
    return this.touchIdPrompt.getRpId();
  }

  getSignerWorkerContext(): WorkerOperationContext {
    return this.enginePorts.walletSessionActivationDeps.getSignerWorkerContext();
  }

  getNonceCoordinator(): NonceCoordinator {
    return this.nonceCoordinator;
  }

  setTheme(next: ThemeName): void {
    if (next !== 'light' && next !== 'dark') return;
    this.theme = next;
  }

  getUserPreferences(): UserPreferencesManager {
    return this.userPreferencesManager;
  }

  async signNear<TRequest extends NearSignIntentRequest>(
    request: TRequest,
  ): Promise<NearSignIntentResult<TRequest>> {
    return await signNearOperation(this.enginePorts.nearSigningDeps, request);
  }

  async signEvmFamily(args: {
    walletSession: WalletSessionRef;
    request: TempoSigningRequest | EvmSigningRequest;
    chainTarget: ThresholdEcdsaChainTarget;
    confirmationConfigOverride?: Partial<ConfirmationConfig>;
    shouldAbort?: () => boolean;
    onEvent?: (event: SigningFlowEvent) => void;
  }): Promise<TempoSignedResult | EvmSignedResult> {
    return await signEvmFamilyOperation(this.enginePorts.tempoSigningDeps, args);
  }

  async reportTempoBroadcastAccepted(args: ReportTempoBroadcastAcceptedArgs): Promise<void> {
    await reportTempoBroadcastAcceptedOperation(this.enginePorts.tempoSigningDeps, args);
  }

  async reportTempoBroadcastRejected(args: ReportTempoBroadcastRejectedArgs): Promise<void> {
    await reportTempoBroadcastRejectedOperation(this.enginePorts.tempoSigningDeps, args);
  }

  async reportTempoFinalized(args: ReportTempoFinalizedArgs): Promise<void> {
    await reportTempoFinalizedOperation(this.enginePorts.tempoSigningDeps, args);
  }

  async reportTempoDroppedOrReplaced(args: ReportTempoDroppedOrReplacedArgs): Promise<void> {
    await reportTempoDroppedOrReplacedOperation(this.enginePorts.tempoSigningDeps, args);
  }

  async reconcileTempoNonceLane(args: ReconcileTempoNonceLaneArgs): Promise<TempoNonceLaneStatus> {
    return await reconcileTempoNonceLaneOperation(this.enginePorts.tempoSigningDeps, args);
  }

  storeUserData(
    userData: Parameters<typeof registrationPublic.storeUserData>[1],
  ): ReturnType<typeof registrationPublic.storeUserData> {
    return registrationPublic.storeUserData(this.registrationPublicDeps, userData);
  }

  getAllUsers(): ReturnType<typeof registrationPublic.getAllUsers> {
    return registrationPublic.getAllUsers(this.registrationPublicDeps);
  }

  getUserBySignerSlot(
    nearAccountId: Parameters<typeof registrationPublic.getUserBySignerSlot>[1],
    signerSlot: Parameters<typeof registrationPublic.getUserBySignerSlot>[2],
  ): ReturnType<typeof registrationPublic.getUserBySignerSlot> {
    return registrationPublic.getUserBySignerSlot(
      this.registrationPublicDeps,
      nearAccountId,
      signerSlot,
    );
  }

  getLastUser(): ReturnType<typeof registrationPublic.getLastUser> {
    return registrationPublic.getLastUser(this.registrationPublicDeps);
  }

  nearAuthenticatorsByAccount(
    nearAccountId: Parameters<typeof registrationPublic.nearAuthenticatorsByAccount>[1],
  ): ReturnType<typeof registrationPublic.nearAuthenticatorsByAccount> {
    return registrationPublic.nearAuthenticatorsByAccount(
      this.registrationPublicDeps,
      nearAccountId,
    );
  }

  updateLastLogin(
    walletId: Parameters<typeof registrationPublic.updateLastLogin>[1],
  ): ReturnType<typeof registrationPublic.updateLastLogin> {
    return registrationPublic.updateLastLogin(this.registrationPublicDeps, walletId);
  }

  setLastUser(
    walletId: Parameters<typeof registrationPublic.setLastUser>[1],
    signerSlot: Parameters<typeof registrationPublic.setLastUser>[2],
  ): ReturnType<typeof registrationPublic.setLastUser> {
    return registrationPublic.setLastUser(this.registrationPublicDeps, walletId, signerSlot);
  }

  activateAuthenticatedWalletState(
    args: Parameters<typeof registrationPublic.activateAuthenticatedWalletState>[1],
  ): ReturnType<typeof registrationPublic.activateAuthenticatedWalletState> {
    return registrationPublic.activateAuthenticatedWalletState(this.registrationPublicDeps, args);
  }

  storeAuthenticator(
    authenticatorData: Parameters<typeof registrationPublic.storeAuthenticator>[1],
  ): ReturnType<typeof registrationPublic.storeAuthenticator> {
    return registrationPublic.storeAuthenticator(this.registrationPublicDeps, authenticatorData);
  }

  rollbackUserRegistration(
    nearAccountId: Parameters<typeof registrationPublic.rollbackUserRegistration>[1],
  ): ReturnType<typeof registrationPublic.rollbackUserRegistration> {
    return registrationPublic.rollbackUserRegistration(this.registrationPublicDeps, nearAccountId);
  }

  hasPasskeyCredential(
    nearAccountId: Parameters<typeof registrationPublic.hasPasskeyCredential>[1],
  ): ReturnType<typeof registrationPublic.hasPasskeyCredential> {
    return registrationPublic.hasPasskeyCredential(this.registrationPublicDeps, nearAccountId);
  }

  storeWalletEd25519RegistrationData(
    input: Parameters<typeof registrationPublic.storeWalletEd25519RegistrationData>[1],
  ): ReturnType<typeof registrationPublic.storeWalletEd25519RegistrationData> {
    return registrationPublic.storeWalletEd25519RegistrationData(
      this.registrationPublicDeps,
      input,
    );
  }

  storeWalletEmailOtpEd25519RegistrationData(
    input: Parameters<typeof registrationPublic.storeWalletEmailOtpEd25519RegistrationData>[1],
  ): ReturnType<typeof registrationPublic.storeWalletEmailOtpEd25519RegistrationData> {
    return registrationPublic.storeWalletEmailOtpEd25519RegistrationData(
      this.registrationPublicDeps,
      input,
    );
  }

  finalizeWalletEd25519SignerRegistration(
    input: Parameters<typeof registrationPublic.finalizeWalletEd25519SignerRegistration>[1],
  ): ReturnType<typeof registrationPublic.finalizeWalletEd25519SignerRegistration> {
    return registrationPublic.finalizeWalletEd25519SignerRegistration(
      this.registrationPublicDeps,
      input,
    );
  }

  preparePasskeyEcdsaBootstrap(
    input: Parameters<typeof preparePasskeyWalletRegistrationEcdsaClientBootstrap>[1],
  ): ReturnType<typeof preparePasskeyWalletRegistrationEcdsaClientBootstrap> {
    return preparePasskeyWalletRegistrationEcdsaClientBootstrap(
      { signerCrypto: this.runtimePorts.signerCrypto },
      input,
    );
  }

  prepareEmailOtpEcdsaBootstrap(
    input: Parameters<typeof prepareEmailOtpWalletRegistrationEcdsaClientBootstrap>[1],
  ): ReturnType<typeof prepareEmailOtpWalletRegistrationEcdsaClientBootstrap> {
    return prepareEmailOtpWalletRegistrationEcdsaClientBootstrap(
      { emailOtpWorker: this.signerWorkerManager.getContext() },
      input,
    );
  }

  finalizeWalletRegistrationEcdsaSessions(
    input: Parameters<typeof finalizeWalletRegistrationEcdsaSessionsOperation>[1],
  ): ReturnType<typeof finalizeWalletRegistrationEcdsaSessionsOperation> {
    return finalizeWalletRegistrationEcdsaSessionsOperation(
      {
        registrationBootstrap: {
          finalizeClientBootstrap: (bootstrapInput) =>
            finalizeWalletRegistrationEcdsaClientBootstrap(
              { signerCrypto: this.runtimePorts.signerCrypto },
              bootstrapInput,
            ),
          storeClientSigningMaterial: (storeInput) =>
            storeWalletRegistrationEcdsaClientSigningMaterial(
              { signerCrypto: this.runtimePorts.signerCrypto },
              storeInput,
            ),
        },
        bootstrapStore: this.ecdsaBootstrapStore,
        sessionStore: this.warmSigning.ecdsaSessions,
        persistEcdsaRoleLocalReadyRecord:
          this.runtimePorts.storage.persistEcdsaRoleLocalReadyRecord,
        warmSessions: {
          hydrateSigningSession: (hydrateInput) =>
            warmCapabilitiesPublic.hydrateSigningSession(
              this.warmCapabilitiesPublicDeps,
              hydrateInput,
            ),
        },
        commitEmailOtpEcdsaSession: this.commitEmailOtpRegistrationEcdsaSession.bind(this),
        signingSessionSeal: this.seamsWebConfigs.signing.sessionSeal,
      },
      input,
    );
  }

  private commitEmailOtpRegistrationEcdsaSession(
    input: Parameters<
      FinalizeWalletRegistrationEcdsaSessionsDeps['commitEmailOtpEcdsaSession']
    >[0],
  ): ReturnType<typeof commitEvmFamilyThresholdEcdsaSessions> {
    return commitEvmFamilyThresholdEcdsaSessions(
      {
        queueByWallet: this.thresholdEcdsaBootstrapQueueByWallet,
        bootstrapStore: this.ecdsaBootstrapStore,
        ecdsaSessions: this.warmSigning.ecdsaSessions,
        persistEcdsaRoleLocalReadyRecord:
          this.runtimePorts.storage.persistEcdsaRoleLocalReadyRecord,
        warmCapabilityReader: this.warmSigning.capabilityReader,
        ensureSealedRefreshStartupParityForThresholdEcdsaBootstrap:
          this.ensureEmailOtpRegistrationEcdsaSealedRefreshParity.bind(this),
      },
      input,
    );
  }

  private ensureEmailOtpRegistrationEcdsaSealedRefreshParity(
    parityArgs: ThresholdEcdsaBootstrapParityArgs,
  ): Promise<void> {
    return ensureSealedRefreshStartupParityForThresholdEcdsaBootstrap(
      () => this.ensureSealedRefreshStartupParity(),
      parityArgs,
    );
  }

  storeWalletEcdsaSignerRecords(
    input: Parameters<typeof registrationPublic.storeWalletEcdsaSignerRecords>[1],
  ): ReturnType<typeof registrationPublic.storeWalletEcdsaSignerRecords> {
    return registrationPublic.storeWalletEcdsaSignerRecords(this.registrationPublicDeps, input);
  }

  storeWalletEmailOtpEcdsaSignerRecords(
    input: Parameters<typeof registrationPublic.storeWalletEmailOtpEcdsaSignerRecords>[1],
  ): ReturnType<typeof registrationPublic.storeWalletEmailOtpEcdsaSignerRecords> {
    return registrationPublic.storeWalletEmailOtpEcdsaSignerRecords(
      this.registrationPublicDeps,
      input,
    );
  }

  finalizeWalletEcdsaRegistration(
    input: Parameters<typeof registrationPublic.finalizeWalletEcdsaRegistration>[1],
  ): ReturnType<typeof registrationPublic.finalizeWalletEcdsaRegistration> {
    return registrationPublic.finalizeWalletEcdsaRegistration(this.registrationPublicDeps, input);
  }

  storeWalletEmailOtpEcdsaRegistrationData(
    input: Parameters<typeof registrationPublic.storeWalletEmailOtpEcdsaRegistrationData>[1],
  ): ReturnType<typeof registrationPublic.storeWalletEmailOtpEcdsaRegistrationData> {
    return registrationPublic.storeWalletEmailOtpEcdsaRegistrationData(
      this.registrationPublicDeps,
      input,
    );
  }

  requestWorkerOperation = <
    K extends SignerWorkerKind,
    T extends SignerWorkerOperationType<K>,
  >(args: {
    kind: K;
    request: SignerWorkerOperationRequest<K, T>;
  }): Promise<SignerWorkerOperationResult<K, T>> =>
    this.signerWorkerManager.getContext().requestWorkerOperation(args);

  private async restorePasskeyEd25519SigningMaterialForReconnect(args: {
    nearAccountId: AccountId;
    credential: WebAuthnAuthenticationCredential;
    signerSlot: number;
    thresholdSessionId: string;
  }): Promise<void> {
    const result = await restoreThresholdEd25519WorkerMaterialFromCredential({
      context: {
        signingEngine: this,
      },
      credential: args.credential,
      nearAccountId: args.nearAccountId,
      signerSlot: args.signerSlot,
      thresholdSessionId: args.thresholdSessionId,
    });
    switch (result.kind) {
      case 'already_loaded':
      case 'restored':
        return;
      case 'material_pending':
        throw new Error(
          '[SigningEngine][near] passkey Ed25519 reconnect did not produce signable Router A/B state: missing_material_handle',
        );
      default: {
        const exhaustive: never = result;
        return exhaustive;
      }
    }
  }

  hydrateSigningSession(
    input: Parameters<typeof warmCapabilitiesPublic.hydrateSigningSession>[1],
  ): ReturnType<typeof warmCapabilitiesPublic.hydrateSigningSession> {
    return warmCapabilitiesPublic.hydrateSigningSession(this.warmCapabilitiesPublicDeps, input);
  }

  persistSigningSessionSealForThresholdSession(
    input: Parameters<UiConfirmRuntimeBridgePort['persistSigningSessionSealForThresholdSession']>[0],
  ): ReturnType<UiConfirmRuntimeBridgePort['persistSigningSessionSealForThresholdSession']> {
    return this.touchConfirm.persistSigningSessionSealForThresholdSession(input);
  }

  async putWarmSessionEd25519UnsealAuthorization(
    input: WarmSessionEd25519UnsealAuthorizationPutPayload,
  ): Promise<void> {
    const result = await this.touchConfirm.putWarmSessionEd25519UnsealAuthorization(input);
    if (!result.ok) {
      throw new Error(
        `Ed25519 warm-session unseal authorization install failed (${result.code}): ${result.message}`,
      );
    }
  }

  requestRegistrationCredentialConfirmation(params: {
    walletId: string;
    nearAccountId?: string;
    signerSlot: number;
    confirmerText?: { title?: string; body?: string };
    confirmationConfigOverride?: Partial<ConfirmationConfig>;
    challengeB64u?: string;
    walletIframeActivation?: RegistrationActivationProof;
  }): Promise<RegistrationCredentialConfirmationPayload> {
    return registrationPublic.requestRegistrationCredentialConfirmation(
      this.registrationPublicDeps,
      params,
    );
  }

  getAuthenticationCredentialsSerialized(args: {
    subjectId: string;
    challengeB64u: string;
    allowCredentials: WebAuthnAllowCredential[];
    includeSecondPrfOutput?: boolean;
  }): Promise<WebAuthnAuthenticationCredential> {
    return registrationPublic.getAuthenticationCredentialsSerialized(
      this.registrationPublicDeps,
      args,
    );
  }

  async exportKeypairWithUI(
    input: SigningEngineExportKeypairWithUIInput,
  ): Promise<{ accountId: string; exportedSchemes: Array<'ed25519' | 'secp256k1'> }> {
    return await recoveryPublic.exportKeypairWithUI(this.recoveryPublicDeps, input);
  }

  async resolveExactKeyExportLane(
    input: SigningEngineResolveExactKeyExportLaneInput,
  ): Promise<SigningEngineResolveExactKeyExportLaneResult> {
    return await recoveryPublic.resolveExactKeyExportLane(this.recoveryPublicDeps, input);
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
    return recoveryPublic.exportNearEd25519SeedArtifactWithUI(this.recoveryPublicDeps, args);
  }

  async exportThresholdEd25519SeedFromHssReport(args: {
    nearAccountId: AccountId;
    preparedSession: Parameters<
      typeof recoveryPublic.exportThresholdEd25519SeedFromHssReport
    >[1]['preparedSession'];
    finalizedReport: Parameters<
      typeof recoveryPublic.exportThresholdEd25519SeedFromHssReport
    >[1]['finalizedReport'];
    expectedPublicKey: string;
    options: {
      variant?: 'drawer' | 'modal';
      theme?: 'dark' | 'light';
      onEvent?: KeyExportEventCallback;
    };
  }): Promise<{ accountId: string; exportedSchemes: Array<'ed25519' | 'secp256k1'> }> {
    return await recoveryPublic.exportThresholdEd25519SeedFromHssReport(
      this.recoveryPublicDeps,
      args,
    );
  }

  async connectEd25519Session(
    args: ConnectEd25519SessionArgs,
  ): Promise<ProvisionWarmEd25519CapabilityResult> {
    return await passkeyPublic.connectEd25519Session(this.passkeyPublicDeps, args);
  }

  async bootstrapEcdsaSession(
    args: EcdsaBootstrapRequest,
  ): Promise<ThresholdEcdsaSessionBootstrapResult> {
    return await passkeyPublic.bootstrapEcdsaSession(this.passkeyPublicDeps, args);
  }

  async loginWithEmailOtpEcdsaCapabilityInternal(
    args: LoginWithEmailOtpEcdsaCapabilityInternalArgs,
  ): Promise<LoginWithEmailOtpEcdsaCapabilityInternalResult> {
    return await emailOtpPublic.loginWithEmailOtpEcdsaCapabilityInternal(
      this.emailOtpPublicDeps,
      args,
    );
  }

  async loginWithEmailOtpEd25519CapabilityInternal(
    args: LoginWithEmailOtpEd25519CapabilityInternalArgs,
  ): Promise<LoginWithEmailOtpEd25519CapabilityInternalResult> {
    return await emailOtpPublic.loginWithEmailOtpEd25519CapabilityInternal(
      this.emailOtpPublicDeps,
      args,
    );
  }

  async requestEmailOtpSigningSessionChallenge(args: {
    walletSession: WalletSessionRef;
    chainTarget: ThresholdEcdsaChainTarget;
  }): Promise<{ challengeId: string; emailHint?: string }> {
    return await emailOtpPublic.requestEmailOtpSigningSessionChallenge(
      this.emailOtpPublicDeps,
      args,
    );
  }

  async refreshEmailOtpSigningSession(args: {
    walletSession: WalletSessionRef;
    chainTarget: ThresholdEcdsaChainTarget;
    challengeId: string;
    otpCode: string;
    ttlMs?: number;
    remainingUses?: number;
  }): Promise<{
    recovery: EmailOtpBootstrapRecovery;
    bootstrap: ThresholdEcdsaSessionBootstrapResult;
    warmCapability: WarmSessionEcdsaCapabilityState;
  }> {
    return await emailOtpPublic.refreshEmailOtpSigningSession(this.emailOtpPublicDeps, args);
  }

  async resolveEmailOtpAppSessionJwt(args: {
    walletSession: WalletSessionRef;
    relayUrl: string;
  }): Promise<string> {
    return await this.emailOtpSessions.resolveAppSessionJwt(args);
  }

  async enrollEmailOtpInternal(args: {
    walletId: WalletId;
    otpCode: string;
    relayUrl?: string;
    challengeId?: string;
    shamirPrimeB64u?: string;
    appSessionJwt?: string;
    clientSecret32?: Uint8Array;
    otpChannel?: WalletEmailOtpChannel;
  }): Promise<Awaited<ReturnType<typeof emailOtpPublic.enrollEmailOtpInternal>>> {
    return await emailOtpPublic.enrollEmailOtpInternal(this.emailOtpPublicDeps, args);
  }

  async rotateEmailOtpRecoveryCodesInternal(args: {
    walletId: WalletId;
    relayUrl?: string;
    appSessionJwt?: string;
  }): Promise<Awaited<ReturnType<typeof emailOtpPublic.rotateEmailOtpRecoveryCodesInternal>>> {
    return await emailOtpPublic.rotateEmailOtpRecoveryCodesInternal(this.emailOtpPublicDeps, args);
  }

  async prepareEmailOtpRegistrationEnrollmentMaterialInternal(
    args: PrepareEmailOtpRegistrationEnrollmentMaterialInternalArgs,
  ): Promise<PrepareEmailOtpRegistrationEnrollmentMaterialInternalResult> {
    return await emailOtpPublic.prepareEmailOtpRegistrationEnrollmentMaterialInternal(
      this.emailOtpPublicDeps,
      args,
    );
  }

  async enrollAndLoginWithEmailOtpEcdsaCapabilityInternal(
    args: EnrollAndLoginWithEmailOtpEcdsaCapabilityInternalArgs,
  ): Promise<EnrollAndLoginWithEmailOtpEcdsaCapabilityInternalResult> {
    return await emailOtpPublic.enrollAndLoginWithEmailOtpEcdsaCapabilityInternal(
      this.emailOtpPublicDeps,
      args,
    );
  }

  listThresholdEcdsaSessionRecordsForWalletTarget(
    args: ListThresholdEcdsaSessionRecordsForWalletTargetInput,
  ): SessionPublicThresholdEcdsaSessionRecord[] {
    return sessionPublic.listThresholdEcdsaSessionRecordsForWalletTarget(
      this.sessionPublicDeps,
      args,
    );
  }

  clearAllThresholdEcdsaSessionRecords(): void {
    sessionPublic.clearAllThresholdEcdsaSessionRecords(this.sessionPublicDeps);
    clearAllRouterAbEd25519ClientPresigns();
  }

  getWarmThresholdEd25519SessionStatus(
    nearAccountId: AccountId | string,
  ): Promise<SigningSessionStatus | null> {
    return warmCapabilitiesPublic.getWarmThresholdEd25519SessionStatus(
      this.warmCapabilitiesPublicDeps,
      toAccountId(nearAccountId),
    );
  }

  getWarmThresholdEcdsaSessionStatus(
    walletId: WalletId,
    chainTarget: ThresholdEcdsaChainTarget,
    thresholdSessionId: string,
  ): Promise<WarmEcdsaSigningSessionStatus | null> {
    return warmCapabilitiesPublic.getWarmThresholdEcdsaSessionStatus(
      this.warmCapabilitiesPublicDeps,
      walletId,
      chainTarget,
      thresholdSessionId,
    );
  }

  listWarmThresholdEcdsaSessionStatuses(
    walletId: WalletId,
    chainTarget: ThresholdEcdsaChainTarget,
  ): Promise<WarmEcdsaSigningSessionStatus[]> {
    return warmCapabilitiesPublic.listWarmThresholdEcdsaSessionStatuses(
      this.warmCapabilitiesPublicDeps,
      walletId,
      chainTarget,
    );
  }

  async scheduleRouterAbEcdsaHssLoginPresignaturePrefill(args: {
    walletId: WalletId;
    chainTarget: ThresholdEcdsaChainTarget;
    thresholdEcdsaSessionRecord: ThresholdEcdsaSessionRecord;
    minRemainingUsesBeforePrefill?: number;
  }): Promise<RouterAbEcdsaHssLoginPresignaturePrefillResult> {
    return await warmCapabilitiesPublic.scheduleRouterAbEcdsaHssLoginPresignaturePrefill(
      this.warmCapabilitiesPublicDeps,
      args,
    );
  }

  async clearVolatileWarmSigningMaterial(walletId?: WalletId): Promise<void> {
    await warmCapabilitiesPublic.clearVolatileWarmSigningMaterial(
      this.warmCapabilitiesPublicDeps,
      walletId,
    );
  }

  clearThresholdEcdsaCommitQueue(): void {
    clearThresholdEcdsaCommitQueue(this.thresholdEcdsaCommitQueueByKey);
  }

  prepareThresholdEd25519HssClientCeremonyFromCredential(
    args: Parameters<
      typeof thresholdEd25519Public.prepareThresholdEd25519HssClientCeremonyFromCredential
    >[1],
  ): ReturnType<
    typeof thresholdEd25519Public.prepareThresholdEd25519HssClientCeremonyFromCredential
  > {
    return thresholdEd25519Public.prepareThresholdEd25519HssClientCeremonyFromCredential(
      this.thresholdEd25519PublicDeps,
      args,
    );
  }

  prepareThresholdEd25519HssClientCeremonyFromPrfFirst(
    args: Parameters<
      typeof thresholdEd25519Public.prepareThresholdEd25519HssClientCeremonyFromPrfFirst
    >[1],
  ): ReturnType<
    typeof thresholdEd25519Public.prepareThresholdEd25519HssClientCeremonyFromPrfFirst
  > {
    return thresholdEd25519Public.prepareThresholdEd25519HssClientCeremonyFromPrfFirst(
      this.thresholdEd25519PublicDeps,
      args,
    );
  }

  prepareThresholdEd25519HssClientRequest(
    args: Parameters<typeof thresholdEd25519Public.prepareThresholdEd25519HssClientRequest>[1],
  ): ReturnType<typeof thresholdEd25519Public.prepareThresholdEd25519HssClientRequest> {
    return thresholdEd25519Public.prepareThresholdEd25519HssClientRequest(
      this.thresholdEd25519PublicDeps,
      args,
    );
  }

  prepareThresholdEd25519PasskeyPrfWorkerMaterialSealAuthorization(
    args: Parameters<
      typeof thresholdEd25519Public.prepareThresholdEd25519PasskeyPrfWorkerMaterialSealAuthorization
    >[1],
  ): ReturnType<
    typeof thresholdEd25519Public.prepareThresholdEd25519PasskeyPrfWorkerMaterialSealAuthorization
  > {
    return thresholdEd25519Public.prepareThresholdEd25519PasskeyPrfWorkerMaterialSealAuthorization(
      this.thresholdEd25519PublicDeps,
      args,
    );
  }

  prepareThresholdEd25519RecoveryCodeWorkerMaterialSealAuthorization(
    args: Parameters<
      typeof thresholdEd25519Public.prepareThresholdEd25519RecoveryCodeWorkerMaterialSealAuthorization
    >[1],
  ): ReturnType<
    typeof thresholdEd25519Public.prepareThresholdEd25519RecoveryCodeWorkerMaterialSealAuthorization
  > {
    return thresholdEd25519Public.prepareThresholdEd25519RecoveryCodeWorkerMaterialSealAuthorization(
      this.thresholdEd25519PublicDeps,
      args,
    );
  }

  prepareThresholdEd25519HssClientOutputMaskHandle(
    args: Parameters<
      typeof thresholdEd25519Public.prepareThresholdEd25519HssClientOutputMaskHandle
    >[1],
  ): ReturnType<typeof thresholdEd25519Public.prepareThresholdEd25519HssClientOutputMaskHandle> {
    return thresholdEd25519Public.prepareThresholdEd25519HssClientOutputMaskHandle(
      this.thresholdEd25519PublicDeps,
      args,
    );
  }

  buildThresholdEd25519HssClientOwnedStagedEvaluatorArtifactFromMaskHandle(
    args: Parameters<
      typeof thresholdEd25519Public.buildThresholdEd25519HssClientOwnedStagedEvaluatorArtifactFromMaskHandle
    >[1],
  ): ReturnType<
    typeof thresholdEd25519Public.buildThresholdEd25519HssClientOwnedStagedEvaluatorArtifactFromMaskHandle
  > {
    return thresholdEd25519Public.buildThresholdEd25519HssClientOwnedStagedEvaluatorArtifactFromMaskHandle(
      this.thresholdEd25519PublicDeps,
      args,
    );
  }

  runThresholdEd25519HssCeremonyWithSession(
    args: Parameters<typeof thresholdEd25519Public.runThresholdEd25519HssCeremonyWithSession>[1],
  ): ReturnType<typeof thresholdEd25519Public.runThresholdEd25519HssCeremonyWithSession> {
    return thresholdEd25519Public.runThresholdEd25519HssCeremonyWithSession(
      this.thresholdEd25519PublicDeps,
      args,
    );
  }

  runThresholdEd25519HssCeremonyWithMaterialHandle(
    args: Parameters<
      typeof thresholdEd25519Public.runThresholdEd25519HssCeremonyWithMaterialHandle
    >[1],
  ): ReturnType<typeof thresholdEd25519Public.runThresholdEd25519HssCeremonyWithMaterialHandle> {
    return thresholdEd25519Public.runThresholdEd25519HssCeremonyWithMaterialHandle(
      this.thresholdEd25519PublicDeps,
      args,
    );
  }
}
