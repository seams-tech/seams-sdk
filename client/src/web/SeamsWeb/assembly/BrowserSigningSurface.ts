import type { PlatformRuntime } from '@/core/platform';
import type { NearClient } from '@/core/rpcClients/near/NearClient';
import type { NonceCoordinator } from '@/core/signingEngine/nonce/NonceCoordinator';
import { toAccountId, type AccountId } from '@/core/types/accountIds';
import type { SigningFlowEvent } from '@/core/types/sdkSentEvents';
import type {
  EmailOtpAuthPolicy,
  SigningSessionStatus,
  SeamsConfigsReadonly,
  ThemeName,
} from '@/core/types/seams';
import type { WebAuthnAuthenticationCredential } from '@/core/types';
import {
  type WalletEmailOtpChannel,
  type WalletEmailOtpLoginOperation,
} from '@shared/utils/emailOtpDomain';
import { type AppOrThresholdSessionAuth } from '@shared/utils/sessionTokens';
import type { UserPreferencesManager } from '@/core/signingEngine/session/userPreferences';
import type { ThresholdEcdsaCanonicalExportArtifact } from '@/core/signingEngine/interfaces/signing';
import type { ThresholdEcdsaSessionBootstrapResult } from '@/core/signingEngine/threshold/ecdsa/activation';
import type { SignerWorkerManager } from '@/core/signingEngine/workerManager/SignerWorkerManager';
import type { SigningRuntime } from '@/core/runtime/types';
import type { EmailOtpWorkerProgressEvent } from '@/core/signingEngine/workerManager/workerTypes';
import type { UiConfirmRuntimeBridgePort } from '@/core/signingEngine/uiConfirm/types';
import type { CreateBrowserSigningRuntimeArgs } from './createBrowserSigningRuntime';
import { readTrustedWalletSigningBudgetStatus as readTrustedWalletSigningBudgetStatusOperation } from '@/core/signingEngine/session/budget/budgetStatusReader';
import type { TouchIdPrompt } from '@/core/signingEngine/stepUpConfirmation/passkeyPrompt/touchIdPrompt';
import type { WebAuthnAllowCredential } from '@/core/signingEngine/webauthnAuth/credentials/collectAuthenticationCredentialForChallengeB64u';
import type { EvmSigningRequest } from '@/core/signingEngine/chains/evm/types';
import type { EvmSignedResult } from '@/core/signingEngine/chains/evm/evmAdapter';
import type { TempoSigningRequest } from '@/core/signingEngine/chains/tempo/types';
import type { TempoSignedResult } from '@/core/signingEngine/chains/tempo/tempoAdapter';
import type { EcdsaBootstrapRequest } from '@/core/signingEngine/session/passkey/ecdsaBootstrap';
import * as thresholdEd25519Public from '@/core/signingEngine/threshold/ed25519/public';
import {
  persistThresholdEcdsaBootstrapForWalletTarget as persistThresholdEcdsaBootstrapForWalletTargetOperation,
} from '@/core/signingEngine/session/warmCapabilities/ecdsaBootstrapPersistence';
import {
  clearThresholdEcdsaSessionRecordForWalletTarget as clearThresholdEcdsaSessionRecordForWalletTargetOperation,
  getThresholdEcdsaSessionRecordByKey as getThresholdEcdsaSessionRecordByIdentityOperation,
  getThresholdEcdsaSessionRecordForWalletTarget as getThresholdEcdsaSessionRecordForWalletTargetOperation,
  listThresholdEcdsaKeyRefsForWalletTarget as listThresholdEcdsaKeyRefsForWalletTargetOperation,
  listThresholdEcdsaSessionRecordsForWalletTarget as listThresholdEcdsaSessionRecordsForWalletTargetOperation,
  markThresholdEd25519EmailOtpSessionConsumedForAccount as markThresholdEd25519EmailOtpSessionConsumedForAccountOperation,
  consumeSingleUseEmailOtpEcdsaLane as consumeSingleUseEmailOtpEcdsaLaneOperation,
  upsertThresholdEcdsaSessionFromBootstrap as upsertThresholdEcdsaSessionFromBootstrapOperation,
  type ThresholdEd25519SessionRecord,
  type ThresholdEcdsaSessionRecord,
} from '@/core/signingEngine/session/persistence/records';
import type {
  ThresholdEcdsaSessionStoreSource,
} from '@/core/signingEngine/session/identity/laneIdentity';
import {
  configuredThresholdEcdsaChainTargets,
  thresholdEcdsaChainTargetKey,
  toWalletId,
  type ThresholdEcdsaChainTarget,
  type WalletId,
  type WalletSessionRef,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { type ThresholdEcdsaLoginPrefillResult } from '@/core/signingEngine/session/warmCapabilities/ecdsaLoginPrefill';
import {
  signNear as signNearOperation,
  type NearSignIntentRequest,
  type NearSignIntentResult,
  type SignTransactionsWithActionsInput,
} from '@/core/signingEngine/flows/signNear/signNear';
import {
  reconcileTempoNonceLane as reconcileTempoNonceLaneOperation,
  reportTempoBroadcastAccepted as reportTempoBroadcastAcceptedOperation,
  reportTempoBroadcastRejected as reportTempoBroadcastRejectedOperation,
  reportTempoDroppedOrReplaced as reportTempoDroppedOrReplacedOperation,
  reportTempoFinalized as reportTempoFinalizedOperation,
  signTempo as signTempoOperation,
  type ReconcileTempoNonceLaneArgs,
  type ReportTempoBroadcastAcceptedArgs,
  type ReportTempoBroadcastRejectedArgs,
  type ReportTempoDroppedOrReplacedArgs,
  type ReportTempoFinalizedArgs,
  type TempoNonceLaneStatus,
} from '@/core/signingEngine/flows/signEvmFamily/signEvmFamily';
import type { EvmFamilySigningTarget } from '@/core/signingEngine/flows/signEvmFamily/types';
import {
  clearThresholdEcdsaCommitQueue,
  withThresholdEcdsaCommitQueue,
  type ThresholdEcdsaCommitQueueByKey,
} from '@/core/signingEngine/threshold/ecdsa/commitQueue';
import {
  clearThresholdEd25519CommitQueue,
  withThresholdEd25519CommitQueue,
  type ThresholdEd25519CommitQueueByKey,
} from '@/core/signingEngine/threshold/ed25519/commitQueue';
import { clearAllThresholdEd25519ClientPresigns } from '@/core/signingEngine/threshold/ed25519/presignPool';
import * as recoveryPublic from '@/core/signingEngine/flows/recovery/public';
import type {
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
  type LoginWithEmailOtpEcdsaCapabilityInternalArgs,
  type LoginWithEmailOtpEcdsaCapabilityInternalResult,
  type PrepareEmailOtpRegistrationEnrollmentMaterialInternalArgs,
  type PrepareEmailOtpRegistrationEnrollmentMaterialInternalResult,
} from '@/core/signingEngine/flows/signEvmFamily/emailOtpPublic';
import * as emailOtpPublic from '@/core/signingEngine/flows/signEvmFamily/emailOtpPublic';
import { createManagerAssembly, type ManagerAssemblyStores } from '@/core/signingEngine/assembly/createManagers';
import { verifySealedRefreshStartupParity } from '@/core/rpcClients/relayer/sealedRefreshCapabilities';
import type { EmailOtpSealedSessionStorePorts } from '@/core/signingEngine/session/emailOtp/EmailOtpThresholdSessionCoordinator';
import type { WarmSessionEcdsaCapabilityState } from '@/core/signingEngine/session/warmCapabilities/types';
import type {
  ProvisionWarmEd25519CapabilityResult,
  WarmEcdsaSigningSessionStatus,
} from '@/core/signingEngine/session/warmCapabilities/types';
import { createSigningEnginePorts } from '@/core/signingEngine/assembly/createPorts';
import type { SigningEngineStorePorts } from '@/core/signingEngine/assembly/ports/shared';
import { provisionThresholdEd25519Session as provisionThresholdEd25519SessionOperation } from '@/core/signingEngine/session/passkey/ed25519SessionProvision';
import { provisionThresholdEcdsaSession as provisionThresholdEcdsaSessionOperation } from '@/core/signingEngine/session/passkey/ecdsaSessionProvision';
import type { EmailOtpThresholdSessionCoordinator } from '@/core/signingEngine/session/emailOtp/EmailOtpThresholdSessionCoordinator';
import type { EmailOtpBootstrapRecovery } from '@/core/signingEngine/stepUpConfirmation/otpPrompt/bootstrapRecovery';
import type {
  RestorePersistedSessionsForWalletInput,
  RestorePersistedSessionsForWalletResult,
  ReadAvailableSigningLanesInput,
  AvailableSigningLanes,
  SessionPublicDeps,
  ThresholdEcdsaSessionRecord as SessionPublicThresholdEcdsaSessionRecord,
  ListThresholdEcdsaSessionRecordsForWalletTargetInput,
} from '@/core/signingEngine/session/public';
import * as sessionPublic from '@/core/signingEngine/session/public';
import { readPersistedAvailableSigningLanesForSigning as readPersistedAvailableSigningLanesForSigningOperation } from '@/core/signingEngine/session/availability/persistedAvailableSigningLanes';
import {
  createWarmSigningPorts,
  type WarmSigningPorts,
} from '@/core/signingEngine/assembly/ports/warmSigning';
import { createSessionPublicDeps } from '@/core/signingEngine/assembly/ports/session';
import * as warmCapabilitiesPublic from '@/core/signingEngine/session/warmCapabilities/public';
import type { WarmCapabilitiesPublicDeps } from '@/core/signingEngine/session/warmCapabilities/public';
import * as passkeyPublic from '@/core/signingEngine/session/passkey/public';
import type { ConnectEd25519SessionArgs, PasskeyPublicDeps } from '@/core/signingEngine/session/passkey/public';
import { createBrowserEmailOtpPublicDeps } from './createBrowserEmailOtpPublicDeps';
import { createBrowserRegistrationPublicDeps } from './createBrowserRegistrationPublicDeps';
import { createBrowserRecoveryPublicDeps } from './createBrowserRecoveryPublicDeps';
import { createBrowserStepUpRuntime } from './createBrowserStepUpRuntime';
import { createBrowserWarmSessionPublicDeps } from './createBrowserWarmSessionPublicDeps';

type InitializeSigningRuntimePort = (args: {
  config: SeamsConfigsReadonly;
  userPreferencesManager: Pick<UserPreferencesManager, 'initFromIndexedDB'>;
  getWorkerBaseOrigin: () => string;
  setWorkerBaseOrigin: (origin: string) => void;
}) => void;

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
  private readonly emailOtpSessions: EmailOtpThresholdSessionCoordinator;
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
  readonly signingRuntime: SigningRuntime;
  private readonly platformRuntime: PlatformRuntime;
  private readonly enginePorts: ReturnType<typeof createSigningEnginePorts>;

  readonly seamsWebConfigs: SeamsConfigsReadonly;

  constructor(
    seamsWebConfigs: SeamsConfigsReadonly,
    nearClient: NearClient,
    deps: {
      managerStores: ManagerAssemblyStores;
      signingEngineStores: SigningEngineStorePorts;
      sealedSigningSessionStore: EmailOtpSealedSessionStorePorts;
      createRuntime: (args: CreateBrowserSigningRuntimeArgs) => SigningRuntime;
      initializeRuntime: InitializeSigningRuntimePort;
      shouldPrewarmWorkers: (workerBaseOrigin: string) => boolean;
    },
  ) {
    this.seamsWebConfigs = seamsWebConfigs;
    this.nearClient = nearClient;
    this.sealedRefreshStartupParityPromise = verifySealedRefreshStartupParity({
      configs: this.seamsWebConfigs,
    }).catch((error: unknown) => {
      this.sealedRefreshStartupParityError =
        error instanceof Error
          ? error
          : new Error(String(error || 'sealed refresh parity check failed'));
    });

    const assembly = createManagerAssembly({
      stores: deps.managerStores,
      seamsWebConfigs: this.seamsWebConfigs,
      nearClient: this.nearClient,
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
      nearKeyOps: {
        signTransactionWithKeyPair: (args) =>
          this.signerWorkerManager.nearKeyOps.signTransactionWithKeyPair(args),
        generateEphemeralNearKeypair: () =>
          this.signerWorkerManager.nearKeyOps.generateEphemeralNearKeypair(),
      },
      accountLifecycle: {
        accountStore: deps.signingEngineStores.walletProfileAndSignerRecords.accountStore,
        userPreferencesManager: this.userPreferencesManager,
        nonceCoordinator: this.nonceCoordinator,
        extractCosePublicKey: (attestationObjectBase64url: string) =>
          this.signerWorkerManager.nearKeyOps.extractCosePublicKey(attestationObjectBase64url),
      },
      ecdsaBootstrapStore:
        deps.signingEngineStores.walletProfileAndSignerRecords.ecdsaBootstrapStore,
      getWarmSessionMaterialWriter: () => this.touchConfirm,
      getNearSigningDeps: () => this.enginePorts.nearSigningDeps,
      getEvmFamilySigningDeps: () => this.enginePorts.tempoSigningDeps,
    });
    this.signingRuntime = signingRuntime;
    const ecdsaRoleLocalReadyRecordStore = signingRuntime.state.ecdsaSessions;
    this.platformRuntime = signingRuntime.platformRuntime;
    this.thresholdEcdsaSessionByLane = signingRuntime.state.ecdsaSessions.recordsByLane;
    this.thresholdEcdsaExportArtifactByLane =
      signingRuntime.state.ecdsaSessions.exportArtifactsByLane;
    const stepUpRuntime = createBrowserStepUpRuntime({
      seamsWebConfigs: this.seamsWebConfigs,
      touchIdPrompt: this.touchIdPrompt,
      signerWorkerManager: this.signerWorkerManager,
      stores: deps.signingEngineStores,
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
    this.emailOtpPublicDeps = createBrowserEmailOtpPublicDeps({
      seamsWebConfigs: this.seamsWebConfigs,
      warmSigning: this.warmSigning,
      getSignerWorkerContext: () =>
        this.enginePorts.thresholdSessionActivationDeps.getSignerWorkerContext(),
      emailOtpSessions: this.emailOtpSessions,
    });
    this.recoveryPublicDeps = createBrowserRecoveryPublicDeps({
      seamsWebConfigs: this.seamsWebConfigs,
      touchIdPrompt: this.touchIdPrompt,
      signerWorkerManager: this.signerWorkerManager,
      keyMaterialStore: deps.signingEngineStores.recoveryAndDeviceLinking.keyMaterialStore,
      warmSigning: this.warmSigning,
      touchConfirm: this.touchConfirm,
      emailOtpSessions: this.emailOtpSessions,
      getTheme: () => this.theme,
    });

    this.enginePorts = createSigningEnginePorts({
      platformRuntime: this.platformRuntime,
      stores: deps.signingEngineStores,
      seamsWebConfigs: this.seamsWebConfigs,
      nearClient: this.nearClient,
      touchIdPrompt: this.touchIdPrompt,
      userPreferencesManager: this.userPreferencesManager,
      nonceCoordinator: assembly.nonceCoordinator,
      ensureSealedRefreshStartupParity: () => this.ensureSealedRefreshStartupParity(),
      touchConfirm: this.touchConfirm,
      getEmailOtpWarmSessionStatus: (sessionId) =>
        this.emailOtpSessions.readWarmSessionStatusOnly(sessionId),
      consumeEmailOtpWarmSessionUses: (args) => this.emailOtpSessions.consumeWarmSessionUses(args),
      getWalletSigningBudgetStatus: (args) =>
        readTrustedWalletSigningBudgetStatusOperation(
          {
            ecdsaSessions: this.warmSigning.ecdsaSessions,
          },
          args,
        ),
      signerWorkerManager: this.signerWorkerManager,
      getWorkerBaseOrigin: () => this.workerBaseOrigin,
      shouldPrewarmWorkers: deps.shouldPrewarmWorkers,
      getTheme: () => this.theme,
      signTempo: (args) => this.signingRuntime.services.evmFamilySigning.signTempo(args),
      extractCosePublicKey: (attestationObjectBase64url: string) =>
        this.extractCosePublicKey(attestationObjectBase64url),
      initializeCurrentUser: (nearAccountId: AccountId, nearClientArg?: NearClient) =>
        registrationPublic.initializeCurrentUser(this.registrationPublicDeps, {
          nearAccountId,
          nearClient: nearClientArg,
        }),
      persistThresholdEcdsaBootstrapForWalletTarget: (args) =>
        persistThresholdEcdsaBootstrapForWalletTargetOperation({
          bootstrapStore:
            deps.signingEngineStores.walletProfileAndSignerRecords.ecdsaBootstrapStore,
          walletId: args.walletId,
          chainTarget: args.chainTarget,
          bootstrap: args.bootstrap,
          signerAuth: args.signerAuth,
        }),
      upsertThresholdEcdsaSessionFromBootstrap: (args) => {
        if (args.hasEmailOtpAuthContext) {
          upsertThresholdEcdsaSessionFromBootstrapOperation(this.warmSigning.ecdsaSessions, {
            walletId: args.walletId,
            chainTarget: args.chainTarget,
            bootstrap: args.bootstrap,
            source: 'email_otp',
            emailOtpAuthContext: args.emailOtpAuthContext,
          });
          return;
        }
        upsertThresholdEcdsaSessionFromBootstrapOperation(this.warmSigning.ecdsaSessions, {
          walletId: args.walletId,
          chainTarget: args.chainTarget,
          bootstrap: args.bootstrap,
          source: args.source,
        });
      },
      listThresholdEcdsaKeyRefsForWalletTarget: (args) =>
        listThresholdEcdsaKeyRefsForWalletTargetOperation(this.warmSigning.ecdsaSessions, args),
      listThresholdEcdsaSessionRecordsForWalletTarget: (args) =>
        listThresholdEcdsaSessionRecordsForWalletTargetOperation(
          this.warmSigning.ecdsaSessions,
          args,
        ),
      getThresholdEcdsaSessionRecordByKey: (identity) =>
        getThresholdEcdsaSessionRecordByIdentityOperation(this.warmSigning.ecdsaSessions, identity),
      getEmailOtpThresholdEcdsaSessionRecordForSigning: (args) =>
        getThresholdEcdsaSessionRecordForWalletTargetOperation(this.warmSigning.ecdsaSessions, {
          walletId: args.walletId,
          chainTarget: args.chainTarget,
          source: 'email_otp',
        }),
      getPasskeyThresholdEcdsaSessionRecordForSigning: (args) =>
        getThresholdEcdsaSessionRecordForWalletTargetOperation(this.warmSigning.ecdsaSessions, {
          walletId: args.walletId,
          chainTarget: args.chainTarget,
          source: args.source,
        }),
      requestEmailOtpTransactionSigningChallenge: (args) =>
        'walletSession' in args
          ? this.emailOtpSessions.requestTransactionSigningChallenge({
              kind: 'wallet_session_challenge',
              walletSession: args.walletSession,
              chain: args.chain,
              ...(args.authLane ? { authLane: args.authLane } : {}),
            })
          : this.emailOtpSessions.requestTransactionSigningChallenge({
              kind: 'near_account_challenge',
              nearAccountId: args.nearAccountId,
              chain: args.chain,
              ...(args.authLane ? { authLane: args.authLane } : {}),
            }),
      isEmailOtpEd25519WarmupPending: (args) => this.emailOtpSessions.isEd25519WarmupPending(args),
      waitForPendingEmailOtpEd25519Warmup: (args) =>
        this.emailOtpSessions.waitForPendingEd25519Warmup(args),
      loginWithEmailOtpEd25519CapabilityForSigning: (args) =>
        this.emailOtpSessions.loginWithEd25519CapabilityForSigning(args),
      provisionThresholdEd25519Session: (args) =>
        provisionThresholdEd25519SessionOperation(
          {
            credentialStore: deps.signingEngineStores.recoveryAndDeviceLinking.credentialStore,
            touchIdPrompt: this.touchIdPrompt,
            touchConfirm: this.touchConfirm,
            defaultRelayerUrl: this.seamsWebConfigs.network.relayer?.url || '',
            getSignerWorkerContext: () =>
              this.enginePorts.thresholdSessionActivationDeps.getSignerWorkerContext(),
          },
          args,
        ),
      loginWithEmailOtpEcdsaCapabilityForSigning: (args) =>
        this.emailOtpSessions.loginWithEcdsaCapabilityForSigning(args),
      restorePersistedSessionForSigning: (args) =>
        args.authMethod === 'passkey'
          ? this.touchConfirm.restorePersistedSessionForSigning({
              ...args,
              authMethod: 'passkey',
            })
          : this.emailOtpSessions.restorePersistedSessionForSigning(args),
      readAvailableSigningLanesForSigning: (args) =>
        readPersistedAvailableSigningLanesForSigningOperation(
          {
            ecdsaSessions: this.warmSigning.ecdsaSessions,
            statusReader: this.warmSigning.statusUiConfirm,
            getEmailOtpWarmSessionStatus: (sessionId) =>
              this.emailOtpSessions.readWarmSessionStatusOnly(sessionId),
            getWalletSigningBudgetStatus: (statusArgs) =>
              this.enginePorts.signingSessionCoordinator.getAvailableStatus(statusArgs),
          },
          args,
          configuredThresholdEcdsaChainTargets(this.seamsWebConfigs.network.chains),
        ),
      consumeSingleUseEmailOtpEcdsaLane: (command) =>
        consumeSingleUseEmailOtpEcdsaLaneOperation(this.warmSigning.ecdsaSessions, command),
      markThresholdEd25519EmailOtpSessionConsumedForAccount: (args) =>
        markThresholdEd25519EmailOtpSessionConsumedForAccountOperation(args),
      clearThresholdEcdsaSessionRecordForWalletTarget: (args) =>
        clearThresholdEcdsaSessionRecordForWalletTargetOperation(
          this.warmSigning.ecdsaSessions,
          args,
        ),
      provisionThresholdEcdsaSession: (args) =>
        provisionThresholdEcdsaSessionOperation(
          {
            queueByWallet: this.thresholdEcdsaBootstrapQueueByWallet,
            activationDeps: this.enginePorts.thresholdSessionActivationDeps,
            touchConfirm: this.touchConfirm,
            resolveSealTransport: ({ thresholdSessionId, chainTarget }) =>
              this.warmSigning.capabilityReader.resolveEcdsaSealTransportByThresholdSessionId({
                thresholdSessionId,
                chainTarget,
              }),
          },
          args,
        ),
      withThresholdEcdsaCommitQueue: (queueArgs) =>
        withThresholdEcdsaCommitQueue({
          queueByKey: this.thresholdEcdsaCommitQueueByKey,
          ...queueArgs,
          walletId: toWalletId(queueArgs.walletId),
        }),
      withThresholdEd25519CommitQueue: (queueArgs) =>
        withThresholdEd25519CommitQueue({
          queueByKey: this.thresholdEd25519CommitQueueByKey,
          ...queueArgs,
        }),
    });
    const warmSessionPublicDeps = createBrowserWarmSessionPublicDeps({
      seamsWebConfigs: this.seamsWebConfigs,
      stores: deps.signingEngineStores,
      touchIdPrompt: this.touchIdPrompt,
      touchConfirm: this.touchConfirm,
      warmSigning: this.warmSigning,
      thresholdEcdsaBootstrapQueueByWallet: this.thresholdEcdsaBootstrapQueueByWallet,
      ensureSealedRefreshStartupParity: () => this.ensureSealedRefreshStartupParity(),
      enginePorts: this.enginePorts,
    });
    this.passkeyPublicDeps = warmSessionPublicDeps.passkeyPublicDeps;
    this.warmCapabilitiesPublicDeps = warmSessionPublicDeps.warmCapabilitiesPublicDeps;
    this.registrationPublicDeps = createBrowserRegistrationPublicDeps({
      enginePorts: this.enginePorts,
    });
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

  async restorePersistedSessionsForWallet(
    args: RestorePersistedSessionsForWalletInput,
  ): Promise<RestorePersistedSessionsForWalletResult> {
    return await sessionPublic.restorePersistedSessionsForWallet(this.sessionPublicDeps, args);
  }

  async readPersistedAvailableSigningLanes(
    args: Omit<ReadAvailableSigningLanesInput, 'ecdsaChainTargets'>,
  ): Promise<AvailableSigningLanes> {
    return await sessionPublic.readPersistedAvailableSigningLanes(this.sessionPublicDeps, args);
  }

  async warmCriticalResources(nearAccountId?: string): Promise<void> {
    await this.ensureSealedRefreshStartupParity();
    await this.enginePorts.getManagerConveniencePorts().warmCriticalResources(nearAccountId);
  }

  getRpId(): string {
    return this.touchIdPrompt.getRpId();
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

  async signTempo(args: {
    walletSession: WalletSessionRef;
    request: TempoSigningRequest | EvmSigningRequest;
    chainTarget: ThresholdEcdsaChainTarget;
    confirmationConfigOverride?: Partial<ConfirmationConfig>;
    shouldAbort?: () => boolean;
    onEvent?: (event: SigningFlowEvent) => void;
  }): Promise<TempoSignedResult | EvmSignedResult> {
    return await signTempoOperation(this.enginePorts.tempoSigningDeps, args);
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

  requestRegistrationCredentialConfirmation(params: {
    nearAccountId: string;
    signerSlot: number;
    confirmerText?: { title?: string; body?: string };
    confirmationConfigOverride?: Partial<ConfirmationConfig>;
    challengeB64u?: string;
  }): Promise<RegistrationCredentialConfirmationPayload> {
    return registrationPublic.requestRegistrationCredentialConfirmation(
      this.registrationPublicDeps,
      params,
    );
  }

  getAuthenticationCredentialsSerialized(args: {
    nearAccountId: AccountId;
    challengeB64u: string;
    allowCredentials: WebAuthnAllowCredential[];
    includeSecondPrfOutput?: boolean;
  }): Promise<WebAuthnAuthenticationCredential> {
    return registrationPublic.getAuthenticationCredentialsSerialized(
      this.registrationPublicDeps,
      args,
    );
  }

  extractCosePublicKey(attestationObjectBase64url: string): Promise<Uint8Array> {
    return registrationPublic.extractCosePublicKey(
      this.registrationPublicDeps,
      attestationObjectBase64url,
    );
  }

  async exportKeypairWithUI(
    input: SigningEngineExportKeypairWithUIInput,
  ): Promise<{ accountId: string; exportedSchemes: Array<'ed25519' | 'secp256k1'> }> {
    return await recoveryPublic.exportKeypairWithUI(this.recoveryPublicDeps, input);
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
    clearAllThresholdEd25519ClientPresigns();
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

  async scheduleThresholdEcdsaLoginPresignPrefill(args: {
    walletId: WalletId;
    chainTarget: ThresholdEcdsaChainTarget;
    thresholdEcdsaSessionRecord: ThresholdEcdsaSessionRecord;
    minRemainingUsesBeforePrefill?: number;
  }): Promise<ThresholdEcdsaLoginPrefillResult> {
    return await warmCapabilitiesPublic.scheduleThresholdEcdsaLoginPresignPrefill(
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

  deriveThresholdEd25519HssClientOutputMask(
    args: Parameters<typeof thresholdEd25519Public.deriveThresholdEd25519HssClientOutputMask>[1],
  ): ReturnType<typeof thresholdEd25519Public.deriveThresholdEd25519HssClientOutputMask> {
    return thresholdEd25519Public.deriveThresholdEd25519HssClientOutputMask(
      this.thresholdEd25519PublicDeps,
      args,
    );
  }

  buildThresholdEd25519HssClientOwnedStagedEvaluatorArtifact(
    args: Parameters<
      typeof thresholdEd25519Public.buildThresholdEd25519HssClientOwnedStagedEvaluatorArtifact
    >[1],
  ): ReturnType<
    typeof thresholdEd25519Public.buildThresholdEd25519HssClientOwnedStagedEvaluatorArtifact
  > {
    return thresholdEd25519Public.buildThresholdEd25519HssClientOwnedStagedEvaluatorArtifact(
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

}
