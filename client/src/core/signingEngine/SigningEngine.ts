import { IndexedDBManager } from '@/core/indexedDB';
import { createBrowserPlatformRuntime, type BrowserPlatformRuntime } from '@/core/platform';
import type {
  ClientAuthenticatorData,
  ClientUserData,
  StoreUserDataInput,
} from '../accountData/near/types';
import type { NearClient, SignedTransaction } from '../rpcClients/near/NearClient';
import type { NonceCoordinator } from './nonce/NonceCoordinator';
import { toAccountId, type AccountId } from '../types/accountIds';
import type { ActionArgsWasm } from '../types/actions';
import type { SigningFlowEvent } from '../types/sdkSentEvents';
import type {
  EmailOtpAuthPolicy,
  SigningSessionStatus,
  SeamsConfigsReadonly,
  ThemeName,
} from '../types/seams';
import type { WebAuthnAuthenticationCredential, WebAuthnRegistrationCredential } from '../types';
import type { WarmSessionSealTransportInput } from '../types/secure-confirm-worker';
import {
  type WalletEmailOtpChannel,
  type WalletEmailOtpLoginOperation,
} from '@shared/utils/emailOtpDomain';
import { SIGNER_AUTH_METHODS, SIGNER_SOURCES } from '@shared/utils/signerDomain';
import { type AppOrThresholdSessionAuth } from '@shared/utils/sessionTokens';
import type { UserPreferencesManager } from './session/userPreferences';
import type {
  ThresholdEcdsaCanonicalExportArtifact,
  ThresholdEcdsaSecp256k1KeyRef,
} from './interfaces/signing';
import type { ThresholdEcdsaSessionBootstrapResult } from './threshold/ecdsa/activation';
import type { SignerWorkerManager } from './workerManager/SignerWorkerManager';
import type { EmailOtpWorkerProgressEvent } from './workerManager/workerTypes';
import type { UiConfirmRuntimeBridgePort } from './uiConfirm/types';
import { readTrustedWalletSigningBudgetStatus as readTrustedWalletSigningBudgetStatusOperation } from './session/budget/budgetStatusReader';
import type { TouchIdPrompt } from './stepUpConfirmation/passkeyPrompt/touchIdPrompt';
import type { WebAuthnAllowCredential } from './webauthnAuth/credentials/collectAuthenticationCredentialForChallengeB64u';
import type { EvmSigningRequest } from './chains/evm/types';
import type { EvmSignedResult } from './chains/evm/evmAdapter';
import type { TempoSigningRequest } from './chains/tempo/types';
import type { TempoSignedResult } from './chains/tempo/tempoAdapter';
import type { EcdsaBootstrapRequest } from './session/passkey/ecdsaBootstrap';
import { claimWarmSessionPrfFirst } from './session/passkey/prfClaim';
import type {
  EvmFamilyEcdsaKeyHandle,
  EvmFamilyEcdsaKeyIdentity,
  EvmFamilyEcdsaSessionLanePolicy,
} from './session/identity/evmFamilyEcdsaIdentity';
import { toRpId } from './session/identity/evmFamilyEcdsaIdentity';
import * as thresholdEd25519Public from './threshold/ed25519/public';
import {
  persistThresholdEcdsaBootstrapForWalletTarget as persistThresholdEcdsaBootstrapForWalletTargetOperation,
  type ThresholdEcdsaBootstrapSignerAuth,
} from './session/warmCapabilities/ecdsaBootstrapPersistence';
import {
  clearThresholdEcdsaSessionRecordForWalletTarget as clearThresholdEcdsaSessionRecordForWalletTargetOperation,
  getStoredThresholdEd25519SessionRecordForAccount,
  getThresholdEcdsaSessionRecordByKey as getThresholdEcdsaSessionRecordByIdentityOperation,
  getThresholdEcdsaSessionRecordForWalletTarget as getThresholdEcdsaSessionRecordForWalletTargetOperation,
  listThresholdEcdsaKeyRefsForWalletTarget as listThresholdEcdsaKeyRefsForWalletTargetOperation,
  listThresholdEcdsaSessionRecordsForWalletTarget as listThresholdEcdsaSessionRecordsForWalletTargetOperation,
  markThresholdEd25519EmailOtpSessionConsumedForAccount as markThresholdEd25519EmailOtpSessionConsumedForAccountOperation,
  consumeSingleUseEmailOtpEcdsaLane as consumeSingleUseEmailOtpEcdsaLaneOperation,
  upsertThresholdEcdsaSessionFromBootstrap as upsertThresholdEcdsaSessionFromBootstrapOperation,
  type ThresholdEd25519SessionRecord,
  type ThresholdEcdsaSessionRecord,
} from './session/persistence/records';
import type {
  ThresholdEcdsaEmailOtpAuthContext,
  ThresholdEcdsaSessionStoreSource,
} from './session/identity/laneIdentity';
import {
  configuredThresholdEcdsaChainTargets,
  thresholdEcdsaChainTargetKey,
  toWalletId,
  type ThresholdEcdsaChainTarget,
  type WalletId,
  type WalletSessionRef,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { type ThresholdEcdsaLoginPrefillResult } from './session/warmCapabilities/ecdsaLoginPrefill';
import { type ThresholdRuntimePolicyScope } from './threshold/sessionPolicy';
import {
  signNear as signNearOperation,
  type NearSignIntentRequest,
  type NearSignIntentResult,
  type SignTransactionsWithActionsInput,
} from './flows/signNear/signNear';
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
} from './flows/signEvmFamily/signEvmFamily';
import type { EvmFamilySigningTarget } from './flows/signEvmFamily/types';
import {
  clearThresholdEcdsaCommitQueue,
  withThresholdEcdsaCommitQueue,
  type ThresholdEcdsaCommitQueueByKey,
} from './threshold/ecdsa/commitQueue';
import {
  clearThresholdEd25519CommitQueue,
  withThresholdEd25519CommitQueue,
  type ThresholdEd25519CommitQueueByKey,
} from './threshold/ed25519/commitQueue';
import * as recoveryPublic from './flows/recovery/public';
import type {
  RecoveryPublicDeps,
  SigningEngineExportKeypairWithUIInput,
  KeyExportEventCallback,
} from './flows/recovery/public';
import type { RegistrationCredentialConfirmationPayload } from './workerManager/validation';
import type { ConfirmationConfig } from '../types/signer-worker';
import * as registrationPublic from './flows/registration/public';
import type {
  StoredRegistrationData,
  StoreAuthenticatorInput,
  StoreWalletEcdsaRegistrationInput,
  StoreWalletEcdsaSignerRecordsInput,
  StoreWalletEcdsaSignerRecordsResult,
  StoreWalletEd25519RegistrationInput,
  StoreWalletEd25519SignerRecordInput,
} from './flows/registration/public';
import {
  type EmailOtpPublicDeps,
  type EnrollAndLoginWithEmailOtpEcdsaCapabilityInternalArgs,
  type EnrollAndLoginWithEmailOtpEcdsaCapabilityInternalResult,
  type LoginWithEmailOtpEcdsaCapabilityInternalArgs,
  type LoginWithEmailOtpEcdsaCapabilityInternalResult,
  type PrepareEmailOtpRegistrationEnrollmentMaterialInternalArgs,
  type PrepareEmailOtpRegistrationEnrollmentMaterialInternalResult,
} from './flows/signEvmFamily/emailOtpPublic';
import * as emailOtpPublic from './flows/signEvmFamily/emailOtpPublic';
import { initializeSigningEngineRuntime } from './assembly/createSigningEngineRuntime';
import { createManagerAssembly } from './assembly/createManagers';
import { verifySealedRefreshStartupParity } from '../rpcClients/relayer/sealedRefreshCapabilities';
import type { ThresholdEcdsaHssRouteAuth } from '../rpcClients/relayer/thresholdEcdsa';
import type {
  WalletRegistrationEcdsaClientBootstrap,
  WalletRegistrationEcdsaHssRespondBootstrap,
  WalletRegistrationEcdsaPrepareContext,
  WalletRegistrationEcdsaWalletKey,
} from '../rpcClients/relayer/walletRegistration';
import { buildWalletRegistrationEcdsaSessionBootstrap } from '../rpcClients/relayer/walletRegistration';
import type { WarmSessionEcdsaCapabilityState } from './session/warmCapabilities/types';
import type {
  ProvisionWarmEd25519CapabilityResult,
  WarmEcdsaSigningSessionStatus,
} from './session/warmCapabilities/types';
import { createSigningEnginePorts } from './assembly/createPorts';
import { provisionThresholdEd25519Session as provisionThresholdEd25519SessionOperation } from './session/passkey/ed25519SessionProvision';
import { provisionThresholdEcdsaSession as provisionThresholdEcdsaSessionOperation } from './session/passkey/ecdsaSessionProvision';
import type { EmailOtpThresholdSessionCoordinator } from './session/emailOtp/EmailOtpThresholdSessionCoordinator';
import type { EmailOtpBootstrapRecovery } from './stepUpConfirmation/otpPrompt/bootstrapRecovery';
import type {
  RestorePersistedSessionsForWalletInput,
  RestorePersistedSessionsForWalletResult,
  ReadAvailableSigningLanesInput,
  AvailableSigningLanes,
  SessionPublicDeps,
  ThresholdEcdsaSessionRecord as SessionPublicThresholdEcdsaSessionRecord,
  UpsertThresholdEcdsaSessionFromBootstrapInput,
  GetThresholdEcdsaKeyRefForWalletTargetInput,
  ListThresholdEcdsaSessionRecordsForWalletTargetInput,
} from './session/public';
import * as sessionPublic from './session/public';
import { readPersistedAvailableSigningLanesForSigning as readPersistedAvailableSigningLanesForSigningOperation } from './session/availability/persistedAvailableSigningLanes';
import {
  createPasskeyPublicDeps,
  createWarmCapabilitiesPublicDeps,
  createWarmSigningPorts,
  type WarmSigningPorts,
} from './assembly/ports/warmSigning';
import { createStepUpRuntime } from './assembly/ports/stepUpRuntime';
import { createRecoveryPublicDeps } from './assembly/ports/recovery';
import * as warmCapabilitiesPublic from './session/warmCapabilities/public';
import type { WarmCapabilitiesPublicDeps } from './session/warmCapabilities/public';
import * as passkeyPublic from './session/passkey/public';
import type { ConnectEd25519SessionArgs, PasskeyPublicDeps } from './session/passkey/public';
import {
  buildThresholdEcdsaHssRoleLocalClientBootstrapWasm,
  type ThresholdEcdsaHssRoleLocalClientBootstrap,
} from './threshold/crypto/hssClientSignerWasm';
import {
  toEcdsaHssSigningRootId,
  toEcdsaHssSigningRootVersion,
  toEcdsaHssThresholdKeyId,
} from './session/identity/emailOtpHssIdentity';

export type { ThresholdEcdsaSessionBootstrapResult } from './threshold/ecdsa/activation';
export type { EmailOtpBootstrapRecovery } from './stepUpConfirmation/otpPrompt/bootstrapRecovery';
export type { NearSignIntentRequest, NearSignIntentResult } from './flows/signNear/signNear';
export type { ThresholdEcdsaLoginPrefillResult } from './session/warmCapabilities/ecdsaLoginPrefill';

export type WalletRegistrationEcdsaPreparedClientBootstrap = {
  clientBootstrap: WalletRegistrationEcdsaClientBootstrap;
  localClientBootstrap: ThresholdEcdsaHssRoleLocalClientBootstrap;
  clientRootShare32B64u: string;
};

export type BootstrapLoginEcdsaSessionFromRestoredEd25519Args = {
  walletId: WalletId;
  chainTarget: ThresholdEcdsaChainTarget;
  relayerUrl: string;
  keyHandle: EvmFamilyEcdsaKeyHandle;
  key: EvmFamilyEcdsaKeyIdentity;
  lanePolicy: EvmFamilyEcdsaSessionLanePolicy;
  ttlMs: number;
  remainingUses: number;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  runtimeScopeBootstrap?: {
    environmentId: string;
    publishableKey: string;
  };
};

/**
 * SigningEngine is the signing composition root:
 * - owns construction and lifecycle for worker managers
 * - exposes direct public signing/session/recovery/persistence methods
 * - keeps shared runtime/config helpers and operation ports internally
 */
export class SigningEngine {
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
  private readonly thresholdEcdsaSessionByLane: Map<string, ThresholdEcdsaSessionRecord> =
    new Map();
  private readonly thresholdEcdsaExportArtifactByLane: Map<
    string,
    ThresholdEcdsaCanonicalExportArtifact
  > = new Map();
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
  private readonly platformRuntime: BrowserPlatformRuntime;
  private readonly enginePorts: ReturnType<typeof createSigningEnginePorts>;

  readonly seamsPasskeyConfigs: SeamsConfigsReadonly;

  constructor(seamsPasskeyConfigs: SeamsConfigsReadonly, nearClient: NearClient) {
    this.seamsPasskeyConfigs = seamsPasskeyConfigs;
    this.nearClient = nearClient;
    this.sealedRefreshStartupParityPromise = verifySealedRefreshStartupParity({
      configs: this.seamsPasskeyConfigs,
    }).catch((error: unknown) => {
      this.sealedRefreshStartupParityError =
        error instanceof Error
          ? error
          : new Error(String(error || 'sealed refresh parity check failed'));
    });

    const assembly = createManagerAssembly({
      indexedDB: IndexedDBManager,
      seamsPasskeyConfigs: this.seamsPasskeyConfigs,
      nearClient: this.nearClient,
      getTheme: () => this.theme,
      getAppearanceTokens: () => this.seamsPasskeyConfigs.ui.appearance?.tokens,
    });

    this.touchIdPrompt = assembly.touchIdPrompt;
    this.userPreferencesManager = assembly.userPreferencesManager;
    this.nonceCoordinator = assembly.nonceCoordinator;
    this.signerWorkerManager = assembly.signerWorkerManager;
    this.platformRuntime = createBrowserPlatformRuntime({
      indexedDB: IndexedDBManager,
      workerCtx: this.signerWorkerManager.getContext(),
      ecdsaSessionStore: {
        recordsByLane: this.thresholdEcdsaSessionByLane,
        exportArtifactsByLane: this.thresholdEcdsaExportArtifactByLane,
      },
    });
    const stepUpRuntime = createStepUpRuntime({
      seamsPasskeyConfigs: this.seamsPasskeyConfigs,
      touchIdPrompt: this.touchIdPrompt,
      signerWorkerManager: this.signerWorkerManager,
      indexedDB: IndexedDBManager,
      baseTouchConfirm: assembly.touchConfirm,
      getSignerWorkerContext: () =>
        this.enginePorts.thresholdSessionActivationDeps.getSignerWorkerContext(),
      thresholdEcdsaBootstrapQueueByWallet: this.thresholdEcdsaBootstrapQueueByWallet,
      getEcdsaSessions: () => this.warmSigning.ecdsaSessions,
      getWarmCapabilityReader: () => this.warmSigning.capabilityReader,
      getThresholdEcdsaSessionRecordByThresholdSessionId: (thresholdSessionId) =>
        this.warmSigning.getThresholdEcdsaSessionRecordByThresholdSessionId(thresholdSessionId),
      ensureSealedRefreshStartupParity: () => this.ensureSealedRefreshStartupParity(),
    });
    this.emailOtpSessions = stepUpRuntime.emailOtpSessions;
    this.touchConfirm = stepUpRuntime.touchConfirm;
    this.warmSigning = createWarmSigningPorts({
      touchConfirm: this.touchConfirm,
      getEmailOtpWarmSessionStatus: (sessionId) =>
        this.emailOtpSessions.readWarmSessionStatusOnly(sessionId),
      signingSessionSeal: this.seamsPasskeyConfigs.signing.sessionSeal,
      recordsByLane: this.thresholdEcdsaSessionByLane,
      exportArtifactsByLane: this.thresholdEcdsaExportArtifactByLane,
    });
    const sessionRestore: SessionPublicDeps['restore'] = {
      emailOtp: (restoreArgs) =>
        this.emailOtpSessions.restorePersistedSessionsForWallet(restoreArgs),
    };
    if (this.touchConfirm.restorePersistedSessionsForWallet) {
      sessionRestore.passkey = (restoreArgs) =>
        this.touchConfirm.restorePersistedSessionsForWallet!(restoreArgs);
    }
    this.sessionPublicDeps = {
      availableLanes: {
        ecdsaSessions: this.warmSigning.ecdsaSessions,
        statusReader: this.touchConfirm,
        getEmailOtpWarmSessionStatus: (sessionId) =>
          this.emailOtpSessions.readWarmSessionStatusOnly(sessionId),
        getWalletSigningBudgetStatus: (statusArgs) =>
          readTrustedWalletSigningBudgetStatusOperation(
            {
              ecdsaSessions: this.warmSigning.ecdsaSessions,
            },
            statusArgs,
          ),
      },
      ecdsaSessions: this.warmSigning.ecdsaSessions,
      signingSessionSeal: this.seamsPasskeyConfigs.signing.sessionSeal,
      getConfiguredEcdsaChainTargets: () =>
        configuredThresholdEcdsaChainTargets(this.seamsPasskeyConfigs.network.chains),
      restore: sessionRestore,
    };
    this.emailOtpPublicDeps = {
      ecdsaSessions: this.warmSigning.ecdsaSessions,
      relayerUrl: this.seamsPasskeyConfigs.network.relayer?.url || '',
      shamirPrimeB64u: this.seamsPasskeyConfigs.signing.sessionSeal?.shamirPrimeB64u || '',
      getSignerWorkerContext: () =>
        this.enginePorts.thresholdSessionActivationDeps.getSignerWorkerContext(),
      emailOtpSessions: this.emailOtpSessions,
    };
    this.recoveryPublicDeps = createRecoveryPublicDeps({
      seamsPasskeyConfigs: this.seamsPasskeyConfigs,
      touchIdPrompt: this.touchIdPrompt,
      signerWorkerManager: this.signerWorkerManager,
      privateKeyExportRecovery: {
        indexedDB: IndexedDBManager,
        relayerUrl: this.seamsPasskeyConfigs.network.relayer.url,
        getRpId: () => this.touchIdPrompt.getRpId(),
        requestExportPrivateKeysWithUi: (payload) =>
          this.signerWorkerManager.requestExportPrivateKeysWithUi(payload),
        getTheme: () => this.theme,
      },
      ecdsaSessions: this.warmSigning.ecdsaSessions,
      touchConfirm: this.touchConfirm,
      emailOtpSessions: this.emailOtpSessions,
      indexedDB: IndexedDBManager,
      warmSessionPolicy: {
        getWarmSession: (nearAccountId) =>
          this.warmSigning.capabilityReader.getWarmSession(nearAccountId),
        resolveExactEcdsaRecord: (recordArgs) =>
          this.warmSigning.statusReader.resolveExactEcdsaRecord(recordArgs),
      },
      getWalletSigningBudgetStatus: (statusArgs) =>
        readTrustedWalletSigningBudgetStatusOperation(
          {
            ecdsaSessions: this.warmSigning.ecdsaSessions,
          },
          statusArgs,
        ),
    });

    this.enginePorts = createSigningEnginePorts({
      platformRuntime: this.platformRuntime,
      seamsPasskeyConfigs: this.seamsPasskeyConfigs,
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
      getTheme: () => this.theme,
      signTempo: (args) => this.signTempo(args),
      extractCosePublicKey: (attestationObjectBase64url: string) =>
        this.extractCosePublicKey(attestationObjectBase64url),
      initializeCurrentUser: (nearAccountId: AccountId, nearClientArg?: NearClient) =>
        registrationPublic.initializeCurrentUser(this.registrationPublicDeps, {
          nearAccountId,
          nearClient: nearClientArg,
        }),
      persistThresholdEcdsaBootstrapForWalletTarget: (args) =>
        persistThresholdEcdsaBootstrapForWalletTargetOperation({
          indexedDB: this.enginePorts.indexedDB,
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
            indexedDB: this.enginePorts.indexedDB,
            touchIdPrompt: this.touchIdPrompt,
            touchConfirm: this.touchConfirm,
            defaultRelayerUrl: this.seamsPasskeyConfigs.network.relayer?.url || '',
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
          configuredThresholdEcdsaChainTargets(this.seamsPasskeyConfigs.network.chains),
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
    this.passkeyPublicDeps = createPasskeyPublicDeps({
      seamsPasskeyConfigs: this.seamsPasskeyConfigs,
      indexedDB: this.enginePorts.indexedDB,
      touchIdPrompt: this.touchIdPrompt,
      touchConfirm: this.touchConfirm,
      warmSigning: this.warmSigning,
      thresholdEcdsaBootstrapQueueByWallet: this.thresholdEcdsaBootstrapQueueByWallet,
      ensureSealedRefreshStartupParity: () => this.ensureSealedRefreshStartupParity(),
      thresholdSessionActivationDeps: this.enginePorts.thresholdSessionActivationDeps,
    });
    this.warmCapabilitiesPublicDeps = createWarmCapabilitiesPublicDeps({
      seamsPasskeyConfigs: this.seamsPasskeyConfigs,
      indexedDB: this.enginePorts.indexedDB,
      touchConfirm: this.touchConfirm,
      warmSigning: this.warmSigning,
      thresholdSessionActivationDeps: this.enginePorts.thresholdSessionActivationDeps,
      resolveCanonicalThresholdEcdsaSessionIdForWalletTarget:
        this.enginePorts.resolveCanonicalThresholdEcdsaSessionIdForWalletTarget,
      signingSessionCoordinator: this.enginePorts.signingSessionCoordinator,
    });
    this.registrationPublicDeps = {
      accountLifecycle: this.enginePorts.registrationAccountLifecycleDeps,
      session: this.enginePorts.registrationSessionDeps,
      signingKeyOps: this.enginePorts.nearKeyOpsDeps.signingKeyOps,
    };
    this.thresholdEd25519PublicDeps = this.enginePorts.thresholdEd25519LifecycleDeps;

    initializeSigningEngineRuntime({
      seamsPasskeyConfigs: this.seamsPasskeyConfigs,
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

  storeUserData(userData: StoreUserDataInput): Promise<void> {
    return registrationPublic.storeUserData(this.registrationPublicDeps, userData);
  }

  getAllUsers(): Promise<ClientUserData[]> {
    return registrationPublic.getAllUsers(this.registrationPublicDeps);
  }

  getUserBySignerSlot(
    nearAccountId: AccountId,
    signerSlot: number,
  ): Promise<ClientUserData | null> {
    return registrationPublic.getUserBySignerSlot(
      this.registrationPublicDeps,
      nearAccountId,
      signerSlot,
    );
  }

  getLastUser(): Promise<ClientUserData | null> {
    return registrationPublic.getLastUser(this.registrationPublicDeps);
  }

  getAuthenticatorsByUser(nearAccountId: AccountId): Promise<ClientAuthenticatorData[]> {
    return this.nearAuthenticatorsByAccount(nearAccountId);
  }

  nearAuthenticatorsByAccount(nearAccountId: AccountId): Promise<ClientAuthenticatorData[]> {
    return registrationPublic.nearAuthenticatorsByAccount(
      this.registrationPublicDeps,
      nearAccountId,
    );
  }

  updateLastLogin(nearAccountId: AccountId): Promise<void> {
    return registrationPublic.updateLastLogin(this.registrationPublicDeps, nearAccountId);
  }

  setLastUser(nearAccountId: AccountId, signerSlot: number = 1): Promise<void> {
    return registrationPublic.setLastUser(this.registrationPublicDeps, nearAccountId, signerSlot);
  }

  initializeCurrentUser(nearAccountId: AccountId, nearClientArg?: NearClient): Promise<void> {
    return registrationPublic.initializeCurrentUser(this.registrationPublicDeps, {
      nearAccountId,
      nearClient: nearClientArg,
    });
  }

  storeAuthenticator(authenticatorData: StoreAuthenticatorInput): Promise<void> {
    return registrationPublic.storeAuthenticator(this.registrationPublicDeps, authenticatorData);
  }

  rollbackUserRegistration(nearAccountId: AccountId): Promise<void> {
    return registrationPublic.rollbackUserRegistration(this.registrationPublicDeps, nearAccountId);
  }

  hasPasskeyCredential(nearAccountId: AccountId): Promise<boolean> {
    return registrationPublic.hasPasskeyCredential(this.registrationPublicDeps, nearAccountId);
  }

  atomicStoreRegistrationData(args: {
    nearAccountId: AccountId;
    credential: WebAuthnRegistrationCredential;
    operationalPublicKey: string;
  }): Promise<StoredRegistrationData> {
    return registrationPublic.atomicStoreRegistrationData(this.registrationPublicDeps, args);
  }

  storeWalletEd25519RegistrationData(
    args: StoreWalletEd25519RegistrationInput,
  ): Promise<StoredRegistrationData> {
    return registrationPublic.storeWalletEd25519RegistrationData(
      this.registrationPublicDeps,
      args,
    );
  }

  storeWalletEmailOtpEd25519RegistrationData(
    args: registrationPublic.StoreWalletEmailOtpEd25519RegistrationInput,
  ): Promise<StoredRegistrationData> {
    return registrationPublic.storeWalletEmailOtpEd25519RegistrationData(
      this.registrationPublicDeps,
      args,
    );
  }

  storeWalletEd25519SignerRecord(
    args: StoreWalletEd25519SignerRecordInput,
  ): Promise<StoredRegistrationData> {
    return registrationPublic.storeWalletEd25519SignerRecord(
      this.registrationPublicDeps,
      args,
    );
  }

  storeWalletEcdsaSignerRecords(
    args: StoreWalletEcdsaSignerRecordsInput,
  ): Promise<StoreWalletEcdsaSignerRecordsResult> {
    return registrationPublic.storeWalletEcdsaSignerRecords(
      this.registrationPublicDeps,
      args,
    );
  }

  storeWalletEmailOtpEcdsaSignerRecords(
    args: StoreWalletEcdsaSignerRecordsInput,
  ): Promise<StoreWalletEcdsaSignerRecordsResult> {
    return registrationPublic.storeWalletEmailOtpEcdsaSignerRecords(
      this.registrationPublicDeps,
      args,
    );
  }

  storeWalletEcdsaRegistrationData(
    args: StoreWalletEcdsaRegistrationInput,
  ): Promise<StoreWalletEcdsaSignerRecordsResult> {
    return registrationPublic.storeWalletEcdsaRegistrationData(
      this.registrationPublicDeps,
      args,
    );
  }

  storeWalletEmailOtpEcdsaRegistrationData(
    args: registrationPublic.StoreWalletEmailOtpEcdsaRegistrationInput,
  ): Promise<StoreWalletEcdsaSignerRecordsResult> {
    return registrationPublic.storeWalletEmailOtpEcdsaRegistrationData(
      this.registrationPublicDeps,
      args,
    );
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

  async prepareWalletRegistrationEcdsaPreparedClientBootstrap(args: {
    prepare: WalletRegistrationEcdsaPrepareContext;
    clientRootShare32B64u: string;
  }): Promise<WalletRegistrationEcdsaPreparedClientBootstrap> {
    const clientBootstrap = await buildThresholdEcdsaHssRoleLocalClientBootstrapWasm({
      context: {
        walletId: toWalletId(args.prepare.walletId),
        rpId: toRpId(args.prepare.rpId),
        ecdsaThresholdKeyId: toEcdsaHssThresholdKeyId(args.prepare.ecdsaThresholdKeyId),
        signingRootId: toEcdsaHssSigningRootId(args.prepare.signingRootId),
        signingRootVersion: toEcdsaHssSigningRootVersion(args.prepare.signingRootVersion),
        keyPurpose: 'evm-signing',
        keyVersion: 'v1',
      },
      clientRootShare32B64u: args.clientRootShare32B64u,
      workerCtx: this.enginePorts.thresholdSessionActivationDeps.getSignerWorkerContext(),
    });
    const serverVisibleClientBootstrap: WalletRegistrationEcdsaClientBootstrap = {
      ...args.prepare,
      hssClientSharePublicKey33B64u: clientBootstrap.clientPublicKey33B64u,
      clientShareRetryCounter: clientBootstrap.clientShareRetryCounter,
      contextBinding32B64u: clientBootstrap.contextBinding32B64u,
    };
    return {
      clientBootstrap: serverVisibleClientBootstrap,
      localClientBootstrap: clientBootstrap,
      clientRootShare32B64u: args.clientRootShare32B64u,
    };
  }

  async prepareWalletRegistrationEcdsaClientBootstrap(args: {
    prepare: WalletRegistrationEcdsaPrepareContext;
    clientRootShare32B64u: string;
  }): Promise<WalletRegistrationEcdsaClientBootstrap> {
    return (await this.prepareWalletRegistrationEcdsaPreparedClientBootstrap(args)).clientBootstrap;
  }

  async persistWalletRegistrationEcdsaBootstrapForWalletKeys(args: {
    walletId: WalletId;
    relayerUrl: string;
    preparedClientBootstrap: WalletRegistrationEcdsaPreparedClientBootstrap;
    bootstrap: WalletRegistrationEcdsaHssRespondBootstrap;
    walletKeys: readonly WalletRegistrationEcdsaWalletKey[];
    auth:
      | { kind: 'passkey' }
      | { kind: 'email_otp'; emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext };
  }): Promise<void> {
    const sessionBootstraps = args.walletKeys.map((walletKey) => ({
      walletKey,
      bootstrap: buildWalletRegistrationEcdsaSessionBootstrap({
        walletId: args.walletId,
        relayerUrl: args.relayerUrl,
        chainTarget: walletKey.chainTarget,
        keygenSessionId: args.preparedClientBootstrap.clientBootstrap.requestId,
        localBootstrap: args.preparedClientBootstrap.localClientBootstrap,
        serverBootstrap: args.bootstrap,
        walletKey,
      }),
    }));
    for (const { walletKey, bootstrap } of sessionBootstraps) {
      await this.persistThresholdEcdsaBootstrapForWalletTarget({
        walletId: args.walletId,
        chainTarget: walletKey.chainTarget,
        bootstrap,
        signerAuth:
          args.auth.kind === 'email_otp'
            ? {
                authMethod: SIGNER_AUTH_METHODS.emailOtp,
                signerSource: SIGNER_SOURCES.emailOtpRegistration,
              }
            : {
                authMethod: SIGNER_AUTH_METHODS.passkey,
                signerSource: SIGNER_SOURCES.passkeyRegistration,
              },
      });
      if (args.auth.kind === 'email_otp') {
        this.upsertThresholdEcdsaSessionFromBootstrap({
          walletId: args.walletId,
          chainTarget: walletKey.chainTarget,
          bootstrap,
          source: 'email_otp',
          emailOtpAuthContext: args.auth.emailOtpAuthContext,
        });
      } else {
        this.upsertThresholdEcdsaSessionFromBootstrap({
          walletId: args.walletId,
          chainTarget: walletKey.chainTarget,
          bootstrap,
          source: 'registration',
        });
      }
      if (args.auth.kind === 'passkey') {
        const thresholdSessionId = String(bootstrap.session.sessionId || '').trim();
        const walletSigningSessionId = String(
          bootstrap.session.walletSigningSessionId ||
            bootstrap.thresholdEcdsaKeyRef.walletSigningSessionId ||
            '',
        ).trim();
        const thresholdSessionAuthToken = String(
          bootstrap.session.jwt || bootstrap.thresholdEcdsaKeyRef.thresholdSessionAuthToken || '',
        ).trim();
        const transport: WarmSessionSealTransportInput = {
          curve: 'ecdsa',
          walletId: String(args.walletId),
          chainTarget: walletKey.chainTarget,
          relayerUrl: args.relayerUrl,
        };
        if (walletSigningSessionId) {
          transport.walletSigningSessionId = walletSigningSessionId;
        }
        if (thresholdSessionAuthToken) {
          transport.thresholdSessionAuthToken = thresholdSessionAuthToken;
        }
        const sealKeyVersion = String(
          this.seamsPasskeyConfigs.signing.sessionSeal?.keyVersion || '',
        ).trim();
        if (sealKeyVersion) {
          transport.keyVersion = sealKeyVersion;
        }
        const sealShamirPrimeB64u = String(
          this.seamsPasskeyConfigs.signing.sessionSeal?.shamirPrimeB64u || '',
        ).trim();
        if (sealShamirPrimeB64u) {
          transport.shamirPrimeB64u = sealShamirPrimeB64u;
        }
        await this.enginePorts.thresholdSessionActivationDeps.touchConfirm.putWarmSessionMaterial({
          sessionId: thresholdSessionId,
          prfFirstB64u: args.preparedClientBootstrap.clientRootShare32B64u,
          expiresAtMs: Number(bootstrap.session.expiresAtMs),
          remainingUses: Number(bootstrap.session.remainingUses),
          transport,
        });
      }
    }
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
    return this.enginePorts.nearKeyOpsDeps.signingKeyOps.signTransactionWithKeyPair({
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
    return this.enginePorts.nearKeyOpsDeps.signingKeyOps.generateEphemeralNearKeypair();
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

  async bootstrapLoginEcdsaSessionFromRestoredEd25519(
    args: BootstrapLoginEcdsaSessionFromRestoredEd25519Args,
  ): Promise<ThresholdEcdsaSessionBootstrapResult> {
    const walletId = toAccountId(args.walletId);
    const restoredEd25519 = getStoredThresholdEd25519SessionRecordForAccount(walletId);
    if (!restoredEd25519) {
      throw new Error('[SigningEngine][ecdsa] restored Ed25519 session record is required');
    }
    if (restoredEd25519.source === 'email_otp' || restoredEd25519.emailOtpAuthContext) {
      throw new Error('[SigningEngine][ecdsa] restored passkey Ed25519 material is required');
    }
    if (String(restoredEd25519.nearAccountId) !== String(walletId)) {
      throw new Error('[SigningEngine][ecdsa] restored Ed25519 wallet identity mismatch');
    }
    if (String(args.key.walletId) !== String(walletId)) {
      throw new Error('[SigningEngine][ecdsa] ECDSA key wallet identity mismatch');
    }
    if (
      thresholdEcdsaChainTargetKey(args.lanePolicy.chainTarget) !==
      thresholdEcdsaChainTargetKey(args.chainTarget)
    ) {
      throw new Error('[SigningEngine][ecdsa] ECDSA lane policy target mismatch');
    }
    if (args.lanePolicy.thresholdSessionKind !== restoredEd25519.thresholdSessionKind) {
      throw new Error('[SigningEngine][ecdsa] restored Ed25519 session kind mismatch');
    }
    if (
      Number(args.lanePolicy.ttlMs) !== Number(args.ttlMs) ||
      Number(args.lanePolicy.remainingUses) !== Number(args.remainingUses)
    ) {
      throw new Error('[SigningEngine][ecdsa] ECDSA lane policy session budget mismatch');
    }

    let routeAuth: ThresholdEcdsaHssRouteAuth;
    if (restoredEd25519.thresholdSessionKind === 'cookie') {
      routeAuth = { kind: 'cookie' };
    } else {
      const jwt = String(restoredEd25519.thresholdSessionAuthToken || '').trim();
      if (!jwt) {
        throw new Error('[SigningEngine][ecdsa] restored Ed25519 JWT auth token is required');
      }
      routeAuth = { kind: 'threshold_session', jwt };
    }

    const clientRootShare32B64u = await claimWarmSessionPrfFirst({
      touchConfirm: this.touchConfirm,
      thresholdSessionId: restoredEd25519.thresholdSessionId,
      errorContext: 'restored Ed25519 login session ECDSA bootstrap',
      uses: 1,
      consume: false,
      curve: 'ed25519',
      chain: 'near',
    });

    return await passkeyPublic.bootstrapEcdsaSession(this.passkeyPublicDeps, {
      kind: 'threshold_session_auth_reconnect_ecdsa_bootstrap',
      source: 'login',
      relayerUrl: args.relayerUrl,
      keyHandle: args.keyHandle,
      key: args.key,
      lanePolicy: args.lanePolicy,
      clientRootShare32B64u,
      routeAuth,
      ...(args.runtimeScopeBootstrap ? { runtimeScopeBootstrap: args.runtimeScopeBootstrap } : {}),
    });
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

  /**
   * Internal Email OTP enrollment bridge.
   * Kept off `SigningEnginePublic` until the Email OTP abstraction is stable.
   */
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

  upsertThresholdEcdsaSessionFromBootstrap(
    args: UpsertThresholdEcdsaSessionFromBootstrapInput,
  ): void {
    sessionPublic.upsertThresholdEcdsaSessionFromBootstrap(this.sessionPublicDeps, args);
  }

  getThresholdEcdsaKeyRefForWalletTarget(
    args: GetThresholdEcdsaKeyRefForWalletTargetInput,
  ): ThresholdEcdsaSecp256k1KeyRef {
    return sessionPublic.getThresholdEcdsaKeyRefForWalletTarget(this.sessionPublicDeps, args);
  }

  listThresholdEcdsaSessionRecordsForWalletTarget(
    args: ListThresholdEcdsaSessionRecordsForWalletTargetInput,
  ): SessionPublicThresholdEcdsaSessionRecord[] {
    return sessionPublic.listThresholdEcdsaSessionRecordsForWalletTarget(
      this.sessionPublicDeps,
      args,
    );
  }

  clearThresholdEcdsaSessionRecordForWallet(walletId: WalletId): void {
    sessionPublic.clearThresholdEcdsaSessionRecordForWallet(this.sessionPublicDeps, walletId);
  }

  clearAllThresholdEcdsaSessionRecords(): void {
    sessionPublic.clearAllThresholdEcdsaSessionRecords(this.sessionPublicDeps);
  }

  persistThresholdEcdsaBootstrapForWalletTarget(args: {
    walletId: WalletId;
    chainTarget: ThresholdEcdsaChainTarget;
    bootstrap: ThresholdEcdsaSessionBootstrapResult;
    signerAuth: ThresholdEcdsaBootstrapSignerAuth;
  }): Promise<void> {
    return warmCapabilitiesPublic.persistThresholdEcdsaBootstrapForWalletTarget(
      this.warmCapabilitiesPublicDeps,
      args,
    );
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

  async hydrateSigningSession(args: {
    sessionId: string;
    prfFirstB64u: string;
    expiresAtMs: number;
    remainingUses: number;
    transport?: WarmSessionSealTransportInput;
  }): Promise<void> {
    await warmCapabilitiesPublic.hydrateSigningSession(this.warmCapabilitiesPublicDeps, args);
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

  deriveThresholdEd25519ClientVerifyingShareFromCredential(
    args: Parameters<
      typeof thresholdEd25519Public.deriveThresholdEd25519ClientVerifyingShareFromCredential
    >[1],
  ): ReturnType<
    typeof thresholdEd25519Public.deriveThresholdEd25519ClientVerifyingShareFromCredential
  > {
    return thresholdEd25519Public.deriveThresholdEd25519ClientVerifyingShareFromCredential(
      this.thresholdEd25519PublicDeps,
      args,
    );
  }

  deriveThresholdEd25519HssClientInputsFromCredential(
    args: Parameters<
      typeof thresholdEd25519Public.deriveThresholdEd25519HssClientInputsFromCredential
    >[1],
  ): ReturnType<typeof thresholdEd25519Public.deriveThresholdEd25519HssClientInputsFromCredential> {
    return thresholdEd25519Public.deriveThresholdEd25519HssClientInputsFromCredential(
      this.thresholdEd25519PublicDeps,
      args,
    );
  }

  deriveThresholdEd25519HssClientInputsFromPrfFirst(
    args: Parameters<
      typeof thresholdEd25519Public.deriveThresholdEd25519HssClientInputsFromPrfFirst
    >[1],
  ): ReturnType<typeof thresholdEd25519Public.deriveThresholdEd25519HssClientInputsFromPrfFirst> {
    return thresholdEd25519Public.deriveThresholdEd25519HssClientInputsFromPrfFirst(
      this.thresholdEd25519PublicDeps,
      args,
    );
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

  completeThresholdEd25519HssClientCeremony(
    args: Parameters<typeof thresholdEd25519Public.completeThresholdEd25519HssClientCeremony>[1],
  ): ReturnType<typeof thresholdEd25519Public.completeThresholdEd25519HssClientCeremony> {
    return thresholdEd25519Public.completeThresholdEd25519HssClientCeremony(
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

  openThresholdEd25519HssSeedOutput(
    args: Parameters<typeof thresholdEd25519Public.openThresholdEd25519HssSeedOutput>[1],
  ): ReturnType<typeof thresholdEd25519Public.openThresholdEd25519HssSeedOutput> {
    return thresholdEd25519Public.openThresholdEd25519HssSeedOutput(
      this.thresholdEd25519PublicDeps,
      args,
    );
  }

  buildThresholdEd25519SeedExportArtifactFromHssReport(
    args: Parameters<
      typeof thresholdEd25519Public.buildThresholdEd25519SeedExportArtifactFromHssReport
    >[1],
  ): ReturnType<
    typeof thresholdEd25519Public.buildThresholdEd25519SeedExportArtifactFromHssReport
  > {
    return thresholdEd25519Public.buildThresholdEd25519SeedExportArtifactFromHssReport(
      this.thresholdEd25519PublicDeps,
      args,
    );
  }

  destroy(): void {
    this.userPreferencesManager.destroy();
    this.nonceCoordinator.clearAll();
    clearThresholdEcdsaCommitQueue(this.thresholdEcdsaCommitQueueByKey);
    clearThresholdEd25519CommitQueue(this.thresholdEd25519CommitQueueByKey);
    sessionPublic.clearAllThresholdEcdsaSessionRecords(this.sessionPublicDeps);
  }
}

/**
 * Boundary-facing API spec for SigningEngine consumers.
 * Keep the tuple narrow and intentional; the exported type derives from it.
 */
const signingEnginePublicMembers = [
  'seamsPasskeyConfigs',
  'setTheme',
  'getUserPreferences',
  'getRpId',
  'getNonceCoordinator',
  'warmCriticalResources',
  'assertSealedRefreshStartupParity',
  'restorePersistedSessionsForWallet',
  'prepareEmailOtpRegistrationEnrollmentMaterialInternal',
  'readPersistedAvailableSigningLanes',
  'signNear',
  'signTempo',
  'reportTempoBroadcastAccepted',
  'reportTempoBroadcastRejected',
  'reportTempoFinalized',
  'reportTempoDroppedOrReplaced',
  'reconcileTempoNonceLane',
  'storeUserData',
  'getAllUsers',
  'getUserBySignerSlot',
  'getLastUser',
  'getAuthenticatorsByUser',
  'nearAuthenticatorsByAccount',
  'updateLastLogin',
  'setLastUser',
  'initializeCurrentUser',
  'storeAuthenticator',
  'rollbackUserRegistration',
  'hasPasskeyCredential',
  'atomicStoreRegistrationData',
  'storeWalletEd25519RegistrationData',
  'storeWalletEmailOtpEd25519RegistrationData',
  'storeWalletEd25519SignerRecord',
  'storeWalletEcdsaSignerRecords',
  'storeWalletEmailOtpEcdsaSignerRecords',
  'storeWalletEcdsaRegistrationData',
  'storeWalletEmailOtpEcdsaRegistrationData',
  'requestRegistrationCredentialConfirmation',
  'getAuthenticationCredentialsSerialized',
  'prepareWalletRegistrationEcdsaPreparedClientBootstrap',
  'prepareWalletRegistrationEcdsaClientBootstrap',
  'persistWalletRegistrationEcdsaBootstrapForWalletKeys',
  'extractCosePublicKey',
  'exportKeypairWithUI',
  'exportNearEd25519SeedArtifactWithUI',
  'exportThresholdEd25519SeedFromHssReport',
  'signTransactionWithKeyPair',
  'generateEphemeralNearKeypair',
  'connectEd25519Session',
  'bootstrapEcdsaSession',
  'bootstrapLoginEcdsaSessionFromRestoredEd25519',
  'upsertThresholdEcdsaSessionFromBootstrap',
  'getThresholdEcdsaKeyRefForWalletTarget',
  'listThresholdEcdsaSessionRecordsForWalletTarget',
  'clearThresholdEcdsaSessionRecordForWallet',
  'clearAllThresholdEcdsaSessionRecords',
  'persistThresholdEcdsaBootstrapForWalletTarget',
  'getWarmThresholdEd25519SessionStatus',
  'getWarmThresholdEcdsaSessionStatus',
  'listWarmThresholdEcdsaSessionStatuses',
  'scheduleThresholdEcdsaLoginPresignPrefill',
  'hydrateSigningSession',
  'clearVolatileWarmSigningMaterial',
  'clearThresholdEcdsaCommitQueue',
  'deriveThresholdEd25519ClientVerifyingShareFromCredential',
  'deriveThresholdEd25519HssClientInputsFromCredential',
  'deriveThresholdEd25519HssClientInputsFromPrfFirst',
  'prepareThresholdEd25519HssClientCeremonyFromCredential',
  'prepareThresholdEd25519HssClientCeremonyFromPrfFirst',
  'prepareThresholdEd25519HssClientRequest',
  'deriveThresholdEd25519HssClientOutputMask',
  'buildThresholdEd25519HssClientOwnedStagedEvaluatorArtifact',
  'completeThresholdEd25519HssClientCeremony',
  'runThresholdEd25519HssCeremonyWithSession',
  'openThresholdEd25519HssSeedOutput',
  'buildThresholdEd25519SeedExportArtifactFromHssReport',
] as const satisfies readonly (keyof SigningEngine)[];

export type SigningEnginePublic = Pick<
  SigningEngine,
  (typeof signingEnginePublicMembers)[number]
>;
