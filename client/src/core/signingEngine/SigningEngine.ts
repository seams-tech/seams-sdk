import { IndexedDBManager } from '@/core/indexedDB';
import type { ClientAuthenticatorData, ClientUserData, StoreUserDataInput } from '../accountData/near/types';
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
import {
  type WalletEmailOtpChannel,
  type WalletEmailOtpLoginOperation,
} from '@shared/utils/emailOtpDomain';
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
import {
  readTrustedWalletSigningBudgetStatus as readTrustedWalletSigningBudgetStatusValue,
} from './session/signingSession/budgetStatusReader';
import type { TouchIdPrompt } from './stepUpConfirmation/passkeyPrompt/touchIdPrompt';
import type { WebAuthnAllowCredential } from './walletAuth/webauthn/credentials/collectAuthenticationCredentialForChallengeB64u';
import type { EvmSigningRequest } from './chains/evm/types';
import type { EvmSignedResult } from './chains/evm/evmAdapter';
import type { TempoSigningRequest } from './chains/tempo/types';
import type { TempoSignedResult } from './chains/tempo/tempoAdapter';
import type { BootstrapEcdsaSessionArgs } from './session/warmSigning/ecdsaBootstrap';
import {
  buildThresholdEd25519SeedExportArtifactFromHssReport as buildThresholdEd25519SeedExportArtifactFromHssReportPublicValue,
  completeThresholdEd25519HssClientCeremony as completeThresholdEd25519HssClientCeremonyPublicValue,
  deriveThresholdEd25519ClientVerifyingShareFromCredential as deriveThresholdEd25519ClientVerifyingShareFromCredentialPublicValue,
  deriveThresholdEd25519HssClientInputsFromCredential as deriveThresholdEd25519HssClientInputsFromCredentialPublicValue,
  openThresholdEd25519HssSeedOutput as openThresholdEd25519HssSeedOutputPublicValue,
  prepareThresholdEd25519HssClientCeremonyFromCredential as prepareThresholdEd25519HssClientCeremonyFromCredentialPublicValue,
  prepareThresholdEd25519HssClientRequest as prepareThresholdEd25519HssClientRequestPublicValue,
  runThresholdEd25519HssCeremonyWithSession as runThresholdEd25519HssCeremonyWithSessionPublicValue,
} from './threshold/ed25519/public';
import {
  persistThresholdEcdsaBootstrapChainAccount as persistThresholdEcdsaBootstrapChainAccountValue,
  type ThresholdEcdsaSmartAccountBootstrapInput,
} from './session/warmSigning/ecdsaBootstrapPersistence';
import {
  clearThresholdEcdsaSessionRecordForLane as clearThresholdEcdsaSessionRecordForLaneValue,
  getEmailOtpThresholdEcdsaKeyRefForSigning as getEmailOtpThresholdEcdsaKeyRefForSigningValue,
  getEmailOtpThresholdEcdsaSessionRecordForSigning as getEmailOtpThresholdEcdsaSessionRecordForSigningValue,
  getPasskeyThresholdEcdsaKeyRefForSigning as getPasskeyThresholdEcdsaKeyRefForSigningValue,
  getPasskeyThresholdEcdsaSessionRecordForSigning as getPasskeyThresholdEcdsaSessionRecordForSigningValue,
  getThresholdEcdsaKeyRefByKey as getThresholdEcdsaKeyRefByIdentityValue,
  getThresholdEcdsaSessionRecordByKey as getThresholdEcdsaSessionRecordByIdentityValue,
  getThresholdEcdsaSessionRecordForTarget as getThresholdEcdsaSessionRecordForTargetValue,
  listThresholdEcdsaRuntimeLanesForSubject as listThresholdEcdsaRuntimeLanesForSubjectValue,
  listThresholdEcdsaKeyRefsForTarget as listThresholdEcdsaKeyRefsForTargetValue,
  listThresholdEcdsaSessionRecordsForTarget as listThresholdEcdsaSessionRecordsForTargetValue,
  markThresholdEd25519EmailOtpSessionConsumedForAccount as markThresholdEd25519EmailOtpSessionConsumedForAccountValue,
  markThresholdEcdsaEmailOtpSessionConsumedForAccount as markThresholdEcdsaEmailOtpSessionConsumedForAccountValue,
  upsertThresholdEcdsaSessionFromBootstrap as upsertThresholdEcdsaSessionFromBootstrapValue,
  type ThresholdEd25519SessionRecord,
  type ThresholdEcdsaSessionRecord,
} from './session/persistence/records';
import type {
  ThresholdEcdsaSessionStoreSource,
} from './session/identity/laneIdentity';
import {
  configuredThresholdEcdsaChainTargets,
  toWalletSubjectId,
  type ThresholdEcdsaChainTarget,
  type WalletSubjectId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  type ThresholdEcdsaLoginPrefillResult,
} from './session/warmSigning/ecdsaLoginPrefill';
import type { ThresholdRuntimePolicyScope } from './threshold/sessionPolicy';
import {
  signNear as signNearValue,
  type NearSignIntentRequest,
  type NearSignIntentResult,
  type SignTransactionsWithActionsInput,
} from './flows/signNear/signNear';
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
import {
  exportKeypairWithUI as exportKeypairWithUIPublicValue,
  exportNearEd25519SeedArtifactWithUI as exportNearEd25519SeedArtifactWithUIPublicValue,
  exportThresholdEd25519SeedFromHssReport as exportThresholdEd25519SeedFromHssReportPublicValue,
  type RecoveryPublicDeps,
  type SigningEngineExportKeypairWithUIInput,
  type KeyExportEventCallback,
} from './flows/recovery/public';
import type { RegistrationCredentialConfirmationPayload } from './workerManager/validation';
import type { ConfirmationConfig } from '../types/signer-worker';
import {
  atomicStoreRegistrationData as atomicStoreRegistrationDataPublicValue,
  extractCosePublicKey as extractRegistrationCosePublicKeyValue,
  getAllUsers as getAllUsersPublicValue,
  getAuthenticatorsByUser as getAuthenticatorsByUserPublicValue,
  getAuthenticationCredentialsSerialized as getAuthenticationCredentialsSerializedPublicValue,
  getLastUser as getLastUserPublicValue,
  getUserBySignerSlot as getUserBySignerSlotPublicValue,
  hasPasskeyCredential as hasPasskeyCredentialPublicValue,
  initializeCurrentUser as initializeCurrentUserPublicValue,
  requestRegistrationCredentialConfirmation as requestRegistrationCredentialConfirmationPublicValue,
  rollbackUserRegistration as rollbackUserRegistrationPublicValue,
  setLastUser as setLastUserPublicValue,
  storeAuthenticator as storeAuthenticatorPublicValue,
  storeUserData as storeUserDataPublicValue,
  updateLastLogin as updateLastLoginPublicValue,
  type RegistrationPublicDeps,
  type StoreAuthenticatorInput,
} from './flows/registration/public';
import {
  enrollAndLoginWithEmailOtpEcdsaCapabilityInternal as enrollAndLoginWithEmailOtpEcdsaCapabilityInternalPublicValue,
  enrollEmailOtpInternal as enrollEmailOtpInternalPublicValue,
  loginWithEmailOtpEcdsaCapabilityInternal as loginWithEmailOtpEcdsaCapabilityInternalPublicValue,
  refreshEmailOtpSigningSession as refreshEmailOtpSigningSessionPublicValue,
  requestEmailOtpSigningSessionChallenge as requestEmailOtpSigningSessionChallengePublicValue,
  type EmailOtpPublicDeps,
} from './flows/signEvmFamily/emailOtpPublic';
import { initializeSigningEngineRuntime } from './assembly/createSigningEngineRuntime';
import { createManagerAssembly } from './assembly/createManagers';
import { verifySealedRefreshStartupParity } from '../rpcClients/relayer/sealedRefreshCapabilities';
import { bootstrapWarmEcdsaCapability } from './session/warmSigning/ecdsaWarmCapabilityBootstrap';
import type { WarmSessionEcdsaCapabilityState } from './session/warmSigning/types';
import type {
  ProvisionWarmEd25519CapabilityArgs,
  ProvisionWarmEd25519CapabilityResult,
  WarmEcdsaSigningSessionStatus,
} from './session/warmSigning/types';
import { createSigningEnginePorts } from './assembly/createPorts';
import { provisionThresholdEd25519Session as provisionThresholdEd25519SessionValue } from './session/warmSigning/ed25519SessionProvision';
import type { EmailOtpThresholdSessionCoordinator } from './sessionEmailOtp/EmailOtpThresholdSessionCoordinator';
import type { EmailOtpBootstrapRecovery } from './stepUpConfirmation/otpPrompt/bootstrapRecovery';
import type {
  RestorePersistedSessionsForAccountInput,
  RestorePersistedSessionsForAccountResult,
  ReadAvailableSigningLanesInput,
  AvailableSigningLanes,
  SessionPublicDeps,
  ThresholdEcdsaSessionRecord as SessionPublicThresholdEcdsaSessionRecord,
  UpsertThresholdEcdsaSessionFromBootstrapInput,
  GetThresholdEcdsaKeyRefForAccountTargetInput,
} from './session/public';
import {
  readPersistedAvailableSigningLanes as readPersistedAvailableSigningLanesValue,
  readPersistedAvailableSigningLanesForSigning as readPersistedAvailableSigningLanesForSigningValue,
  readPersistedAvailableSigningLanesForTargets as readPersistedAvailableSigningLanesForTargetsValue,
} from './session/availability/persistedAvailableSigningLanes';
import {
  createWarmSigningPorts,
  createWarmSigningPublicDeps,
  type WarmSigningPorts,
} from './assembly/ports/warmSigning';
import { createStepUpRuntime } from './assembly/ports/stepUpRuntime';
import { createRecoveryPublicDeps } from './assembly/ports/recovery';
import { createSessionPublicDeps } from './assembly/ports/session';
import { createEmailOtpPublicDeps } from './assembly/ports/emailOtp';
import {
  clearAllThresholdEcdsaSessionRecords as clearAllThresholdEcdsaSessionRecordsPublicValue,
  clearThresholdEcdsaSessionRecordForAccount as clearThresholdEcdsaSessionRecordForAccountPublicValue,
  getThresholdEcdsaKeyRefForAccountTarget as getThresholdEcdsaKeyRefForAccountTargetPublicValue,
  listThresholdEcdsaSessionRecordsForSubject as listThresholdEcdsaSessionRecordsForSubjectPublicValue,
  readPersistedAvailableSigningLanes as readPersistedAvailableSigningLanesPublicValue,
  restorePersistedSessionsForAccount as restorePersistedSessionsForAccountPublicValue,
  upsertThresholdEcdsaSessionFromBootstrap as upsertThresholdEcdsaSessionFromBootstrapPublicValue,
} from './session/public';
import type {
  WarmSigningPublicDeps,
} from './session/warmSigning/public';
import {
  bootstrapEcdsaSession as bootstrapEcdsaSessionPublicValue,
  clearWarmSigningSessions as clearWarmSigningSessionsPublicValue,
  connectEd25519Session as connectEd25519SessionPublicValue,
  getWarmThresholdEcdsaSessionStatus as getWarmThresholdEcdsaSessionStatusPublicValue,
  getWarmThresholdEd25519SessionStatus as getWarmThresholdEd25519SessionStatusPublicValue,
  hydrateSigningSession as hydrateSigningSessionPublicValue,
  listWarmThresholdEcdsaSessionStatuses as listWarmThresholdEcdsaSessionStatusesPublicValue,
  persistThresholdEcdsaBootstrapChainAccount as persistThresholdEcdsaBootstrapChainAccountPublicValue,
  scheduleThresholdEcdsaLoginPresignPrefill as scheduleThresholdEcdsaLoginPresignPrefillPublicValue,
} from './session/warmSigning/public';

export type { ThresholdEcdsaSessionBootstrapResult } from './threshold/ecdsa/activation';
export type { EmailOtpBootstrapRecovery } from './stepUpConfirmation/otpPrompt/bootstrapRecovery';
export type { NearSignIntentRequest, NearSignIntentResult } from './flows/signNear/signNear';
export type { ThresholdEcdsaLoginPrefillResult } from './session/warmSigning/ecdsaLoginPrefill';

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
  private readonly thresholdEcdsaBootstrapQueueByAccount: Map<string, Promise<void>> = new Map();
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
  private readonly warmSigningPublic: WarmSigningPublicDeps;
  private readonly sessionPublic: SessionPublicDeps;
  private readonly emailOtpPublic: EmailOtpPublicDeps;
  private readonly recoveryPublic: RecoveryPublicDeps;
  private readonly sealedRefreshStartupParityPromise: Promise<void>;
  private sealedRefreshStartupParityError: Error | null = null;
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
      seamsPasskeyConfigs: this.seamsPasskeyConfigs,
      nearClient: this.nearClient,
      getTheme: () => this.theme,
      getAppearanceTokens: () => this.seamsPasskeyConfigs.ui.appearance?.tokens,
    });

    this.touchIdPrompt = assembly.touchIdPrompt;
    this.userPreferencesManager = assembly.userPreferencesManager;
    this.nonceCoordinator = assembly.nonceCoordinator;
    this.signerWorkerManager = assembly.signerWorkerManager;
    const stepUpRuntime = createStepUpRuntime({
      seamsPasskeyConfigs: this.seamsPasskeyConfigs,
      touchIdPrompt: this.touchIdPrompt,
      signerWorkerManager: this.signerWorkerManager,
      indexedDB: IndexedDBManager,
      baseTouchConfirm: assembly.touchConfirm,
      getSignerWorkerContext: () =>
        this.enginePorts.thresholdSessionActivationDeps.getSignerWorkerContext(),
      thresholdEcdsaBootstrapQueueByAccount: this.thresholdEcdsaBootstrapQueueByAccount,
      getEcdsaSessions: () => this.warmSigning.ecdsaSessions,
      getWarmCapabilityReader: () => this.warmSigning.capabilityReader,
      listThresholdEcdsaSessionRecordsForSubject: (args) =>
        this.warmSigning.listThresholdEcdsaSessionRecordsForSubject(args),
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
    this.sessionPublic = createSessionPublicDeps({
      seamsPasskeyConfigs: this.seamsPasskeyConfigs,
      ecdsaSessions: this.warmSigning.ecdsaSessions,
      touchConfirm: this.touchConfirm,
      emailOtpSessions: this.emailOtpSessions,
    });
    this.emailOtpPublic = createEmailOtpPublicDeps({
      ecdsaSessions: this.warmSigning.ecdsaSessions,
      relayerUrl: this.seamsPasskeyConfigs.network.relayer?.url || '',
      shamirPrimeB64u: this.seamsPasskeyConfigs.signing.sessionSeal?.shamirPrimeB64u || '',
      getSignerWorkerContext: () =>
        this.enginePorts.thresholdSessionActivationDeps.getSignerWorkerContext(),
      emailOtpSessions: this.emailOtpSessions,
    });
    this.recoveryPublic = createRecoveryPublicDeps({
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
      warmSessionPolicy: {
        getWarmSession: (nearAccountId) =>
          this.warmSigning.capabilityReader.getWarmSession(nearAccountId),
        resolveCurrentEcdsaRecord: (recordArgs) =>
          this.warmSigning.statusReader.resolveCurrentEcdsaRecord(recordArgs),
      },
    });

    this.enginePorts = createSigningEnginePorts({
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
        readTrustedWalletSigningBudgetStatusValue(
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
        initializeCurrentUserPublicValue(this.registrationPublicDeps(), {
          nearAccountId,
          nearClient: nearClientArg,
        }),
      persistThresholdEcdsaBootstrapChainAccount: (args) =>
        persistThresholdEcdsaBootstrapChainAccountValue({
          indexedDB: this.enginePorts.indexedDB,
          nearAccountId: toAccountId(args.nearAccountId),
          chainTarget: args.chainTarget,
          bootstrap: args.bootstrap,
          smartAccount: args.smartAccount,
          deployment: args.deployment,
        }),
      upsertThresholdEcdsaSessionFromBootstrap: (args) =>
        upsertThresholdEcdsaSessionFromBootstrapValue(this.warmSigning.ecdsaSessions, args),
      listThresholdEcdsaKeyRefsForTarget: (args) =>
        listThresholdEcdsaKeyRefsForTargetValue(this.warmSigning.ecdsaSessions, args),
      listThresholdEcdsaSessionRecordsForTarget: (args) =>
        listThresholdEcdsaSessionRecordsForTargetValue(this.warmSigning.ecdsaSessions, args),
      listThresholdEcdsaSessionRecordsForSubject: (args) =>
        this.warmSigning.listThresholdEcdsaSessionRecordsForSubject(args),
      getThresholdEcdsaSessionRecordByKey: (identity) =>
        getThresholdEcdsaSessionRecordByIdentityValue(this.warmSigning.ecdsaSessions, identity),
      getThresholdEcdsaKeyRefByKey: (identity) =>
        getThresholdEcdsaKeyRefByIdentityValue(this.warmSigning.ecdsaSessions, identity),
      getEmailOtpThresholdEcdsaKeyRefForSigning: (args) =>
        getEmailOtpThresholdEcdsaKeyRefForSigningValue(this.warmSigning.ecdsaSessions, args),
      getEmailOtpThresholdEcdsaSessionRecordForSigning: (args) =>
        getThresholdEcdsaSessionRecordForTargetValue(this.warmSigning.ecdsaSessions, {
          subjectId: args.subjectId,
          chainTarget: args.chainTarget,
          source: 'email_otp',
        }),
      getPasskeyThresholdEcdsaKeyRefForSigning: (args) =>
        getPasskeyThresholdEcdsaKeyRefForSigningValue(this.warmSigning.ecdsaSessions, args),
      getPasskeyThresholdEcdsaSessionRecordForSigning: (args) =>
        getThresholdEcdsaSessionRecordForTargetValue(this.warmSigning.ecdsaSessions, {
          subjectId: args.subjectId,
          chainTarget: args.chainTarget,
          source: args.source,
        }),
      requestEmailOtpTransactionSigningChallenge: (args) =>
        this.emailOtpSessions.requestTransactionSigningChallenge(args),
      isEmailOtpEd25519WarmupPending: (args) => this.emailOtpSessions.isEd25519WarmupPending(args),
      waitForPendingEmailOtpEd25519Warmup: (args) =>
        this.emailOtpSessions.waitForPendingEd25519Warmup(args),
      loginWithEmailOtpEd25519CapabilityForSigning: (args) =>
        this.emailOtpSessions.loginWithEd25519CapabilityForSigning(args),
      provisionThresholdEd25519Session: (args) =>
        provisionThresholdEd25519SessionValue(
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
        readPersistedAvailableSigningLanesForSigningValue(
          {
            ecdsaSessions: this.warmSigning.ecdsaSessions,
            statusReader: this.warmSigning.statusUiConfirm,
          },
          args,
          configuredThresholdEcdsaChainTargets(this.seamsPasskeyConfigs.network.chains),
        ),
      markThresholdEcdsaEmailOtpSessionConsumedForAccount: (args) =>
        markThresholdEcdsaEmailOtpSessionConsumedForAccountValue(
          this.warmSigning.ecdsaSessions,
          {
            subjectId: toWalletSubjectId(args.nearAccountId),
            chainTarget: args.chainTarget,
            ...(typeof args.uses === 'number' ? { uses: args.uses } : {}),
          },
        ),
      markThresholdEd25519EmailOtpSessionConsumedForAccount: (args) =>
        markThresholdEd25519EmailOtpSessionConsumedForAccountValue(args),
      clearThresholdEcdsaSessionRecordForLane: (args) =>
        clearThresholdEcdsaSessionRecordForLaneValue(this.warmSigning.ecdsaSessions, args),
      provisionThresholdEcdsaSession: (args) =>
        bootstrapWarmEcdsaCapability(
          {
            ensureSealedRefreshStartupParity: () => this.ensureSealedRefreshStartupParity(),
            queueByAccount: this.thresholdEcdsaBootstrapQueueByAccount,
            activationDeps: this.enginePorts.thresholdSessionActivationDeps,
            touchConfirm: this.touchConfirm,
            ecdsaSessions: this.warmSigning.ecdsaSessions,
            capabilityReader: this.warmSigning.capabilityReader,
          },
          args,
        ),
      withThresholdEcdsaCommitQueue: (queueArgs) =>
        withThresholdEcdsaCommitQueue({
          queueByKey: this.thresholdEcdsaCommitQueueByKey,
          ...queueArgs,
        }),
      withThresholdEd25519CommitQueue: (queueArgs) =>
        withThresholdEd25519CommitQueue({
          queueByKey: this.thresholdEd25519CommitQueueByKey,
          ...queueArgs,
        }),
    });
    this.warmSigningPublic = createWarmSigningPublicDeps({
      seamsPasskeyConfigs: this.seamsPasskeyConfigs,
      indexedDB: this.enginePorts.indexedDB,
      touchIdPrompt: this.touchIdPrompt,
      touchConfirm: this.touchConfirm,
      warmSigning: this.warmSigning,
      thresholdEcdsaBootstrapQueueByAccount: this.thresholdEcdsaBootstrapQueueByAccount,
      ensureSealedRefreshStartupParity: () => this.ensureSealedRefreshStartupParity(),
      thresholdSessionActivationDeps: this.enginePorts.thresholdSessionActivationDeps,
      resolveCanonicalThresholdEcdsaSessionIdForChain:
        this.enginePorts.resolveCanonicalThresholdEcdsaSessionIdForChain,
      signingSessionCoordinator: this.enginePorts.signingSessionCoordinator,
    });

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

  async restorePersistedSessionsForAccount(
    args: RestorePersistedSessionsForAccountInput,
  ): Promise<RestorePersistedSessionsForAccountResult> {
    return await restorePersistedSessionsForAccountPublicValue(this.sessionPublic, args);
  }

  async readPersistedAvailableSigningLanes(
    args: Omit<ReadAvailableSigningLanesInput, 'ecdsaChainTargets'>,
  ): Promise<AvailableSigningLanes> {
    return await readPersistedAvailableSigningLanesPublicValue(this.sessionPublic, args);
  }

  private registrationPublicDeps(): RegistrationPublicDeps {
    return {
      accountLifecycle: this.enginePorts.registrationAccountLifecycleDeps,
      session: this.enginePorts.registrationSessionDeps,
      signingKeyOps: this.enginePorts.nearKeyOpsDeps.signingKeyOps,
    };
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
    return await signNearValue(this.enginePorts.nearSigningDeps, request);
  }

  async signTempo(args: {
    nearAccountId: string;
    subjectId: WalletSubjectId;
    request: TempoSigningRequest | EvmSigningRequest;
    chainTarget: ThresholdEcdsaChainTarget;
    confirmationConfigOverride?: Partial<ConfirmationConfig>;
    shouldAbort?: () => boolean;
    onEvent?: (event: SigningFlowEvent) => void;
  }): Promise<TempoSignedResult | EvmSignedResult> {
    return await signTempoValue(this.enginePorts.tempoSigningDeps, args);
  }

  async reportTempoBroadcastAccepted(args: ReportTempoBroadcastAcceptedArgs): Promise<void> {
    await reportTempoBroadcastAcceptedValue(this.enginePorts.tempoSigningDeps, args);
  }

  async reportTempoBroadcastRejected(args: ReportTempoBroadcastRejectedArgs): Promise<void> {
    await reportTempoBroadcastRejectedValue(this.enginePorts.tempoSigningDeps, args);
  }

  async reportTempoFinalized(args: ReportTempoFinalizedArgs): Promise<void> {
    await reportTempoFinalizedValue(this.enginePorts.tempoSigningDeps, args);
  }

  async reportTempoDroppedOrReplaced(args: ReportTempoDroppedOrReplacedArgs): Promise<void> {
    await reportTempoDroppedOrReplacedValue(this.enginePorts.tempoSigningDeps, args);
  }

  async reconcileTempoNonceLane(args: ReconcileTempoNonceLaneArgs): Promise<TempoNonceLaneStatus> {
    return await reconcileTempoNonceLaneValue(this.enginePorts.tempoSigningDeps, args);
  }

  storeUserData(userData: StoreUserDataInput): Promise<void> {
    return storeUserDataPublicValue(this.registrationPublicDeps(), userData);
  }

  getAllUsers(): Promise<ClientUserData[]> {
    return getAllUsersPublicValue(this.registrationPublicDeps());
  }

  getUserBySignerSlot(
    nearAccountId: AccountId,
    signerSlot: number,
  ): Promise<ClientUserData | null> {
    return getUserBySignerSlotPublicValue(this.registrationPublicDeps(), nearAccountId, signerSlot);
  }

  getLastUser(): Promise<ClientUserData | null> {
    return getLastUserPublicValue(this.registrationPublicDeps());
  }

  getAuthenticatorsByUser(nearAccountId: AccountId): Promise<ClientAuthenticatorData[]> {
    return getAuthenticatorsByUserPublicValue(this.registrationPublicDeps(), nearAccountId);
  }

  updateLastLogin(nearAccountId: AccountId): Promise<void> {
    return updateLastLoginPublicValue(this.registrationPublicDeps(), nearAccountId);
  }

  setLastUser(nearAccountId: AccountId, signerSlot: number = 1): Promise<void> {
    return setLastUserPublicValue(this.registrationPublicDeps(), nearAccountId, signerSlot);
  }

  initializeCurrentUser(nearAccountId: AccountId, nearClientArg?: NearClient): Promise<void> {
    return initializeCurrentUserPublicValue(this.registrationPublicDeps(), {
      nearAccountId,
      nearClient: nearClientArg,
    });
  }

  storeAuthenticator(authenticatorData: StoreAuthenticatorInput): Promise<void> {
    return storeAuthenticatorPublicValue(this.registrationPublicDeps(), authenticatorData);
  }

  rollbackUserRegistration(nearAccountId: AccountId): Promise<void> {
    return rollbackUserRegistrationPublicValue(this.registrationPublicDeps(), nearAccountId);
  }

  hasPasskeyCredential(nearAccountId: AccountId): Promise<boolean> {
    return hasPasskeyCredentialPublicValue(this.registrationPublicDeps(), nearAccountId);
  }

  atomicStoreRegistrationData(args: {
    nearAccountId: AccountId;
    credential: WebAuthnRegistrationCredential;
    operationalPublicKey: string;
  }): Promise<void> {
    return atomicStoreRegistrationDataPublicValue(this.registrationPublicDeps(), args);
  }

  requestRegistrationCredentialConfirmation(params: {
    nearAccountId: string;
    signerSlot: number;
    confirmerText?: { title?: string; body?: string };
    confirmationConfigOverride?: Partial<ConfirmationConfig>;
  }): Promise<RegistrationCredentialConfirmationPayload> {
    return requestRegistrationCredentialConfirmationPublicValue(
      this.registrationPublicDeps(),
      params,
    );
  }

  getAuthenticationCredentialsSerialized(args: {
    nearAccountId: AccountId;
    challengeB64u: string;
    allowCredentials: WebAuthnAllowCredential[];
    includeSecondPrfOutput?: boolean;
  }): Promise<WebAuthnAuthenticationCredential> {
    return getAuthenticationCredentialsSerializedPublicValue(this.registrationPublicDeps(), args);
  }

  extractCosePublicKey(attestationObjectBase64url: string): Promise<Uint8Array> {
    return extractRegistrationCosePublicKeyValue(
      this.registrationPublicDeps(),
      attestationObjectBase64url,
    );
  }

  async exportKeypairWithUI(
    input: SigningEngineExportKeypairWithUIInput,
  ): Promise<{ accountId: string; exportedSchemes: Array<'ed25519' | 'secp256k1'> }> {
    return await exportKeypairWithUIPublicValue(this.recoveryPublic, input);
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
    return exportNearEd25519SeedArtifactWithUIPublicValue(this.recoveryPublic, args);
  }

  async exportThresholdEd25519SeedFromHssReport(args: {
    nearAccountId: AccountId;
    preparedSession: Parameters<
      typeof buildThresholdEd25519SeedExportArtifactFromHssReportPublicValue
    >[1]['preparedSession'];
    finalizedReport: Parameters<
      typeof buildThresholdEd25519SeedExportArtifactFromHssReportPublicValue
    >[1]['finalizedReport'];
    expectedPublicKey: string;
    options: {
      variant?: 'drawer' | 'modal';
      theme?: 'dark' | 'light';
      onEvent?: KeyExportEventCallback;
    };
  }): Promise<{ accountId: string; exportedSchemes: Array<'ed25519' | 'secp256k1'> }> {
    return await exportThresholdEd25519SeedFromHssReportPublicValue(this.recoveryPublic, args);
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
    args: Omit<ProvisionWarmEd25519CapabilityArgs, 'beforeProvision' | 'assertNotCancelled'>,
  ): Promise<ProvisionWarmEd25519CapabilityResult> {
    return await connectEd25519SessionPublicValue(this.warmSigningPublic, args);
  }

  async bootstrapEcdsaSession(
    args: BootstrapEcdsaSessionArgs,
  ): Promise<ThresholdEcdsaSessionBootstrapResult> {
    return await bootstrapEcdsaSessionPublicValue(this.warmSigningPublic, args);
  }

  async loginWithEmailOtpEcdsaCapabilityInternal(args: {
    nearAccountId: AccountId | string;
    subjectId: WalletSubjectId;
    chainTarget: ThresholdEcdsaChainTarget;
    emailOtpAuthPolicy?: EmailOtpAuthPolicy;
    emailOtpAuthReason?: 'login' | 'sign';
    relayUrl?: string;
    challengeId?: string;
    otpCode: string;
    operation?: WalletEmailOtpLoginOperation;
    shamirPrimeB64u?: string;
    appSessionJwt?: string;
    routeAuth?: AppOrThresholdSessionAuth;
    ecdsaThresholdKeyId?: string;
    participantIds?: number[];
    sessionKind?: 'jwt' | 'cookie';
    sessionId?: string;
    walletSigningSessionId?: string;
    ttlMs?: number;
    remainingUses?: number;
    runtimePolicyScope?: ThresholdRuntimePolicyScope;
    smartAccount?: ThresholdEcdsaSmartAccountBootstrapInput;
    onProgress?: (progress: EmailOtpWorkerProgressEvent) => void;
  }): Promise<{
    recovery: EmailOtpBootstrapRecovery;
    bootstrap: ThresholdEcdsaSessionBootstrapResult;
    warmCapability: WarmSessionEcdsaCapabilityState;
  }> {
    return await loginWithEmailOtpEcdsaCapabilityInternalPublicValue(this.emailOtpPublic, args);
  }

  async requestEmailOtpSigningSessionChallenge(args: {
    nearAccountId: AccountId | string;
    subjectId: WalletSubjectId;
    chainTarget: ThresholdEcdsaChainTarget;
  }): Promise<{ challengeId: string; emailHint?: string }> {
    return await requestEmailOtpSigningSessionChallengePublicValue(this.emailOtpPublic, args);
  }

  async refreshEmailOtpSigningSession(args: {
    nearAccountId: AccountId | string;
    subjectId: WalletSubjectId;
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
    return await refreshEmailOtpSigningSessionPublicValue(this.emailOtpPublic, args);
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
    otpChannel?: WalletEmailOtpChannel;
  }): Promise<Awaited<ReturnType<typeof enrollEmailOtpInternalPublicValue>>> {
    return await enrollEmailOtpInternalPublicValue(this.emailOtpPublic, args);
  }

  async enrollAndLoginWithEmailOtpEcdsaCapabilityInternal(args: {
    nearAccountId: AccountId | string;
    subjectId: WalletSubjectId;
    chainTarget: ThresholdEcdsaChainTarget;
    emailOtpAuthPolicy?: EmailOtpAuthPolicy;
    otpCode: string;
    relayUrl?: string;
    challengeId?: string;
    shamirPrimeB64u?: string;
    appSessionJwt?: string;
    routeAuth?: AppOrThresholdSessionAuth;
    ecdsaThresholdKeyId?: string;
    participantIds?: number[];
    sessionKind?: 'jwt' | 'cookie';
    sessionId?: string;
    ttlMs?: number;
    remainingUses?: number;
    clientSecret32?: Uint8Array;
    otpChannel?: WalletEmailOtpChannel;
    runtimePolicyScope?: ThresholdRuntimePolicyScope;
    smartAccount?: ThresholdEcdsaSmartAccountBootstrapInput;
    registrationAttemptId?: string;
    onProgress?: (progress: EmailOtpWorkerProgressEvent) => void;
  }): Promise<{
    enrollment: Awaited<ReturnType<typeof enrollEmailOtpInternalPublicValue>>;
    bootstrap: ThresholdEcdsaSessionBootstrapResult;
    warmCapability: WarmSessionEcdsaCapabilityState;
  }> {
    return await enrollAndLoginWithEmailOtpEcdsaCapabilityInternalPublicValue(
      this.emailOtpPublic,
      args,
    );
  }

  upsertThresholdEcdsaSessionFromBootstrap(
    args: UpsertThresholdEcdsaSessionFromBootstrapInput,
  ): void {
    upsertThresholdEcdsaSessionFromBootstrapPublicValue(this.sessionPublic, args);
  }

  getThresholdEcdsaKeyRefForAccountTarget(
    args: GetThresholdEcdsaKeyRefForAccountTargetInput,
  ): ThresholdEcdsaSecp256k1KeyRef {
    return getThresholdEcdsaKeyRefForAccountTargetPublicValue(this.sessionPublic, args);
  }

  listThresholdEcdsaSessionRecordsForSubject(args: {
    subjectId: WalletSubjectId;
  }): SessionPublicThresholdEcdsaSessionRecord[] {
    return listThresholdEcdsaSessionRecordsForSubjectPublicValue(this.sessionPublic, args);
  }

  clearThresholdEcdsaSessionRecordForAccount(nearAccountId: AccountId | string): void {
    clearThresholdEcdsaSessionRecordForAccountPublicValue(this.sessionPublic, nearAccountId);
  }

  clearAllThresholdEcdsaSessionRecords(): void {
    clearAllThresholdEcdsaSessionRecordsPublicValue(this.sessionPublic);
  }

  persistThresholdEcdsaBootstrapChainAccount(args: {
    nearAccountId: AccountId | string;
    chainTarget: ThresholdEcdsaChainTarget;
    bootstrap: ThresholdEcdsaSessionBootstrapResult;
    smartAccount?: ThresholdEcdsaSmartAccountBootstrapInput;
    deployment?: {
      deployed: boolean;
      deploymentTxHash?: string;
    };
    ensureEmailOtpNearAccountMapping?: boolean;
  }): Promise<void> {
    return persistThresholdEcdsaBootstrapChainAccountPublicValue(this.warmSigningPublic, args);
  }

  getWarmThresholdEd25519SessionStatus(
    nearAccountId: AccountId | string,
  ): Promise<SigningSessionStatus | null> {
    return getWarmThresholdEd25519SessionStatusPublicValue(this.warmSigningPublic, nearAccountId);
  }

  getWarmThresholdEcdsaSessionStatus(
    nearAccountId: AccountId | string,
    chainTarget: ThresholdEcdsaChainTarget,
    thresholdSessionId: string,
  ): Promise<WarmEcdsaSigningSessionStatus | null> {
    return getWarmThresholdEcdsaSessionStatusPublicValue(
      this.warmSigningPublic,
      nearAccountId,
      chainTarget,
      thresholdSessionId,
    );
  }

  listWarmThresholdEcdsaSessionStatuses(
    nearAccountId: AccountId | string,
    chainTarget: ThresholdEcdsaChainTarget,
  ): Promise<WarmEcdsaSigningSessionStatus[]> {
    return listWarmThresholdEcdsaSessionStatusesPublicValue(
      this.warmSigningPublic,
      nearAccountId,
      chainTarget,
    );
  }

  async scheduleThresholdEcdsaLoginPresignPrefill(args: {
    nearAccountId: AccountId | string;
    chainTarget: ThresholdEcdsaChainTarget;
    thresholdEcdsaKeyRef: ThresholdEcdsaSecp256k1KeyRef;
    minRemainingUsesBeforePrefill?: number;
  }): Promise<ThresholdEcdsaLoginPrefillResult> {
    return await scheduleThresholdEcdsaLoginPresignPrefillPublicValue(
      this.warmSigningPublic,
      args,
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
      thresholdSessionAuthToken?: string;
      keyVersion?: string;
      shamirPrimeB64u?: string;
    };
  }): Promise<void> {
    await hydrateSigningSessionPublicValue(this.warmSigningPublic, args);
  }

  async clearWarmSigningSessions(nearAccountId?: AccountId | string): Promise<void> {
    await clearWarmSigningSessionsPublicValue(this.warmSigningPublic, nearAccountId);
  }

  clearThresholdEcdsaCommitQueue(): void {
    clearThresholdEcdsaCommitQueue(this.thresholdEcdsaCommitQueueByKey);
  }

  deriveThresholdEd25519ClientVerifyingShareFromCredential(
    args: Parameters<typeof deriveThresholdEd25519ClientVerifyingShareFromCredentialPublicValue>[1],
  ): ReturnType<typeof deriveThresholdEd25519ClientVerifyingShareFromCredentialPublicValue> {
    return deriveThresholdEd25519ClientVerifyingShareFromCredentialPublicValue(
      this.enginePorts.thresholdEd25519LifecycleDeps,
      args,
    );
  }

  deriveThresholdEd25519HssClientInputsFromCredential(
    args: Parameters<typeof deriveThresholdEd25519HssClientInputsFromCredentialPublicValue>[1],
  ): ReturnType<typeof deriveThresholdEd25519HssClientInputsFromCredentialPublicValue> {
    return deriveThresholdEd25519HssClientInputsFromCredentialPublicValue(
      this.enginePorts.thresholdEd25519LifecycleDeps,
      args,
    );
  }

  prepareThresholdEd25519HssClientCeremonyFromCredential(
    args: Parameters<typeof prepareThresholdEd25519HssClientCeremonyFromCredentialPublicValue>[1],
  ): ReturnType<typeof prepareThresholdEd25519HssClientCeremonyFromCredentialPublicValue> {
    return prepareThresholdEd25519HssClientCeremonyFromCredentialPublicValue(
      this.enginePorts.thresholdEd25519LifecycleDeps,
      args,
    );
  }

  prepareThresholdEd25519HssClientRequest(
    args: Parameters<typeof prepareThresholdEd25519HssClientRequestPublicValue>[1],
  ): ReturnType<typeof prepareThresholdEd25519HssClientRequestPublicValue> {
    return prepareThresholdEd25519HssClientRequestPublicValue(
      this.enginePorts.thresholdEd25519LifecycleDeps,
      args,
    );
  }

  completeThresholdEd25519HssClientCeremony(
    args: Parameters<typeof completeThresholdEd25519HssClientCeremonyPublicValue>[1],
  ): ReturnType<typeof completeThresholdEd25519HssClientCeremonyPublicValue> {
    return completeThresholdEd25519HssClientCeremonyPublicValue(
      this.enginePorts.thresholdEd25519LifecycleDeps,
      args,
    );
  }

  runThresholdEd25519HssCeremonyWithSession(
    args: Parameters<typeof runThresholdEd25519HssCeremonyWithSessionPublicValue>[1],
  ): ReturnType<typeof runThresholdEd25519HssCeremonyWithSessionPublicValue> {
    return runThresholdEd25519HssCeremonyWithSessionPublicValue(
      this.enginePorts.thresholdEd25519LifecycleDeps,
      args,
    );
  }

  openThresholdEd25519HssSeedOutput(
    args: Parameters<typeof openThresholdEd25519HssSeedOutputPublicValue>[1],
  ): ReturnType<typeof openThresholdEd25519HssSeedOutputPublicValue> {
    return openThresholdEd25519HssSeedOutputPublicValue(
      this.enginePorts.thresholdEd25519LifecycleDeps,
      args,
    );
  }

  buildThresholdEd25519SeedExportArtifactFromHssReport(
    args: Parameters<typeof buildThresholdEd25519SeedExportArtifactFromHssReportPublicValue>[1],
  ): ReturnType<typeof buildThresholdEd25519SeedExportArtifactFromHssReportPublicValue> {
    return buildThresholdEd25519SeedExportArtifactFromHssReportPublicValue(
      this.enginePorts.thresholdEd25519LifecycleDeps,
      args,
    );
  }

  destroy(): void {
    this.userPreferencesManager.destroy();
    this.nonceCoordinator.clearAll();
    clearThresholdEcdsaCommitQueue(this.thresholdEcdsaCommitQueueByKey);
    clearThresholdEd25519CommitQueue(this.thresholdEd25519CommitQueueByKey);
    clearAllThresholdEcdsaSessionRecordsPublicValue(this.sessionPublic);
  }

}

/**
 * Boundary-facing API spec for SigningEngine consumers.
 * Keep this narrow and intentional; prefer adding methods here explicitly.
 */
export type SigningEnginePublic = Pick<
  SigningEngine,
  | 'seamsPasskeyConfigs'
  | 'setTheme'
  | 'getUserPreferences'
  | 'getRpId'
  | 'getNonceCoordinator'
  | 'warmCriticalResources'
  | 'assertSealedRefreshStartupParity'
  | 'restorePersistedSessionsForAccount'
  | 'readPersistedAvailableSigningLanes'
  | 'signNear'
  | 'signTempo'
  | 'reportTempoBroadcastAccepted'
  | 'reportTempoBroadcastRejected'
  | 'reportTempoFinalized'
  | 'reportTempoDroppedOrReplaced'
  | 'reconcileTempoNonceLane'
  | 'storeUserData'
  | 'getAllUsers'
  | 'getUserBySignerSlot'
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
  | 'getThresholdEcdsaKeyRefForAccountTarget'
  | 'listThresholdEcdsaSessionRecordsForSubject'
  | 'clearThresholdEcdsaSessionRecordForAccount'
  | 'clearAllThresholdEcdsaSessionRecords'
  | 'persistThresholdEcdsaBootstrapChainAccount'
  | 'getWarmThresholdEd25519SessionStatus'
  | 'getWarmThresholdEcdsaSessionStatus'
  | 'listWarmThresholdEcdsaSessionStatuses'
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
