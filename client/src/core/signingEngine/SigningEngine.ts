import { IndexedDBManager } from '@/core/indexedDB';
import type { ClientAuthenticatorData, ClientUserData, StoreUserDataInput } from '../accountData/near/types';
import { getNearThresholdKeyMaterial } from '../accountData/near/keyMaterial';
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
} from './session/budget/budgetStatusReader';
import type { TouchIdPrompt } from './stepUpConfirmation/passkeyPrompt/touchIdPrompt';
import type { WebAuthnAllowCredential } from './webauthnAuth/credentials/collectAuthenticationCredentialForChallengeB64u';
import type { EvmSigningRequest } from './chains/evm/types';
import type { EvmSignedResult } from './chains/evm/evmAdapter';
import type { TempoSigningRequest } from './chains/tempo/types';
import type { TempoSignedResult } from './chains/tempo/tempoAdapter';
import type { EcdsaBootstrapRequest } from './session/passkey/ecdsaBootstrap';
import { claimWarmSessionPrfFirst } from './session/passkey/prfClaim';
import { getLastLoggedInSignerSlot } from './webauthnAuth/device/signerSlot';
import type {
  EvmFamilyEcdsaKeyHandle,
  EvmFamilyEcdsaKeyIdentity,
  EvmFamilyEcdsaSessionLanePolicy,
} from './session/identity/evmFamilyEcdsaIdentity';
import {
  createThresholdEd25519PublicApi,
  type ThresholdEd25519PublicApi,
} from './threshold/ed25519/public';
import {
  persistThresholdEcdsaBootstrapForWalletTarget as persistThresholdEcdsaBootstrapForWalletTargetValue,
} from './session/warmCapabilities/ecdsaBootstrapPersistence';
import {
  clearThresholdEcdsaSessionRecordForWalletTarget as clearThresholdEcdsaSessionRecordForWalletTargetValue,
  getStoredThresholdEd25519SessionRecordForAccount,
  getEmailOtpThresholdEcdsaKeyRefForSigning as getEmailOtpThresholdEcdsaKeyRefForSigningValue,
  getEmailOtpThresholdEcdsaSessionRecordForSigning as getEmailOtpThresholdEcdsaSessionRecordForSigningValue,
  getPasskeyThresholdEcdsaKeyRefForSigning as getPasskeyThresholdEcdsaKeyRefForSigningValue,
  getPasskeyThresholdEcdsaSessionRecordForSigning as getPasskeyThresholdEcdsaSessionRecordForSigningValue,
  getThresholdEcdsaKeyRefByKey as getThresholdEcdsaKeyRefByIdentityValue,
  getThresholdEcdsaSessionRecordByKey as getThresholdEcdsaSessionRecordByIdentityValue,
  getThresholdEcdsaSessionRecordForWalletTarget as getThresholdEcdsaSessionRecordForWalletTargetValue,
  listThresholdEcdsaKeyRefsForWalletTarget as listThresholdEcdsaKeyRefsForWalletTargetValue,
  listThresholdEcdsaSessionRecordsForWalletTarget as listThresholdEcdsaSessionRecordsForWalletTargetValue,
  markThresholdEd25519EmailOtpSessionConsumedForAccount as markThresholdEd25519EmailOtpSessionConsumedForAccountValue,
  consumeSingleUseEmailOtpEcdsaLane as consumeSingleUseEmailOtpEcdsaLaneValue,
  upsertThresholdEcdsaSessionFromBootstrap as upsertThresholdEcdsaSessionFromBootstrapValue,
  type ThresholdEd25519SessionRecord,
  type ThresholdEcdsaSessionRecord,
} from './session/persistence/records';
import type {
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
import {
  type ThresholdEcdsaLoginPrefillResult,
} from './session/warmCapabilities/ecdsaLoginPrefill';
import {
  parseThresholdRuntimePolicyScopeFromJwt,
  type ThresholdRuntimePolicyScope,
} from './threshold/sessionPolicy';
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
  createRecoveryPublicApi,
  type RecoveryPublicApi,
  type RecoveryPublicDeps,
  type SigningEngineExportKeypairWithUIInput,
  type KeyExportEventCallback,
} from './flows/recovery/public';
import type { RegistrationCredentialConfirmationPayload } from './workerManager/validation';
import type { ConfirmationConfig } from '../types/signer-worker';
import {
  createRegistrationPublicApi,
  type RegistrationPublicApi,
  type StoredRegistrationData,
  type StoreAuthenticatorInput,
} from './flows/registration/public';
import {
  createEmailOtpPublicApi,
  type EmailOtpPublicApi,
  type EmailOtpPublicDeps,
  type EnrollAndLoginWithEmailOtpEcdsaCapabilityInternalArgs,
  type EnrollAndLoginWithEmailOtpEcdsaCapabilityInternalResult,
  type LoginWithEmailOtpEcdsaCapabilityInternalArgs,
  type LoginWithEmailOtpEcdsaCapabilityInternalResult,
} from './flows/signEvmFamily/emailOtpPublic';
import type { EmailOtpEd25519SessionReconstructionPlan } from './session/emailOtp/provisioning';
import { initializeSigningEngineRuntime } from './assembly/createSigningEngineRuntime';
import { createManagerAssembly } from './assembly/createManagers';
import { verifySealedRefreshStartupParity } from '../rpcClients/relayer/sealedRefreshCapabilities';
import type { ThresholdEcdsaHssRouteAuth } from '../rpcClients/relayer/thresholdEcdsa';
import type { WarmSessionEcdsaCapabilityState } from './session/warmCapabilities/types';
import type {
  ProvisionWarmEd25519CapabilityResult,
  WarmEcdsaSigningSessionStatus,
} from './session/warmCapabilities/types';
import { createSigningEnginePorts } from './assembly/createPorts';
import { provisionThresholdEd25519Session as provisionThresholdEd25519SessionValue } from './session/passkey/ed25519SessionProvision';
import { provisionThresholdEcdsaSession as provisionThresholdEcdsaSessionValue } from './session/passkey/ecdsaSessionProvision';
import type { EmailOtpThresholdSessionCoordinator } from './session/emailOtp/EmailOtpThresholdSessionCoordinator';
import type { EmailOtpBootstrapRecovery } from './stepUpConfirmation/otpPrompt/bootstrapRecovery';
import type {
  RestorePersistedSessionsForWalletInput,
  RestorePersistedSessionsForWalletResult,
  ReadAvailableSigningLanesInput,
  AvailableSigningLanes,
  SessionPublicApi,
  ThresholdEcdsaSessionRecord as SessionPublicThresholdEcdsaSessionRecord,
  UpsertThresholdEcdsaSessionFromBootstrapInput,
  GetThresholdEcdsaKeyRefForWalletTargetInput,
  ListThresholdEcdsaSessionRecordsForWalletTargetInput,
} from './session/public';
import { createSessionPublicApi } from './session/public';
import { readPersistedAvailableSigningLanesForSigning as readPersistedAvailableSigningLanesForSigningValue } from './session/availability/persistedAvailableSigningLanes';
import {
  createPasskeyPublicDeps,
  createWarmCapabilitiesPublicDeps,
  createWarmSigningPorts,
  type WarmSigningPorts,
} from './assembly/ports/warmSigning';
import { createStepUpRuntime } from './assembly/ports/stepUpRuntime';
import { createRecoveryPublicDeps } from './assembly/ports/recovery';
import { createSessionPublicDeps } from './assembly/ports/session';
import { createEmailOtpPublicDeps } from './assembly/ports/emailOtp';
import type {
  WarmCapabilitiesPublicApi,
} from './session/warmCapabilities/public';
import { createWarmCapabilitiesPublicApi } from './session/warmCapabilities/public';
import type { ConnectEd25519SessionArgs, PasskeyPublicApi } from './session/passkey/public';
import { createPasskeyPublicApi } from './session/passkey/public';

export type { ThresholdEcdsaSessionBootstrapResult } from './threshold/ecdsa/activation';
export type { EmailOtpBootstrapRecovery } from './stepUpConfirmation/otpPrompt/bootstrapRecovery';
export type { NearSignIntentRequest, NearSignIntentResult } from './flows/signNear/signNear';
export type { ThresholdEcdsaLoginPrefillResult } from './session/warmCapabilities/ecdsaLoginPrefill';

export type BootstrapLoginEcdsaSessionFromRestoredEd25519Args = {
  walletId: WalletId;
  subjectId?: never;
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

type SigningEngineEmailOtpEcdsaLoginInput = Omit<
  LoginWithEmailOtpEcdsaCapabilityInternalArgs,
  'ed25519SessionReconstruction'
> & {
  ed25519SessionReconstruction?: EmailOtpEd25519SessionReconstructionPlan;
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
  private readonly passkeyPublic: PasskeyPublicApi;
  private readonly warmCapabilitiesPublic: WarmCapabilitiesPublicApi;
  private readonly sessionPublic: SessionPublicApi;
  private readonly emailOtpPublic: EmailOtpPublicApi;
  private readonly recoveryPublic: RecoveryPublicApi;
  private readonly registrationPublic: RegistrationPublicApi;
  private readonly thresholdEd25519Public: ThresholdEd25519PublicApi;
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
    const sessionPublicDeps = createSessionPublicDeps({
      seamsPasskeyConfigs: this.seamsPasskeyConfigs,
      ecdsaSessions: this.warmSigning.ecdsaSessions,
      touchConfirm: this.touchConfirm,
      emailOtpSessions: this.emailOtpSessions,
      getWalletSigningBudgetStatus: (statusArgs) =>
        readTrustedWalletSigningBudgetStatusValue(
          {
            ecdsaSessions: this.warmSigning.ecdsaSessions,
          },
          statusArgs,
        ),
    });
    this.sessionPublic = createSessionPublicApi(sessionPublicDeps);
    const emailOtpPublicDeps = createEmailOtpPublicDeps({
      ecdsaSessions: this.warmSigning.ecdsaSessions,
      relayerUrl: this.seamsPasskeyConfigs.network.relayer?.url || '',
      shamirPrimeB64u: this.seamsPasskeyConfigs.signing.sessionSeal?.shamirPrimeB64u || '',
      getSignerWorkerContext: () =>
        this.enginePorts.thresholdSessionActivationDeps.getSignerWorkerContext(),
      emailOtpSessions: this.emailOtpSessions,
    });
    this.emailOtpPublic = createEmailOtpPublicApi(emailOtpPublicDeps);
    const recoveryPublicDeps = createRecoveryPublicDeps({
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
        resolveExactEcdsaRecord: (recordArgs) =>
          this.warmSigning.statusReader.resolveExactEcdsaRecord(recordArgs),
      },
      getWalletSigningBudgetStatus: (statusArgs) =>
        readTrustedWalletSigningBudgetStatusValue(
          {
            ecdsaSessions: this.warmSigning.ecdsaSessions,
          },
          statusArgs,
        ),
    });
    this.recoveryPublic = createRecoveryPublicApi(recoveryPublicDeps);

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
          this.registrationPublic.initializeCurrentUser({
            nearAccountId,
            nearClient: nearClientArg,
          }),
      persistThresholdEcdsaBootstrapForWalletTarget: (args) =>
        persistThresholdEcdsaBootstrapForWalletTargetValue({
          indexedDB: this.enginePorts.indexedDB,
          walletId: toAccountId(args.walletId),
          chainTarget: args.chainTarget,
          bootstrap: args.bootstrap,
        }),
      upsertThresholdEcdsaSessionFromBootstrap: (args) =>
        upsertThresholdEcdsaSessionFromBootstrapValue(this.warmSigning.ecdsaSessions, args),
      listThresholdEcdsaKeyRefsForWalletTarget: (args) =>
        listThresholdEcdsaKeyRefsForWalletTargetValue(this.warmSigning.ecdsaSessions, args),
      listThresholdEcdsaSessionRecordsForWalletTarget: (args) =>
        listThresholdEcdsaSessionRecordsForWalletTargetValue(this.warmSigning.ecdsaSessions, args),
      getThresholdEcdsaSessionRecordByKey: (identity) =>
        getThresholdEcdsaSessionRecordByIdentityValue(this.warmSigning.ecdsaSessions, identity),
      getThresholdEcdsaKeyRefByKey: (identity) =>
        getThresholdEcdsaKeyRefByIdentityValue(this.warmSigning.ecdsaSessions, identity),
      getEmailOtpThresholdEcdsaKeyRefForSigning: (args) =>
        getEmailOtpThresholdEcdsaKeyRefForSigningValue(this.warmSigning.ecdsaSessions, args),
      getEmailOtpThresholdEcdsaSessionRecordForSigning: (args) =>
        getThresholdEcdsaSessionRecordForWalletTargetValue(this.warmSigning.ecdsaSessions, {
          walletId: args.walletId,
          chainTarget: args.chainTarget,
          source: 'email_otp',
        }),
      getPasskeyThresholdEcdsaKeyRefForSigning: (args) =>
        getPasskeyThresholdEcdsaKeyRefForSigningValue(this.warmSigning.ecdsaSessions, args),
      getPasskeyThresholdEcdsaSessionRecordForSigning: (args) =>
        getThresholdEcdsaSessionRecordForWalletTargetValue(this.warmSigning.ecdsaSessions, {
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
            getWalletSigningBudgetStatus: (statusArgs) =>
              this.enginePorts.signingSessionCoordinator.getAvailableStatus(statusArgs),
          },
          args,
          configuredThresholdEcdsaChainTargets(this.seamsPasskeyConfigs.network.chains),
        ),
      consumeSingleUseEmailOtpEcdsaLane: (command) =>
        consumeSingleUseEmailOtpEcdsaLaneValue(this.warmSigning.ecdsaSessions, command),
      markThresholdEd25519EmailOtpSessionConsumedForAccount: (args) =>
        markThresholdEd25519EmailOtpSessionConsumedForAccountValue(args),
      clearThresholdEcdsaSessionRecordForWalletTarget: (args) =>
        clearThresholdEcdsaSessionRecordForWalletTargetValue(this.warmSigning.ecdsaSessions, args),
      provisionThresholdEcdsaSession: (args) =>
        provisionThresholdEcdsaSessionValue(
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
    const passkeyPublicDeps = createPasskeyPublicDeps({
      seamsPasskeyConfigs: this.seamsPasskeyConfigs,
      indexedDB: this.enginePorts.indexedDB,
      touchIdPrompt: this.touchIdPrompt,
      touchConfirm: this.touchConfirm,
      warmSigning: this.warmSigning,
      thresholdEcdsaBootstrapQueueByWallet: this.thresholdEcdsaBootstrapQueueByWallet,
      ensureSealedRefreshStartupParity: () => this.ensureSealedRefreshStartupParity(),
      thresholdSessionActivationDeps: this.enginePorts.thresholdSessionActivationDeps,
    });
    this.passkeyPublic = createPasskeyPublicApi(passkeyPublicDeps);
    const warmCapabilitiesPublicDeps = createWarmCapabilitiesPublicDeps({
      seamsPasskeyConfigs: this.seamsPasskeyConfigs,
      indexedDB: this.enginePorts.indexedDB,
      touchConfirm: this.touchConfirm,
      warmSigning: this.warmSigning,
      thresholdSessionActivationDeps: this.enginePorts.thresholdSessionActivationDeps,
      resolveCanonicalThresholdEcdsaSessionIdForWalletTarget:
        this.enginePorts.resolveCanonicalThresholdEcdsaSessionIdForWalletTarget,
      signingSessionCoordinator: this.enginePorts.signingSessionCoordinator,
    });
    this.warmCapabilitiesPublic = createWarmCapabilitiesPublicApi(warmCapabilitiesPublicDeps);
    this.registrationPublic = createRegistrationPublicApi({
      accountLifecycle: this.enginePorts.registrationAccountLifecycleDeps,
      session: this.enginePorts.registrationSessionDeps,
      signingKeyOps: this.enginePorts.nearKeyOpsDeps.signingKeyOps,
    });
    this.thresholdEd25519Public = createThresholdEd25519PublicApi(
      this.enginePorts.thresholdEd25519LifecycleDeps,
    );

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
    return await this.sessionPublic.restorePersistedSessionsForWallet(args);
  }

  async readPersistedAvailableSigningLanes(
    args: Omit<ReadAvailableSigningLanesInput, 'ecdsaChainTargets'>,
  ): Promise<AvailableSigningLanes> {
    return await this.sessionPublic.readPersistedAvailableSigningLanes(args);
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
    walletSession: WalletSessionRef;
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
    return this.registrationPublic.storeUserData(userData);
  }

  getAllUsers(): Promise<ClientUserData[]> {
    return this.registrationPublic.getAllUsers();
  }

  getUserBySignerSlot(
    nearAccountId: AccountId,
    signerSlot: number,
  ): Promise<ClientUserData | null> {
    return this.registrationPublic.getUserBySignerSlot(nearAccountId, signerSlot);
  }

  getLastUser(): Promise<ClientUserData | null> {
    return this.registrationPublic.getLastUser();
  }

  getAuthenticatorsByUser(nearAccountId: AccountId): Promise<ClientAuthenticatorData[]> {
    return this.registrationPublic.getAuthenticatorsByUser(nearAccountId);
  }

  updateLastLogin(nearAccountId: AccountId): Promise<void> {
    return this.registrationPublic.updateLastLogin(nearAccountId);
  }

  setLastUser(nearAccountId: AccountId, signerSlot: number = 1): Promise<void> {
    return this.registrationPublic.setLastUser(nearAccountId, signerSlot);
  }

  initializeCurrentUser(nearAccountId: AccountId, nearClientArg?: NearClient): Promise<void> {
    return this.registrationPublic.initializeCurrentUser({
      nearAccountId,
      nearClient: nearClientArg,
    });
  }

  storeAuthenticator(authenticatorData: StoreAuthenticatorInput): Promise<void> {
    return this.registrationPublic.storeAuthenticator(authenticatorData);
  }

  rollbackUserRegistration(nearAccountId: AccountId): Promise<void> {
    return this.registrationPublic.rollbackUserRegistration(nearAccountId);
  }

  hasPasskeyCredential(nearAccountId: AccountId): Promise<boolean> {
    return this.registrationPublic.hasPasskeyCredential(nearAccountId);
  }

  atomicStoreRegistrationData(args: {
    nearAccountId: AccountId;
    credential: WebAuthnRegistrationCredential;
    operationalPublicKey: string;
  }): Promise<StoredRegistrationData> {
    return this.registrationPublic.atomicStoreRegistrationData(args);
  }

  requestRegistrationCredentialConfirmation(params: {
    nearAccountId: string;
    signerSlot: number;
    confirmerText?: { title?: string; body?: string };
    confirmationConfigOverride?: Partial<ConfirmationConfig>;
  }): Promise<RegistrationCredentialConfirmationPayload> {
    return this.registrationPublic.requestRegistrationCredentialConfirmation(params);
  }

  getAuthenticationCredentialsSerialized(args: {
    nearAccountId: AccountId;
    challengeB64u: string;
    allowCredentials: WebAuthnAllowCredential[];
    includeSecondPrfOutput?: boolean;
  }): Promise<WebAuthnAuthenticationCredential> {
    return this.registrationPublic.getAuthenticationCredentialsSerialized(args);
  }

  extractCosePublicKey(attestationObjectBase64url: string): Promise<Uint8Array> {
    return this.registrationPublic.extractCosePublicKey(attestationObjectBase64url);
  }

  async exportKeypairWithUI(
    input: SigningEngineExportKeypairWithUIInput,
  ): Promise<{ accountId: string; exportedSchemes: Array<'ed25519' | 'secp256k1'> }> {
    return await this.recoveryPublic.exportKeypairWithUI(input);
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
    return this.recoveryPublic.exportNearEd25519SeedArtifactWithUI(args);
  }

  async exportThresholdEd25519SeedFromHssReport(args: {
    nearAccountId: AccountId;
    preparedSession: Parameters<
      RecoveryPublicApi['exportThresholdEd25519SeedFromHssReport']
    >[0]['preparedSession'];
    finalizedReport: Parameters<
      RecoveryPublicApi['exportThresholdEd25519SeedFromHssReport']
    >[0]['finalizedReport'];
    expectedPublicKey: string;
    options: {
      variant?: 'drawer' | 'modal';
      theme?: 'dark' | 'light';
      onEvent?: KeyExportEventCallback;
    };
  }): Promise<{ accountId: string; exportedSchemes: Array<'ed25519' | 'secp256k1'> }> {
    return await this.recoveryPublic.exportThresholdEd25519SeedFromHssReport(args);
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
    return await this.passkeyPublic.connectEd25519Session(args);
  }

  async bootstrapEcdsaSession(
    args: EcdsaBootstrapRequest,
  ): Promise<ThresholdEcdsaSessionBootstrapResult> {
    return await this.passkeyPublic.bootstrapEcdsaSession(args);
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

    return await this.passkeyPublic.bootstrapEcdsaSession({
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
    args: SigningEngineEmailOtpEcdsaLoginInput,
  ): Promise<LoginWithEmailOtpEcdsaCapabilityInternalResult> {
    const walletId = toAccountId(args.walletSession.walletId);
    const signerSlot = await getLastLoggedInSignerSlot(walletId, IndexedDBManager.clientDB).catch(
      () => 1,
    );
    const thresholdKeyMaterial = await getNearThresholdKeyMaterial(
      {
        clientDB: IndexedDBManager.clientDB,
        accountKeyMaterialDB: IndexedDBManager.accountKeyMaterialDB,
      },
      walletId,
      signerSlot,
    ).catch(() => null);
    const participantIds = thresholdKeyMaterial?.participants
      .map((participant) => Number(participant.id))
      .filter((participantId) => Number.isSafeInteger(participantId) && participantId > 0);
    const runtimePolicyScope =
      args.runtimePolicyScope ||
      parseThresholdRuntimePolicyScopeFromJwt(args.appSessionJwt) ||
      parseThresholdRuntimePolicyScopeFromJwt(args.routeAuth?.jwt);
    const ed25519SessionReconstruction: EmailOtpEd25519SessionReconstructionPlan =
      args.ed25519SessionReconstruction ||
      (thresholdKeyMaterial?.relayerKeyId &&
      thresholdKeyMaterial.keyVersion &&
      participantIds?.length &&
      runtimePolicyScope
        ? {
            kind: 'reconstruct',
            ed25519Key: {
              relayerKeyId: thresholdKeyMaterial.relayerKeyId,
              keyVersion: thresholdKeyMaterial.keyVersion,
              participantIds,
            },
            runtimePolicyScope,
          }
        : {
            kind: 'defer',
            reason:
              thresholdKeyMaterial?.relayerKeyId &&
              thresholdKeyMaterial.keyVersion &&
              participantIds?.length
                ? 'missing_runtime_policy_scope'
                : 'missing_ed25519_key_identity',
          });
    return await this.emailOtpPublic.loginWithEmailOtpEcdsaCapabilityInternal({
      ...args,
      ed25519SessionReconstruction,
    });
  }

  async requestEmailOtpSigningSessionChallenge(args: {
    walletSession: WalletSessionRef;
    chainTarget: ThresholdEcdsaChainTarget;
  }): Promise<{ challengeId: string; emailHint?: string }> {
    return await this.emailOtpPublic.requestEmailOtpSigningSessionChallenge(args);
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
    return await this.emailOtpPublic.refreshEmailOtpSigningSession(args);
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
  }): Promise<Awaited<ReturnType<EmailOtpPublicApi['enrollEmailOtpInternal']>>> {
    return await this.emailOtpPublic.enrollEmailOtpInternal(args);
  }

  async enrollAndLoginWithEmailOtpEcdsaCapabilityInternal(
    args: EnrollAndLoginWithEmailOtpEcdsaCapabilityInternalArgs,
  ): Promise<EnrollAndLoginWithEmailOtpEcdsaCapabilityInternalResult> {
    return await this.emailOtpPublic.enrollAndLoginWithEmailOtpEcdsaCapabilityInternal(args);
  }

  upsertThresholdEcdsaSessionFromBootstrap(
    args: UpsertThresholdEcdsaSessionFromBootstrapInput,
  ): void {
    this.sessionPublic.upsertThresholdEcdsaSessionFromBootstrap(args);
  }

  getThresholdEcdsaKeyRefForWalletTarget(
    args: GetThresholdEcdsaKeyRefForWalletTargetInput,
  ): ThresholdEcdsaSecp256k1KeyRef {
    return this.sessionPublic.getThresholdEcdsaKeyRefForWalletTarget(args);
  }

  listThresholdEcdsaSessionRecordsForWalletTarget(
    args: ListThresholdEcdsaSessionRecordsForWalletTargetInput,
  ): SessionPublicThresholdEcdsaSessionRecord[] {
    return this.sessionPublic.listThresholdEcdsaSessionRecordsForWalletTarget(args);
  }

  clearThresholdEcdsaSessionRecordForWallet(walletId: WalletId): void {
    this.sessionPublic.clearThresholdEcdsaSessionRecordForWallet(walletId);
  }

  clearAllThresholdEcdsaSessionRecords(): void {
    this.sessionPublic.clearAllThresholdEcdsaSessionRecords();
  }

  persistThresholdEcdsaBootstrapForWalletTarget(args: {
    walletId: WalletId;
    chainTarget: ThresholdEcdsaChainTarget;
    bootstrap: ThresholdEcdsaSessionBootstrapResult;
    ensureEmailOtpNearAccountMapping?: boolean;
  }): Promise<void> {
    return this.warmCapabilitiesPublic.persistThresholdEcdsaBootstrapForWalletTarget(args);
  }

  getWarmThresholdEd25519SessionStatus(
    nearAccountId: AccountId | string,
  ): Promise<SigningSessionStatus | null> {
    return this.warmCapabilitiesPublic.getWarmThresholdEd25519SessionStatus(nearAccountId);
  }

  getWarmThresholdEcdsaSessionStatus(
    walletId: WalletId,
    chainTarget: ThresholdEcdsaChainTarget,
    thresholdSessionId: string,
  ): Promise<WarmEcdsaSigningSessionStatus | null> {
    return this.warmCapabilitiesPublic.getWarmThresholdEcdsaSessionStatus(
      walletId,
      chainTarget,
      thresholdSessionId,
    );
  }

  listWarmThresholdEcdsaSessionStatuses(
    walletId: WalletId,
    chainTarget: ThresholdEcdsaChainTarget,
  ): Promise<WarmEcdsaSigningSessionStatus[]> {
    return this.warmCapabilitiesPublic.listWarmThresholdEcdsaSessionStatuses(
      walletId,
      chainTarget,
    );
  }

  async scheduleThresholdEcdsaLoginPresignPrefill(args: {
    walletId: WalletId;
    chainTarget: ThresholdEcdsaChainTarget;
    thresholdEcdsaKeyRef: ThresholdEcdsaSecp256k1KeyRef;
    minRemainingUsesBeforePrefill?: number;
  }): Promise<ThresholdEcdsaLoginPrefillResult> {
    return await this.warmCapabilitiesPublic.scheduleThresholdEcdsaLoginPresignPrefill(args);
  }

  async hydrateSigningSession(args: {
    sessionId: string;
    prfFirstB64u: string;
    expiresAtMs: number;
    remainingUses: number;
    transport?: WarmSessionSealTransportInput;
  }): Promise<void> {
    await this.warmCapabilitiesPublic.hydrateSigningSession(args);
  }

  async clearVolatileWarmSigningMaterial(walletId?: WalletId): Promise<void> {
    await this.warmCapabilitiesPublic.clearVolatileWarmSigningMaterial(walletId);
  }

  clearThresholdEcdsaCommitQueue(): void {
    clearThresholdEcdsaCommitQueue(this.thresholdEcdsaCommitQueueByKey);
  }

  deriveThresholdEd25519ClientVerifyingShareFromCredential(
    args: Parameters<
      ThresholdEd25519PublicApi['deriveThresholdEd25519ClientVerifyingShareFromCredential']
    >[0],
  ): ReturnType<ThresholdEd25519PublicApi['deriveThresholdEd25519ClientVerifyingShareFromCredential']> {
    return this.thresholdEd25519Public.deriveThresholdEd25519ClientVerifyingShareFromCredential(args);
  }

  deriveThresholdEd25519HssClientInputsFromCredential(
    args: Parameters<
      ThresholdEd25519PublicApi['deriveThresholdEd25519HssClientInputsFromCredential']
    >[0],
  ): ReturnType<ThresholdEd25519PublicApi['deriveThresholdEd25519HssClientInputsFromCredential']> {
    return this.thresholdEd25519Public.deriveThresholdEd25519HssClientInputsFromCredential(args);
  }

  prepareThresholdEd25519HssClientCeremonyFromCredential(
    args: Parameters<
      ThresholdEd25519PublicApi['prepareThresholdEd25519HssClientCeremonyFromCredential']
    >[0],
  ): ReturnType<ThresholdEd25519PublicApi['prepareThresholdEd25519HssClientCeremonyFromCredential']> {
    return this.thresholdEd25519Public.prepareThresholdEd25519HssClientCeremonyFromCredential(args);
  }

  prepareThresholdEd25519HssClientRequest(
    args: Parameters<ThresholdEd25519PublicApi['prepareThresholdEd25519HssClientRequest']>[0],
  ): ReturnType<ThresholdEd25519PublicApi['prepareThresholdEd25519HssClientRequest']> {
    return this.thresholdEd25519Public.prepareThresholdEd25519HssClientRequest(args);
  }

  completeThresholdEd25519HssClientCeremony(
    args: Parameters<ThresholdEd25519PublicApi['completeThresholdEd25519HssClientCeremony']>[0],
  ): ReturnType<ThresholdEd25519PublicApi['completeThresholdEd25519HssClientCeremony']> {
    return this.thresholdEd25519Public.completeThresholdEd25519HssClientCeremony(args);
  }

  runThresholdEd25519HssCeremonyWithSession(
    args: Parameters<ThresholdEd25519PublicApi['runThresholdEd25519HssCeremonyWithSession']>[0],
  ): ReturnType<ThresholdEd25519PublicApi['runThresholdEd25519HssCeremonyWithSession']> {
    return this.thresholdEd25519Public.runThresholdEd25519HssCeremonyWithSession(args);
  }

  openThresholdEd25519HssSeedOutput(
    args: Parameters<ThresholdEd25519PublicApi['openThresholdEd25519HssSeedOutput']>[0],
  ): ReturnType<ThresholdEd25519PublicApi['openThresholdEd25519HssSeedOutput']> {
    return this.thresholdEd25519Public.openThresholdEd25519HssSeedOutput(args);
  }

  buildThresholdEd25519SeedExportArtifactFromHssReport(
    args: Parameters<
      ThresholdEd25519PublicApi['buildThresholdEd25519SeedExportArtifactFromHssReport']
    >[0],
  ): ReturnType<ThresholdEd25519PublicApi['buildThresholdEd25519SeedExportArtifactFromHssReport']> {
    return this.thresholdEd25519Public.buildThresholdEd25519SeedExportArtifactFromHssReport(args);
  }

  destroy(): void {
    this.userPreferencesManager.destroy();
    this.nonceCoordinator.clearAll();
    clearThresholdEcdsaCommitQueue(this.thresholdEcdsaCommitQueueByKey);
    clearThresholdEd25519CommitQueue(this.thresholdEd25519CommitQueueByKey);
    this.sessionPublic.clearAllThresholdEcdsaSessionRecords();
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
  | 'restorePersistedSessionsForWallet'
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
  | 'bootstrapLoginEcdsaSessionFromRestoredEd25519'
  | 'upsertThresholdEcdsaSessionFromBootstrap'
  | 'getThresholdEcdsaKeyRefForWalletTarget'
  | 'listThresholdEcdsaSessionRecordsForWalletTarget'
  | 'clearThresholdEcdsaSessionRecordForWallet'
  | 'clearAllThresholdEcdsaSessionRecords'
  | 'persistThresholdEcdsaBootstrapForWalletTarget'
  | 'getWarmThresholdEd25519SessionStatus'
  | 'getWarmThresholdEcdsaSessionStatus'
  | 'listWarmThresholdEcdsaSessionStatuses'
  | 'scheduleThresholdEcdsaLoginPresignPrefill'
  | 'hydrateSigningSession'
  | 'clearVolatileWarmSigningMaterial'
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
