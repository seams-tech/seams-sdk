import { IndexedDBManager } from '@/core/indexedDB';
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
import { readTrustedWalletSigningBudgetStatus as readTrustedWalletSigningBudgetStatusValue } from './session/budget/budgetStatusReader';
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
import {
  createThresholdEd25519PublicApi,
  type ThresholdEd25519PublicApi,
} from './threshold/ed25519/public';
import { persistThresholdEcdsaBootstrapForWalletTarget as persistThresholdEcdsaBootstrapForWalletTargetValue } from './session/warmCapabilities/ecdsaBootstrapPersistence';
import {
  clearThresholdEcdsaSessionRecordForWalletTarget as clearThresholdEcdsaSessionRecordForWalletTargetValue,
  getStoredThresholdEd25519SessionRecordForAccount,
  getEmailOtpThresholdEcdsaSessionRecordForSigning as getEmailOtpThresholdEcdsaSessionRecordForSigningValue,
  getPasskeyThresholdEcdsaSessionRecordForSigning as getPasskeyThresholdEcdsaSessionRecordForSigningValue,
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
import type { ThresholdEcdsaSessionStoreSource } from './session/identity/laneIdentity';
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
import { initializeSigningEngineRuntime } from './assembly/createSigningEngineRuntime';
import { createManagerAssembly } from './assembly/createManagers';
import { verifySealedRefreshStartupParity } from '../rpcClients/relayer/sealedRefreshCapabilities';
import type {
  ThresholdEcdsaHssRoleLocalBootstrapValue,
  ThresholdEcdsaHssRouteAuth,
} from '../rpcClients/relayer/thresholdEcdsa';
import type {
  WalletRegistrationEcdsaClientBootstrap,
  WalletRegistrationEcdsaPrepareContext,
  WalletRegistrationEcdsaWalletKey,
} from '../rpcClients/relayer/walletRegistration';
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
import type { WarmCapabilitiesPublicApi } from './session/warmCapabilities/public';
import { createWarmCapabilitiesPublicApi } from './session/warmCapabilities/public';
import type { ConnectEd25519SessionArgs, PasskeyPublicApi } from './session/passkey/public';
import { createPasskeyPublicApi } from './session/passkey/public';
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
      getEmailOtpThresholdEcdsaSessionRecordForSigning: (args) =>
        getThresholdEcdsaSessionRecordForWalletTargetValue(this.warmSigning.ecdsaSessions, {
          walletId: args.walletId,
          chainTarget: args.chainTarget,
          source: 'email_otp',
        }),
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

  storeWalletSubjectEd25519RegistrationData(
    args: Parameters<RegistrationPublicApi['storeWalletSubjectEd25519RegistrationData']>[0],
  ): Promise<StoredRegistrationData> {
    return this.registrationPublic.storeWalletSubjectEd25519RegistrationData(args);
  }

  storeWalletSubjectEd25519SignerRecord(
    args: Parameters<RegistrationPublicApi['storeWalletSubjectEd25519SignerRecord']>[0],
  ): ReturnType<RegistrationPublicApi['storeWalletSubjectEd25519SignerRecord']> {
    return this.registrationPublic.storeWalletSubjectEd25519SignerRecord(args);
  }

  storeWalletSubjectEcdsaSignerRecords(
    args: Parameters<RegistrationPublicApi['storeWalletSubjectEcdsaSignerRecords']>[0],
  ): ReturnType<RegistrationPublicApi['storeWalletSubjectEcdsaSignerRecords']> {
    return this.registrationPublic.storeWalletSubjectEcdsaSignerRecords(args);
  }

  storeWalletSubjectEcdsaRegistrationData(
    args: Parameters<RegistrationPublicApi['storeWalletSubjectEcdsaRegistrationData']>[0],
  ): ReturnType<RegistrationPublicApi['storeWalletSubjectEcdsaRegistrationData']> {
    return this.registrationPublic.storeWalletSubjectEcdsaRegistrationData(args);
  }

  requestRegistrationCredentialConfirmation(params: {
    nearAccountId: string;
    signerSlot: number;
    confirmerText?: { title?: string; body?: string };
    confirmationConfigOverride?: Partial<ConfirmationConfig>;
    challengeB64u?: string;
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
      clientPublicKey33B64u: clientBootstrap.clientPublicKey33B64u,
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
    bootstrap: ThresholdEcdsaHssRoleLocalBootstrapValue;
    walletKeys: readonly WalletRegistrationEcdsaWalletKey[];
  }): Promise<void> {
    await this.enginePorts.thresholdSessionActivationDeps.touchConfirm.putWarmSessionMaterial({
      sessionId: args.bootstrap.sessionId,
      prfFirstB64u: args.preparedClientBootstrap.clientRootShare32B64u,
      expiresAtMs: Number(args.bootstrap.expiresAtMs),
      remainingUses: Number(args.bootstrap.remainingUses),
    });
    for (const walletKey of args.walletKeys) {
      const bootstrap = this.buildWalletRegistrationEcdsaSessionBootstrap({
        walletId: args.walletId,
        relayerUrl: args.relayerUrl,
        chainTarget: walletKey.chainTarget,
        preparedClientBootstrap: args.preparedClientBootstrap,
        bootstrap: args.bootstrap,
        walletKey,
      });
      await this.persistThresholdEcdsaBootstrapForWalletTarget({
        walletId: args.walletId,
        chainTarget: walletKey.chainTarget,
        bootstrap,
      });
      this.upsertThresholdEcdsaSessionFromBootstrap({
        walletId: args.walletId,
        chainTarget: walletKey.chainTarget,
        bootstrap,
        source: 'registration',
      });
    }
  }

  private buildWalletRegistrationEcdsaSessionBootstrap(args: {
    walletId: WalletId;
    relayerUrl: string;
    chainTarget: ThresholdEcdsaChainTarget;
    preparedClientBootstrap: WalletRegistrationEcdsaPreparedClientBootstrap;
    bootstrap: ThresholdEcdsaHssRoleLocalBootstrapValue;
    walletKey: WalletRegistrationEcdsaWalletKey;
  }): ThresholdEcdsaSessionBootstrapResult {
    const localBootstrap = args.preparedClientBootstrap.localClientBootstrap;
    const serverBootstrap = args.bootstrap;
    if (
      String(localBootstrap.clientPublicKey33B64u || '').trim() !==
        String(serverBootstrap.publicIdentity.clientPublicKey33B64u || '').trim() ||
      String(localBootstrap.contextBinding32B64u || '').trim() !==
        String(serverBootstrap.contextBinding32B64u || '').trim()
    ) {
      throw new Error('ECDSA registration bootstrap identity mismatch');
    }
    const participantIds = args.walletKey.participantIds.map((participantId) =>
      Math.floor(Number(participantId)),
    );
    const nowMs = Date.now();
    const thresholdSessionAuthToken = String(serverBootstrap.jwt || '').trim();
    const ecdsaThresholdKeyId = String(args.walletKey.ecdsaThresholdKeyId || '').trim();
    const keyHandle = String(args.walletKey.keyHandle || serverBootstrap.keyHandle || '').trim();
    const signingRootId = String(
      args.walletKey.signingRootId || serverBootstrap.signingRootId || '',
    ).trim();
    const signingRootVersion = String(
      args.walletKey.signingRootVersion || serverBootstrap.signingRootVersion || '',
    ).trim();
    const thresholdEcdsaPublicKeyB64u = String(
      args.walletKey.thresholdEcdsaPublicKeyB64u ||
        serverBootstrap.thresholdEcdsaPublicKeyB64u ||
        '',
    ).trim();
    const ethereumAddress = String(
      args.walletKey.thresholdOwnerAddress || serverBootstrap.ethereumAddress || '',
    ).trim();
    const relayerKeyId = String(
      args.walletKey.relayerKeyId || serverBootstrap.relayerKeyId || '',
    ).trim();
    const relayerVerifyingShareB64u = String(
      args.walletKey.relayerVerifyingShareB64u || serverBootstrap.relayerVerifyingShareB64u || '',
    ).trim();
    const thresholdSessionId = String(serverBootstrap.sessionId || '').trim();
    const walletSigningSessionId = String(serverBootstrap.walletSigningSessionId || '').trim();
    const remainingUses = Math.max(0, Math.floor(Number(serverBootstrap.remainingUses)));
    const expiresAtMs = Math.max(0, Math.floor(Number(serverBootstrap.expiresAtMs)));
    if (
      !keyHandle ||
      !ecdsaThresholdKeyId ||
      !signingRootId ||
      !thresholdEcdsaPublicKeyB64u ||
      !ethereumAddress ||
      !relayerKeyId ||
      !relayerVerifyingShareB64u ||
      !thresholdSessionId ||
      !walletSigningSessionId ||
      !thresholdSessionAuthToken ||
      !participantIds.length ||
      participantIds.some(
        (participantId) => !Number.isSafeInteger(participantId) || participantId <= 0,
      ) ||
      !Number.isFinite(remainingUses) ||
      !Number.isFinite(expiresAtMs)
    ) {
      throw new Error('ECDSA registration bootstrap returned incomplete session material');
    }
    const keyRef: ThresholdEcdsaSecp256k1KeyRef = {
      type: 'threshold-ecdsa-secp256k1',
      userId: String(args.walletId),
      chainTarget: args.chainTarget,
      relayerUrl: args.relayerUrl,
      keyHandle,
      ecdsaThresholdKeyId,
      signingRootId,
      ...(signingRootVersion ? { signingRootVersion } : {}),
      backendBinding: {
        relayerKeyId,
        clientVerifyingShareB64u: localBootstrap.clientPublicKey33B64u,
        clientAdditiveShare32B64u: localBootstrap.clientShare32B64u,
        ecdsaHssRoleLocalClientState: {
          kind: 'role_local_ready',
          artifactKind: 'ecdsa-hss-role-local-client-state',
          contextBinding32B64u: localBootstrap.contextBinding32B64u,
          clientShare32B64u: localBootstrap.clientShare32B64u,
          clientPublicKey33B64u: localBootstrap.clientPublicKey33B64u,
          clientShareRetryCounter: localBootstrap.clientShareRetryCounter,
          relayerPublicKey33B64u: serverBootstrap.publicIdentity.relayerPublicKey33B64u,
          groupPublicKey33B64u: serverBootstrap.publicIdentity.groupPublicKey33B64u,
          ethereumAddress,
          clientCaitSithInput: localBootstrap.clientCaitSithInput,
          createdAtMs: nowMs,
          updatedAtMs: nowMs,
        },
      },
      participantIds,
      thresholdEcdsaPublicKeyB64u,
      ethereumAddress,
      relayerVerifyingShareB64u,
      thresholdSessionKind: 'jwt',
      thresholdSessionAuthToken,
      thresholdSessionId,
      walletSigningSessionId,
    };
    return {
      thresholdEcdsaKeyRef: keyRef,
      keygen: {
        ok: true,
        keygenSessionId: args.preparedClientBootstrap.clientBootstrap.requestId,
        rpId: serverBootstrap.rpId,
        keyHandle,
        ecdsaThresholdKeyId,
        clientVerifyingShareB64u: localBootstrap.clientPublicKey33B64u,
        clientAdditiveShare32B64u: localBootstrap.clientShare32B64u,
        thresholdEcdsaPublicKeyB64u,
        ethereumAddress,
        relayerKeyId,
        relayerVerifyingShareB64u,
        participantIds,
        ...(typeof args.chainTarget.chainId === 'number'
          ? { chainId: args.chainTarget.chainId }
          : {}),
      },
      session: {
        ok: true,
        sessionId: thresholdSessionId,
        walletSigningSessionId,
        expiresAtMs,
        remainingUses,
        jwt: thresholdSessionAuthToken,
      },
    };
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
    args: LoginWithEmailOtpEcdsaCapabilityInternalArgs,
  ): Promise<LoginWithEmailOtpEcdsaCapabilityInternalResult> {
    return await this.emailOtpPublic.loginWithEmailOtpEcdsaCapabilityInternal(args);
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
    return this.warmCapabilitiesPublic.listWarmThresholdEcdsaSessionStatuses(walletId, chainTarget);
  }

  async scheduleThresholdEcdsaLoginPresignPrefill(args: {
    walletId: WalletId;
    chainTarget: ThresholdEcdsaChainTarget;
    thresholdEcdsaSessionRecord: ThresholdEcdsaSessionRecord;
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
  ): ReturnType<
    ThresholdEd25519PublicApi['deriveThresholdEd25519ClientVerifyingShareFromCredential']
  > {
    return this.thresholdEd25519Public.deriveThresholdEd25519ClientVerifyingShareFromCredential(
      args,
    );
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
  ): ReturnType<
    ThresholdEd25519PublicApi['prepareThresholdEd25519HssClientCeremonyFromCredential']
  > {
    return this.thresholdEd25519Public.prepareThresholdEd25519HssClientCeremonyFromCredential(args);
  }

  prepareThresholdEd25519HssClientRequest(
    args: Parameters<ThresholdEd25519PublicApi['prepareThresholdEd25519HssClientRequest']>[0],
  ): ReturnType<ThresholdEd25519PublicApi['prepareThresholdEd25519HssClientRequest']> {
    return this.thresholdEd25519Public.prepareThresholdEd25519HssClientRequest(args);
  }

  deriveThresholdEd25519HssClientOutputMask(
    args: Parameters<ThresholdEd25519PublicApi['deriveThresholdEd25519HssClientOutputMask']>[0],
  ): ReturnType<ThresholdEd25519PublicApi['deriveThresholdEd25519HssClientOutputMask']> {
    return this.thresholdEd25519Public.deriveThresholdEd25519HssClientOutputMask(args);
  }

  buildThresholdEd25519HssClientOwnedStagedEvaluatorArtifact(
    args: Parameters<
      ThresholdEd25519PublicApi['buildThresholdEd25519HssClientOwnedStagedEvaluatorArtifact']
    >[0],
  ): ReturnType<
    ThresholdEd25519PublicApi['buildThresholdEd25519HssClientOwnedStagedEvaluatorArtifact']
  > {
    return this.thresholdEd25519Public.buildThresholdEd25519HssClientOwnedStagedEvaluatorArtifact(
      args,
    );
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
  | 'storeWalletSubjectEd25519RegistrationData'
  | 'storeWalletSubjectEd25519SignerRecord'
  | 'storeWalletSubjectEcdsaSignerRecords'
  | 'storeWalletSubjectEcdsaRegistrationData'
  | 'requestRegistrationCredentialConfirmation'
  | 'getAuthenticationCredentialsSerialized'
  | 'prepareWalletRegistrationEcdsaPreparedClientBootstrap'
  | 'prepareWalletRegistrationEcdsaClientBootstrap'
  | 'persistWalletRegistrationEcdsaBootstrapForWalletKeys'
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
  | 'deriveThresholdEd25519HssClientOutputMask'
  | 'buildThresholdEd25519HssClientOwnedStagedEvaluatorArtifact'
  | 'completeThresholdEd25519HssClientCeremony'
  | 'runThresholdEd25519HssCeremonyWithSession'
  | 'openThresholdEd25519HssSeedOutput'
  | 'buildThresholdEd25519SeedExportArtifactFromHssReport'
>;
