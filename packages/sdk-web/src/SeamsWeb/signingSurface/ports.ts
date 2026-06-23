import type { NonceCoordinator } from '@/core/signingEngine/nonce/NonceCoordinator';
import type {
  ThresholdEcdsaChainTarget,
  WalletId as EcdsaWalletId,
  WalletSessionRef,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type {
  ProvisionWarmEd25519CapabilityResult,
  WarmEcdsaSigningSessionStatus,
  WarmSessionEcdsaCapabilityState,
} from '@/core/signingEngine/session/warmCapabilities/types';
import type { RouterAbEcdsaHssLoginPresignaturePrefillResult } from '@/core/signingEngine/session/warmCapabilities/ecdsaLoginPrefill';
import type {
  AvailableSigningLanes,
  ListThresholdEcdsaSessionRecordsForWalletTargetInput,
  ReadAvailableSigningLanesInput,
  RestorePersistedSessionsForWalletInput,
  RestorePersistedSessionsForWalletResult,
  ThresholdEcdsaSessionRecord as SessionPublicThresholdEcdsaSessionRecord,
} from '@/core/signingEngine/session/public';
import type { ThresholdEcdsaSessionRecord } from '@/core/signingEngine/session/persistence/records';
import type {
  NearSignIntentRequest,
  NearSignIntentResult,
} from '@/core/signingEngine/flows/signNear/signNear';
import type {
  ReconcileTempoNonceLaneArgs as RuntimeReconcileTempoNonceLaneArgs,
  ReportTempoBroadcastAcceptedArgs as RuntimeReportTempoBroadcastAcceptedArgs,
  ReportTempoBroadcastRejectedArgs as RuntimeReportTempoBroadcastRejectedArgs,
  ReportTempoDroppedOrReplacedArgs as RuntimeReportTempoDroppedOrReplacedArgs,
  ReportTempoFinalizedArgs as RuntimeReportTempoFinalizedArgs,
  TempoNonceLaneStatus as RuntimeTempoNonceLaneStatus,
} from '@/core/signingEngine/flows/signEvmFamily/signEvmFamily';
import type { EvmSigningRequest } from '@/core/signingEngine/chains/evm/evmSigning.types';
import type { TempoSigningRequest } from '@/core/signingEngine/chains/tempo/tempoSigning.types';
import type { EvmSignedResult } from '@/core/signingEngine/chains/evm/evmAdapter';
import type { TempoSignedResult } from '@/core/signingEngine/chains/tempo/tempoAdapter';
import type {
  NearEphemeralKeypair,
  NearTransactionKeyPairSigningInput,
} from '@/core/signingEngine/useCases/nearKeyOperations';
import type { NearClient, SignedTransaction } from '@/core/rpcClients/near/NearClient';
import type { AccountId } from '@/core/types/accountIds';
import type {
  ClientAuthenticatorData,
  ClientUserData,
  StoreUserDataInput,
} from '@/core/accountData/near/nearAccountData.types';
import type { SeamsConfigsReadonly, SigningSessionStatus, ThemeName } from '@/core/types/seams';
import type { ConfirmationConfig } from '@/core/types/signer-worker';
import type {
  KeyExportEventCallback,
  SigningEngineExportKeypairWithUIInput,
} from '@/core/signingEngine/flows/recovery/public';
import type {
  StoreAuthenticatorInput,
  StoredRegistrationData,
  StoreWalletEcdsaRegistrationInput,
  StoreWalletEcdsaSignerRecordsInput,
  StoreWalletEcdsaSignerRecordsResult,
  StoreWalletEd25519RegistrationInput,
  StoreWalletEd25519SignerRecordInput,
  StoreWalletEmailOtpEd25519RegistrationInput,
  StoreWalletEmailOtpEcdsaRegistrationInput,
} from '@/core/signingEngine/flows/registration/accountLifecycle';
import type {
  EmailOtpWalletRegistrationEcdsaPreparedClientBootstrap,
  PasskeyWalletRegistrationEcdsaPreparedClientBootstrap,
  PrepareEmailOtpWalletRegistrationEcdsaClientBootstrapInput,
  PreparePasskeyWalletRegistrationEcdsaClientBootstrapInput,
} from '@/core/signingEngine/flows/registration/services/ecdsaRegistrationBootstrap';
import type { FinalizeWalletRegistrationEcdsaSessionsInput } from '@/core/signingEngine/flows/registration/services/ecdsaRegistrationSessions';
import type { ThresholdEcdsaSessionBootstrapResult } from '@/core/signingEngine/threshold/ecdsa/activation';
import type { EcdsaBootstrapRequest } from '@/core/signingEngine/session/passkey/ecdsaBootstrap';
import type { ConnectEd25519SessionArgs } from '@/core/signingEngine/session/passkey/public';
import type { HydrateWarmSigningSessionInput } from '@/core/signingEngine/session/passkey/warmSessionHydration';
import type { WarmSessionEd25519UnsealAuthorizationPutPayload } from '@/core/types/secure-confirm-worker';
import type { EmailOtpBootstrapRecovery } from '@/core/signingEngine/stepUpConfirmation/otpPrompt/bootstrapRecovery';
import type {
  EnrollAndLoginWithEmailOtpEcdsaCapabilityInternalArgs,
  EnrollAndLoginWithEmailOtpEcdsaCapabilityInternalResult,
  EnrollEmailOtpInternalArgs,
  EnrollEmailOtpInternalResult,
  LoginWithEmailOtpEd25519CapabilityInternalArgs,
  LoginWithEmailOtpEd25519CapabilityInternalResult,
  LoginWithEmailOtpEcdsaCapabilityInternalArgs,
  LoginWithEmailOtpEcdsaCapabilityInternalResult,
  PrepareEmailOtpRegistrationEnrollmentMaterialInternalArgs,
  PrepareEmailOtpRegistrationEnrollmentMaterialInternalResult,
  RotateEmailOtpRecoveryCodesInternalArgs,
  RotateEmailOtpRecoveryCodesInternalResult,
} from '@/core/signingEngine/flows/signEvmFamily/emailOtpPublic';
import type { WebAuthnAllowCredential } from '@/core/signingEngine/webauthnAuth/credentials/collectAuthenticationCredentialForChallengeB64u';
import type { RegistrationCredentialConfirmationPayload } from '@/core/signingEngine/workerManager/validation';
import type { RegistrationActivationProof } from '@/core/signingEngine/stepUpConfirmation/channel/confirmTypes';
import type { WebAuthnAuthenticationCredential } from '@/core/types';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import type {
  ThresholdEd25519HssFinalizedReportEnvelope,
  ThresholdEd25519HssPreparedSessionEnvelope,
} from '@/core/signingEngine/threshold/crypto/hssClientSignerWasm';
import type * as thresholdEd25519Public from '@/core/signingEngine/threshold/ed25519/public';
import type { SigningFlowEvent } from '@/core/types/sdkSentEvents';
import type {
  WorkerResourceWarmupAccountContext,
  WorkerResourceWarmupDiagnostics,
} from '@/core/signingEngine/assembly/warmup';

export interface RpIdSurface {
  getRpId(): string;
}

export interface SignerWorkerContextSurface {
  getSignerWorkerContext(): WorkerOperationContext;
}

export interface NonceCoordinatorSurface {
  getNonceCoordinator(): NonceCoordinator;
}

export interface NearSigningSurface extends NonceCoordinatorSurface {
  signNear<TRequest extends NearSignIntentRequest>(
    request: TRequest,
  ): Promise<NearSignIntentResult<TRequest>>;
  signTransactionWithKeyPair(input: NearTransactionKeyPairSigningInput): Promise<{
    signedTransaction: SignedTransaction;
    logs?: string[];
  }>;
  generateEphemeralNearKeypair(): Promise<NearEphemeralKeypair>;
}

export interface EvmFamilySigningSurface {
  signEvmFamily(args: {
    walletSession: WalletSessionRef;
    request: TempoSigningRequest | EvmSigningRequest;
    chainTarget: ThresholdEcdsaChainTarget;
    confirmationConfigOverride?: Partial<ConfirmationConfig>;
    shouldAbort?: () => boolean;
    onEvent?: (event: SigningFlowEvent) => void;
  }): Promise<TempoSignedResult | EvmSignedResult>;
}

export interface TempoNonceLifecycleSurface {
  reportTempoBroadcastAccepted(args: RuntimeReportTempoBroadcastAcceptedArgs): Promise<void>;
  reportTempoBroadcastRejected(args: RuntimeReportTempoBroadcastRejectedArgs): Promise<void>;
  reportTempoFinalized(args: RuntimeReportTempoFinalizedArgs): Promise<void>;
  reportTempoDroppedOrReplaced(args: RuntimeReportTempoDroppedOrReplacedArgs): Promise<void>;
  reconcileTempoNonceLane(
    args: RuntimeReconcileTempoNonceLaneArgs,
  ): Promise<RuntimeTempoNonceLaneStatus>;
}

export interface EcdsaSessionBootstrapSurface {
  bootstrapEcdsaSession(args: EcdsaBootstrapRequest): Promise<ThresholdEcdsaSessionBootstrapResult>;
}

export type TempoSigningSurface = EvmFamilySigningSurface &
  TempoNonceLifecycleSurface &
  EcdsaSessionBootstrapSurface;

export interface WalletIframeWarmupSurface {
  warmCriticalResources(
    accountContext?: WorkerResourceWarmupAccountContext,
  ): Promise<WorkerResourceWarmupDiagnostics>;
}

export interface RuntimeStartupSurface {
  assertSealedRefreshStartupParity(): Promise<void>;
}

export interface UserProfileStoreSurface {
  storeUserData(userData: StoreUserDataInput): Promise<void>;
  getAllUsers(): Promise<ClientUserData[]>;
  getUserBySignerSlot(nearAccountId: AccountId, signerSlot: number): Promise<ClientUserData | null>;
  getLastUser(): Promise<ClientUserData | null>;
  nearAuthenticatorsByAccount(nearAccountId: AccountId): Promise<ClientAuthenticatorData[]>;
  updateLastLogin(nearAccountId: AccountId): Promise<void>;
  setLastUser(nearAccountId: AccountId, signerSlot: number): Promise<void>;
}

export type UserAccountLookupSurface = Pick<
  UserProfileStoreSurface,
  'getUserBySignerSlot' | 'getLastUser' | 'nearAuthenticatorsByAccount'
>;

export interface EcdsaLoginSessionSurface {
  listThresholdEcdsaSessionRecordsForWalletTarget(
    args: ListThresholdEcdsaSessionRecordsForWalletTargetInput,
  ): SessionPublicThresholdEcdsaSessionRecord[];
  scheduleRouterAbEcdsaHssLoginPresignaturePrefill(args: {
    walletId: EcdsaWalletId;
    chainTarget: ThresholdEcdsaChainTarget;
    thresholdEcdsaSessionRecord: ThresholdEcdsaSessionRecord;
    minRemainingUsesBeforePrefill?: number;
  }): Promise<RouterAbEcdsaHssLoginPresignaturePrefillResult>;
}

export interface Ed25519SessionConnectionSurface {
  connectEd25519Session(
    args: ConnectEd25519SessionArgs,
  ): Promise<ProvisionWarmEd25519CapabilityResult>;
}

export type LoginWarmSigningSurface = RuntimeStartupSurface &
  EcdsaSessionBootstrapSurface &
  Ed25519SessionConnectionSurface &
  WorkerOperationContext &
  Pick<SigningSessionSurface, 'hydrateSigningSession' | 'putWarmSessionEd25519UnsealAuthorization'> &
  NonceCoordinatorSurface &
  RpIdSurface;

export interface RegistrationAccountSurface {
  activateAuthenticatedWalletState(args: {
    walletId: EcdsaWalletId;
    nearAccountId: AccountId;
    nearClient?: NearClient;
  }): Promise<void>;
  storeAuthenticator(authenticatorData: StoreAuthenticatorInput): Promise<void>;
  rollbackUserRegistration(nearAccountId: AccountId): Promise<void>;
  hasPasskeyCredential(nearAccountId: AccountId): Promise<boolean>;
  storeWalletEd25519RegistrationData(
    input: StoreWalletEd25519RegistrationInput,
  ): Promise<StoredRegistrationData>;
  storeWalletEmailOtpEd25519RegistrationData(
    input: StoreWalletEmailOtpEd25519RegistrationInput,
  ): Promise<StoredRegistrationData>;
  finalizeWalletEd25519SignerRegistration(
    input: StoreWalletEd25519SignerRecordInput,
  ): Promise<StoredRegistrationData>;
}

export interface EcdsaRegistrationSurface {
  preparePasskeyEcdsaBootstrap(
    input: PreparePasskeyWalletRegistrationEcdsaClientBootstrapInput,
  ): Promise<PasskeyWalletRegistrationEcdsaPreparedClientBootstrap>;
  prepareEmailOtpEcdsaBootstrap(
    input: PrepareEmailOtpWalletRegistrationEcdsaClientBootstrapInput,
  ): Promise<EmailOtpWalletRegistrationEcdsaPreparedClientBootstrap>;
  finalizeWalletRegistrationEcdsaSessions(
    input: FinalizeWalletRegistrationEcdsaSessionsInput,
  ): Promise<void>;
  storeWalletEcdsaSignerRecords(
    input: StoreWalletEcdsaSignerRecordsInput,
  ): Promise<StoreWalletEcdsaSignerRecordsResult>;
  storeWalletEmailOtpEcdsaSignerRecords(
    input: StoreWalletEcdsaSignerRecordsInput,
  ): Promise<StoreWalletEcdsaSignerRecordsResult>;
  finalizeWalletEcdsaRegistration(
    input: StoreWalletEcdsaRegistrationInput,
  ): Promise<StoreWalletEcdsaSignerRecordsResult>;
  storeWalletEmailOtpEcdsaRegistrationData(
    input: StoreWalletEmailOtpEcdsaRegistrationInput,
  ): Promise<StoreWalletEcdsaSignerRecordsResult>;
}

export interface SigningSessionSurface {
  hydrateSigningSession(input: HydrateWarmSigningSessionInput): Promise<void>;
  putWarmSessionEd25519UnsealAuthorization(
    input: WarmSessionEd25519UnsealAuthorizationPutPayload,
  ): Promise<void>;
  restorePersistedSessionsForWallet(
    args: RestorePersistedSessionsForWalletInput,
  ): Promise<RestorePersistedSessionsForWalletResult>;
  readPersistedAvailableSigningLanes(
    args: Omit<ReadAvailableSigningLanesInput, 'ecdsaChainTargets'>,
  ): Promise<AvailableSigningLanes>;
}

export interface WarmSessionStatusSurface {
  getWarmThresholdEd25519SessionStatus(
    nearAccountId: AccountId | string,
  ): Promise<SigningSessionStatus | null>;
  getWarmThresholdEcdsaSessionStatus(
    walletId: EcdsaWalletId,
    chainTarget: ThresholdEcdsaChainTarget,
    thresholdSessionId: string,
  ): Promise<WarmEcdsaSigningSessionStatus | null>;
  listWarmThresholdEcdsaSessionStatuses(
    walletId: EcdsaWalletId,
    chainTarget: ThresholdEcdsaChainTarget,
  ): Promise<WarmEcdsaSigningSessionStatus[]>;
}

export type WalletSessionReadSurface = RuntimeStartupSurface &
  NonceCoordinatorSurface &
  UserAccountLookupSurface &
  WarmSessionStatusSurface &
  Pick<SigningSessionSurface, 'readPersistedAvailableSigningLanes'> &
  Pick<EcdsaLoginSessionSurface, 'listThresholdEcdsaSessionRecordsForWalletTarget'>;

export type LoginUnlockSigningSurface = WalletSessionReadSurface &
  UserAccountLookupSurface &
  LoginWarmSigningSurface &
  EcdsaLoginSessionSurface &
  Pick<SigningSessionSurface, 'hydrateSigningSession'> &
  PasskeyLoginAssertionSurface &
  Pick<EcdsaSessionControlSurface, 'clearVolatileWarmSigningMaterial'> &
  Pick<UserProfileStoreSurface, 'setLastUser' | 'updateLastLogin'> &
  Pick<WarmSessionStatusSurface, 'getWarmThresholdEd25519SessionStatus'>;

export type RecentUnlocksSigningSurface = Pick<
  UserProfileStoreSurface,
  'getAllUsers' | 'getLastUser'
>;

export interface EcdsaSessionControlSurface {
  clearAllThresholdEcdsaSessionRecords(): void;
  clearVolatileWarmSigningMaterial(walletId?: EcdsaWalletId): Promise<void>;
  clearThresholdEcdsaCommitQueue(): void;
}

export type LockSigningSurface = NonceCoordinatorSurface & EcdsaSessionControlSurface;

export type LocalLoginStateSurface = WalletSessionReadSurface &
  Pick<
    UserProfileStoreSurface & RegistrationAccountSurface,
    'setLastUser' | 'updateLastLogin' | 'activateAuthenticatedWalletState'
  >;

export type AccountSyncSigningSurface = LocalLoginStateSurface &
  ThresholdEd25519HssClientSurface &
  ThresholdEd25519HssCeremonySurface &
  Pick<SigningSessionSurface, 'hydrateSigningSession'> &
  RpIdSurface &
  PasskeyLoginAssertionSurface &
  Pick<
    UserProfileStoreSurface & RegistrationAccountSurface,
    'storeUserData' | 'storeAuthenticator'
  >;

export interface WebAuthnRegistrationConfirmationSurface {
  requestRegistrationCredentialConfirmation(params: {
    walletId: string;
    nearAccountId?: string;
    signerSlot: number;
    confirmerText?: { title?: string; body?: string };
    confirmationConfigOverride?: Partial<ConfirmationConfig>;
    challengeB64u?: string;
    walletIframeActivation?: RegistrationActivationProof;
  }): Promise<RegistrationCredentialConfirmationPayload>;
}

export interface PasskeyLoginAssertionSurface {
  getAuthenticationCredentialsSerialized(args: {
    subjectId: string;
    challengeB64u: string;
    allowCredentials: WebAuthnAllowCredential[];
    includeSecondPrfOutput?: boolean;
  }): Promise<WebAuthnAuthenticationCredential>;
}

export interface WebAuthnAttestationSurface {
  extractCosePublicKey(attestationObjectBase64url: string): Promise<Uint8Array>;
}

export interface EmailOtpSigningSessionSurface {
  loginWithEmailOtpEcdsaCapabilityInternal(
    args: LoginWithEmailOtpEcdsaCapabilityInternalArgs,
  ): Promise<LoginWithEmailOtpEcdsaCapabilityInternalResult>;
  loginWithEmailOtpEd25519CapabilityInternal(
    args: LoginWithEmailOtpEd25519CapabilityInternalArgs,
  ): Promise<LoginWithEmailOtpEd25519CapabilityInternalResult>;
  requestEmailOtpSigningSessionChallenge(args: {
    walletSession: WalletSessionRef;
    chainTarget: ThresholdEcdsaChainTarget;
  }): Promise<{ challengeId: string; emailHint?: string }>;
  refreshEmailOtpSigningSession(args: {
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
  }>;
  resolveEmailOtpAppSessionJwt(args: {
    walletSession: WalletSessionRef;
    relayUrl: string;
  }): Promise<string>;
  enrollEmailOtpInternal(args: EnrollEmailOtpInternalArgs): Promise<EnrollEmailOtpInternalResult>;
  rotateEmailOtpRecoveryCodesInternal(
    args: RotateEmailOtpRecoveryCodesInternalArgs,
  ): Promise<RotateEmailOtpRecoveryCodesInternalResult>;
  enrollAndLoginWithEmailOtpEcdsaCapabilityInternal(
    args: EnrollAndLoginWithEmailOtpEcdsaCapabilityInternalArgs,
  ): Promise<EnrollAndLoginWithEmailOtpEcdsaCapabilityInternalResult>;
}

export interface KeyExportSigningSurface {
  exportKeypairWithUI(
    input: SigningEngineExportKeypairWithUIInput,
  ): Promise<{ accountId: string; exportedSchemes: Array<'ed25519' | 'secp256k1'> }>;
  exportNearEd25519SeedArtifactWithUI(args: {
    nearAccountId: AccountId;
    seedB64u: string;
    expectedPublicKey: string;
    options: {
      variant?: 'drawer' | 'modal';
      theme?: 'dark' | 'light';
    };
  }): Promise<{ accountId: string; exportedSchemes: Array<'ed25519' | 'secp256k1'> }>;
  exportThresholdEd25519SeedFromHssReport(args: {
    nearAccountId: AccountId;
    preparedSession: ThresholdEd25519HssPreparedSessionEnvelope;
    finalizedReport: ThresholdEd25519HssFinalizedReportEnvelope;
    expectedPublicKey: string;
    options: {
      variant?: 'drawer' | 'modal';
      theme?: 'dark' | 'light';
      onEvent?: KeyExportEventCallback;
    };
  }): Promise<{ accountId: string; exportedSchemes: Array<'ed25519' | 'secp256k1'> }>;
}

export interface ThresholdEd25519HssClientSurface {
  prepareThresholdEd25519HssClientCeremonyFromCredential(
    args: Parameters<
      typeof thresholdEd25519Public.prepareThresholdEd25519HssClientCeremonyFromCredential
    >[1],
  ): ReturnType<
    typeof thresholdEd25519Public.prepareThresholdEd25519HssClientCeremonyFromCredential
  >;
  prepareThresholdEd25519HssClientCeremonyFromPrfFirst(
    args: Parameters<
      typeof thresholdEd25519Public.prepareThresholdEd25519HssClientCeremonyFromPrfFirst
    >[1],
  ): ReturnType<typeof thresholdEd25519Public.prepareThresholdEd25519HssClientCeremonyFromPrfFirst>;
  prepareThresholdEd25519HssClientRequest(
    args: Parameters<typeof thresholdEd25519Public.prepareThresholdEd25519HssClientRequest>[1],
  ): ReturnType<typeof thresholdEd25519Public.prepareThresholdEd25519HssClientRequest>;
  prepareThresholdEd25519PasskeyPrfWorkerMaterialSealAuthorization(
    args: Parameters<
      typeof thresholdEd25519Public.prepareThresholdEd25519PasskeyPrfWorkerMaterialSealAuthorization
    >[1],
  ): ReturnType<
    typeof thresholdEd25519Public.prepareThresholdEd25519PasskeyPrfWorkerMaterialSealAuthorization
  >;
  prepareThresholdEd25519RecoveryCodeWorkerMaterialSealAuthorization(
    args: Parameters<
      typeof thresholdEd25519Public.prepareThresholdEd25519RecoveryCodeWorkerMaterialSealAuthorization
    >[1],
  ): ReturnType<
    typeof thresholdEd25519Public.prepareThresholdEd25519RecoveryCodeWorkerMaterialSealAuthorization
  >;
  deriveThresholdEd25519HssClientOutputMask(
    args: Parameters<typeof thresholdEd25519Public.deriveThresholdEd25519HssClientOutputMask>[1],
  ): ReturnType<typeof thresholdEd25519Public.deriveThresholdEd25519HssClientOutputMask>;
  deriveThresholdEd25519RoleSeparatedClientVerifyingShare(
    args: Parameters<
      typeof thresholdEd25519Public.deriveThresholdEd25519RoleSeparatedClientVerifyingShare
    >[1],
  ): ReturnType<
    typeof thresholdEd25519Public.deriveThresholdEd25519RoleSeparatedClientVerifyingShare
  >;
  buildThresholdEd25519HssClientOwnedStagedEvaluatorArtifact(
    args: Parameters<
      typeof thresholdEd25519Public.buildThresholdEd25519HssClientOwnedStagedEvaluatorArtifact
    >[1],
  ): ReturnType<
    typeof thresholdEd25519Public.buildThresholdEd25519HssClientOwnedStagedEvaluatorArtifact
  >;
}

export interface ThresholdEd25519HssCeremonySurface {
  runThresholdEd25519HssCeremonyWithSession(
    args: Parameters<typeof thresholdEd25519Public.runThresholdEd25519HssCeremonyWithSession>[1],
  ): ReturnType<typeof thresholdEd25519Public.runThresholdEd25519HssCeremonyWithSession>;
  runThresholdEd25519HssCeremonyWithMaterialHandle(
    args: Parameters<
      typeof thresholdEd25519Public.runThresholdEd25519HssCeremonyWithMaterialHandle
    >[1],
  ): ReturnType<typeof thresholdEd25519Public.runThresholdEd25519HssCeremonyWithMaterialHandle>;
}

export interface EmailOtpRegistrationEnrollmentSurface {
  prepareEmailOtpRegistrationEnrollmentMaterialInternal(
    args: PrepareEmailOtpRegistrationEnrollmentMaterialInternalArgs,
  ): Promise<PrepareEmailOtpRegistrationEnrollmentMaterialInternalResult>;
}

export type RegistrationSigningSurface = RpIdSurface &
  Pick<WalletIframeWarmupSurface, 'warmCriticalResources'> &
  Pick<SigningSessionSurface, 'readPersistedAvailableSigningLanes' | 'hydrateSigningSession'> &
  Pick<
    EmailOtpRegistrationEnrollmentSurface,
    'prepareEmailOtpRegistrationEnrollmentMaterialInternal'
  > &
  SignerWorkerContextSurface &
  PasskeyLoginAssertionSurface &
  Pick<UserProfileStoreSurface, 'getUserBySignerSlot'> &
  Pick<
    RegistrationAccountSurface,
    'storeWalletEd25519RegistrationData' | 'storeWalletEmailOtpEd25519RegistrationData'
  > &
  Pick<
    EcdsaRegistrationSurface,
    | 'storeWalletEcdsaSignerRecords'
    | 'storeWalletEmailOtpEcdsaSignerRecords'
    | 'storeWalletEmailOtpEcdsaRegistrationData'
  > &
  WebAuthnRegistrationConfirmationSurface &
  RegistrationAccountSurface &
  EcdsaRegistrationSurface &
  ThresholdEd25519HssClientSurface &
  ThresholdEd25519HssCeremonySurface;

export type SeamsWebBaseContext<TSigningEngine> = {
  signingEngine: TSigningEngine;
  nearClient: NearClient;
  configs: SeamsConfigsReadonly;
  theme: ThemeName;
};

export type RegistrationWebContext = SeamsWebBaseContext<RegistrationSigningSurface>;

export type NearSigningWebContext = SeamsWebBaseContext<
  NearSigningSurface & UserAccountLookupSurface & RpIdSurface
>;

export type WalletSessionWebContext = SeamsWebBaseContext<WalletSessionReadSurface>;

export type LoginWebContext = SeamsWebBaseContext<LoginUnlockSigningSurface>;

export type LockWebContext = SeamsWebBaseContext<LockSigningSurface>;

export type RecentUnlocksWebContext = SeamsWebBaseContext<RecentUnlocksSigningSurface>;

export type WalletAuthWebContext = SeamsWebBaseContext<
  LoginUnlockSigningSurface &
    LockSigningSurface &
    RecentUnlocksSigningSurface &
    RegistrationAccountSurface &
    EcdsaLoginSessionSurface
>;

export type LocalLoginStateWebContext = SeamsWebBaseContext<LocalLoginStateSurface>;

export type AccountSyncWebContext = SeamsWebBaseContext<AccountSyncSigningSurface>;

export type EmailRecoverySigningSurface = AccountSyncSigningSurface &
  WebAuthnRegistrationConfirmationSurface &
  WebAuthnAttestationSurface &
  Pick<EcdsaRegistrationSurface, 'preparePasskeyEcdsaBootstrap' | 'storeWalletEcdsaSignerRecords'>;

export type EmailRecoveryWebContext = SeamsWebBaseContext<EmailRecoverySigningSurface>;

export type DeviceLinkingSigningSurface = LocalLoginStateSurface &
  NearSigningSurface &
  ThresholdEd25519HssClientSurface &
  ThresholdEd25519HssCeremonySurface &
  Pick<SigningSessionSurface, 'hydrateSigningSession'> &
  RpIdSurface &
  WebAuthnRegistrationConfirmationSurface &
  WebAuthnAttestationSurface &
  Pick<
    UserProfileStoreSurface & RegistrationAccountSurface,
    'storeUserData' | 'storeAuthenticator'
  > &
  Pick<EcdsaRegistrationSurface, 'preparePasskeyEcdsaBootstrap' | 'storeWalletEcdsaSignerRecords'>;

export type DeviceLinkingWebContext = SeamsWebBaseContext<DeviceLinkingSigningSurface>;
