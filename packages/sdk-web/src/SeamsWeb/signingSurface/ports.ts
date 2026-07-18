import type { NonceCoordinator } from '@/core/signingEngine/nonce/NonceCoordinator';
import type { WalletId } from '@shared/utils/registrationIntent';
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
import type { RouterAbEcdsaDerivationLoginPresignaturePrefillResult } from '@/core/signingEngine/session/warmCapabilities/ecdsaLoginPrefill';
import type {
  AvailableSigningLanes,
  ListThresholdEcdsaSessionRecordsForWalletTargetInput,
  ReadAvailableSigningLanesInput,
  DiscoverPersistedSessionsForWalletInput,
  DiscoverPersistedSessionsForWalletResult,
  ThresholdEcdsaSessionRecord as SessionPublicThresholdEcdsaSessionRecord,
} from '@/core/signingEngine/session/public';
import type {
  ThresholdEcdsaSessionRecord,
  ThresholdEd25519SessionRecord,
} from '@/core/signingEngine/session/persistence/records';
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
import type { NearClient } from '@/core/rpcClients/near/NearClient';
import type { ProductEd25519YaoCapabilityActivationPortV1 } from '@/core/signingEngine/flows/registration/services/ed25519YaoRegistration';
import type { AccountId } from '@/core/types/accountIds';
import type {
  ClientAuthenticatorData,
  ClientUserData,
  StoreUserDataInput,
} from '@/core/accountData/near/nearAccountData.types';
import type { SeamsConfigsReadonly, SigningSessionStatus, ThemeMode } from '@/core/types/seams';
import type { ConfirmationConfig } from '@/core/types/signer-worker';
import type { WebAuthnRegistrationCredential } from '@/core/types/webauthn';
import type {
  RegistrationWebAuthnPromptOwner,
  ReservedRegistrationWebAuthnPrompt,
} from '@/core/signingEngine/stepUpConfirmation/passkeyPrompt/webauthnPromptCoordinator';
import type {
  SigningEngineResolveExactKeyExportLaneInput,
  SigningEngineResolveExactKeyExportLaneResult,
  SigningEngineExportKeypairWithUIInput,
} from '@/core/signingEngine/flows/recovery/public';
import type {
  StoreAuthenticatorInput,
  StoredRegistrationData,
  StoredWalletEd25519SignerRegistration,
  StoreWalletEcdsaRegistrationInput,
  StoreWalletEcdsaSignerRecordsInput,
  StoreWalletEcdsaSignerRecordsResult,
  StoreWalletEd25519RegistrationInput,
  StoreWalletEd25519SignerRecordInput,
  StoreWalletMixedRegistrationInput,
  StoreWalletMixedRegistrationResult,
  StoreWalletEmailOtpEd25519RegistrationInput,
  StoreWalletEmailOtpMixedRegistrationInput,
  StoreWalletEmailOtpMixedRegistrationResult,
  StoreWalletEmailOtpEcdsaRegistrationInput,
} from '@/core/signingEngine/flows/registration/accountLifecycle';
import type { StoreWalletSignerFinalizeRollbackReceipt } from '@/core/indexedDB/seamsWalletDB/repositories';
import type { FinalizeWalletRegistrationEcdsaSessionsInput } from '@/core/signingEngine/flows/registration/services/ecdsaRegistrationSessions';
import type {
  CloseRouterAbEcdsaRegistrationCeremonyRequestV1,
  CloseRouterAbEcdsaRegistrationCeremonyResultV1,
  CreateRouterAbEcdsaRegistrationCeremonyRequestV1,
  CreateRouterAbEcdsaRegistrationCeremonyResultV1,
  FinalizeRouterAbEcdsaRegistrationActivationRequestV1,
  FinalizeRouterAbEcdsaRegistrationActivationResultV1,
  VerifyRouterAbEcdsaRegistrationClientProofsRequestV1,
  VerifyRouterAbEcdsaRegistrationClientProofsResultV1,
} from '@/core/signingEngine/routerAb/ecdsaDerivation/clientCeremony';
import type { ThresholdEcdsaSessionBootstrapResult } from '@/core/signingEngine/threshold/ecdsa/activation';
import type { EcdsaBootstrapRequest } from '@/core/signingEngine/session/passkey/ecdsaBootstrap';
import type { ConnectEd25519SessionArgs } from '@/core/signingEngine/session/passkey/public';
import type { HydrateWarmSigningSessionInput } from '@/core/signingEngine/session/passkey/warmSessionHydration';
import type { EmailOtpBootstrapRecovery } from '@/core/signingEngine/stepUpConfirmation/otpPrompt/bootstrapRecovery';
import type { LoginWithEmailOtpEd25519YaoCapabilityInternalArgs } from '@/core/signingEngine/session/emailOtp/ed25519YaoLogin';
import type { PreparedColdEmailOtpEd25519YaoRecoveryV1 } from '@/core/signingEngine/session/emailOtp/ed25519YaoBudgetRecovery';
import type { EmailOtpEd25519YaoRecoveryBootstrapV1 } from '@/core/signingEngine/workerManager/workerTypes';
import type { EmailOtpEd25519YaoPendingFactorHandle } from '@/core/signingEngine/session/emailOtp/ed25519YaoRootVault';
import type { EmailOtpAppSessionBinding } from '@/core/signingEngine/session/emailOtp/appSessionJwtCache';
import type {
  EnrollAndLoginWithEmailOtpEcdsaCapabilityInternalArgs,
  EnrollAndLoginWithEmailOtpEcdsaCapabilityInternalResult,
  EnrollEmailOtpInternalArgs,
  EnrollEmailOtpInternalResult,
  LoginWithEmailOtpEcdsaCapabilityInternalArgs,
  LoginWithEmailOtpEcdsaCapabilityInternalResult,
  PrepareEmailOtpRegistrationEnrollmentMaterialInternalArgs,
  PrepareEmailOtpRegistrationEnrollmentMaterialInternalResult,
  RotateEmailOtpRecoveryCodesInternalArgs,
  RotateEmailOtpRecoveryCodesInternalResult,
} from '@/core/signingEngine/flows/signEvmFamily/emailOtpPublic';
import type { WebAuthnAllowCredential } from '@/core/signingEngine/webauthnAuth/credentials/collectAuthenticationCredentialForChallengeB64u';
import type { RegistrationCredentialConfirmationPayload } from '@/core/signingEngine/workerManager/validation';
import type { WebAuthnAuthenticationCredential } from '@/core/types';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import type {
  WarmSessionSealAndPersistResult,
  WarmSessionSealTransportInput,
} from '@/core/types/secure-confirm-worker';
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
  setLastUser(walletId: WalletId, signerSlot: number): Promise<void>;
}

export type UserAccountLookupSurface = Pick<
  UserProfileStoreSurface,
  'getUserBySignerSlot' | 'getLastUser' | 'nearAuthenticatorsByAccount'
>;

export interface EcdsaLoginSessionSurface {
  listThresholdEcdsaSessionRecordsForWalletTarget(
    args: ListThresholdEcdsaSessionRecordsForWalletTargetInput,
  ): SessionPublicThresholdEcdsaSessionRecord[];
  scheduleRouterAbEcdsaDerivationLoginPresignaturePrefill(args: {
    walletId: EcdsaWalletId;
    chainTarget: ThresholdEcdsaChainTarget;
    thresholdEcdsaSessionRecord: ThresholdEcdsaSessionRecord;
    minRemainingUsesBeforePrefill?: number;
  }): Promise<RouterAbEcdsaDerivationLoginPresignaturePrefillResult>;
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
  Pick<SigningSessionSurface, 'hydrateSigningSession'> &
  NonceCoordinatorSurface &
  RpIdSurface;

export interface RegistrationAccountSurface {
  activateAuthenticatedWalletState(args: {
    walletId: EcdsaWalletId;
    nearAccountId: AccountId;
    signerSlot: number;
    nearClient?: NearClient;
  }): Promise<void>;
  storeAuthenticator(authenticatorData: StoreAuthenticatorInput): Promise<void>;
  rollbackUserRegistration(nearAccountId: AccountId): Promise<void>;
  hasPasskeyCredential(nearAccountId: AccountId): Promise<boolean>;
  storeWalletEd25519RegistrationData(
    input: StoreWalletEd25519RegistrationInput,
  ): Promise<StoredRegistrationData>;
  storeWalletMixedRegistrationData(
    input: StoreWalletMixedRegistrationInput,
  ): Promise<StoreWalletMixedRegistrationResult>;
  storeWalletEd25519RecoveryRegistrationData(
    input: StoreWalletEd25519RegistrationInput,
  ): Promise<StoredRegistrationData>;
  storeWalletEmailOtpEd25519RegistrationData(
    input: StoreWalletEmailOtpEd25519RegistrationInput,
  ): Promise<StoredRegistrationData>;
  storeWalletEmailOtpMixedRegistrationData(
    input: StoreWalletEmailOtpMixedRegistrationInput,
  ): Promise<StoreWalletEmailOtpMixedRegistrationResult>;
  finalizeWalletEd25519SignerRegistration(
    input: StoreWalletEd25519SignerRecordInput,
  ): Promise<StoredWalletEd25519SignerRegistration>;
  rollbackWalletEd25519SignerRegistration(
    receipt: StoreWalletSignerFinalizeRollbackReceipt,
  ): Promise<void>;
}

export interface EcdsaRegistrationSurface {
  createRouterAbEcdsaRegistrationCeremony(
    input: CreateRouterAbEcdsaRegistrationCeremonyRequestV1,
  ): Promise<CreateRouterAbEcdsaRegistrationCeremonyResultV1>;
  verifyRouterAbEcdsaRegistrationClientProofs(
    input: VerifyRouterAbEcdsaRegistrationClientProofsRequestV1,
  ): Promise<VerifyRouterAbEcdsaRegistrationClientProofsResultV1>;
  finalizeRouterAbEcdsaRegistrationActivation(
    input: FinalizeRouterAbEcdsaRegistrationActivationRequestV1,
  ): Promise<FinalizeRouterAbEcdsaRegistrationActivationResultV1>;
  closeRouterAbEcdsaRegistrationCeremony(
    input: CloseRouterAbEcdsaRegistrationCeremonyRequestV1,
  ): Promise<CloseRouterAbEcdsaRegistrationCeremonyResultV1>;
  finalizeWalletRegistrationEcdsaSessions(
    input: FinalizeWalletRegistrationEcdsaSessionsInput,
  ): Promise<void>;
  storeWalletEcdsaSignerRecords(
    input: StoreWalletEcdsaSignerRecordsInput,
  ): Promise<StoreWalletEcdsaSignerRecordsResult>;
  storeWalletEcdsaRecoverySignerRecords(
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

export type Ed25519YaoRegistrationActivationSurface = ProductEd25519YaoCapabilityActivationPortV1;

export interface SigningSessionSurface {
  hydrateSigningSession(input: HydrateWarmSigningSessionInput): Promise<void>;
  persistSigningSessionSealForThresholdSession(input: {
    sessionId: string;
    transport?: WarmSessionSealTransportInput;
  }): Promise<WarmSessionSealAndPersistResult>;
  discoverPersistedSessionsForWallet(
    args: DiscoverPersistedSessionsForWalletInput,
  ): Promise<DiscoverPersistedSessionsForWalletResult>;
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
  Ed25519YaoRegistrationActivationSurface &
  EcdsaLoginSessionSurface &
  Pick<
    SigningSessionSurface,
    'hydrateSigningSession' | 'persistSigningSessionSealForThresholdSession'
  > &
  PasskeyLoginAssertionSurface &
  Pick<EcdsaSessionControlSurface, 'clearVolatileWarmSigningMaterial'> &
  Pick<UserProfileStoreSurface, 'setLastUser'> &
  Pick<WarmSessionStatusSurface, 'getWarmThresholdEd25519SessionStatus'>;

export type RecentUnlocksSigningSurface = Pick<
  UserProfileStoreSurface,
  'getAllUsers' | 'getLastUser'
>;

export interface EcdsaSessionControlSurface {
  clearAllThresholdEcdsaSessionRecords(): void;
  clearVolatileWarmSigningMaterial(walletId?: EcdsaWalletId): Promise<void>;
  clearThresholdEcdsaSigningQueue(): void;
}

export type LockSigningSurface = NonceCoordinatorSurface & EcdsaSessionControlSurface;

export type LocalLoginStateSurface = WalletSessionReadSurface &
  Pick<
    UserProfileStoreSurface & RegistrationAccountSurface,
    'setLastUser' | 'activateAuthenticatedWalletState'
  >;

export type AccountSyncSigningSurface = LocalLoginStateSurface &
  Ed25519YaoRegistrationActivationSurface &
  Pick<EcdsaSessionControlSurface, 'clearVolatileWarmSigningMaterial'> &
  Pick<
    SigningSessionSurface,
    'hydrateSigningSession' | 'persistSigningSessionSealForThresholdSession'
  > &
  RpIdSurface &
  PasskeyLoginAssertionSurface &
  Pick<
    UserProfileStoreSurface & RegistrationAccountSurface,
    'storeUserData' | 'storeAuthenticator'
  >;

export interface WebAuthnRegistrationConfirmationSurface {
  openRegistrationPreparationModal(params: {
    walletLabel: string;
    signerSlot: number;
  }): Promise<void>;
  closeRegistrationPreparationModal(): void;
  requestRegistrationCredentialConfirmation(params: {
    walletId: string;
    nearAccountId?: string;
    signerSlot: number;
    confirmerText?: { title?: string; body?: string };
    confirmationConfigOverride?: Partial<ConfirmationConfig>;
    challengeB64u?: string;
  }): Promise<RegistrationCredentialConfirmationPayload>;
  startPreparedPasskeyRegistrationCredential(args: {
    walletId: string;
    signerSlot: number;
    challengeB64u: string;
    expectedRpId: string;
    reservation: ReservedRegistrationWebAuthnPrompt;
    owner: RegistrationWebAuthnPromptOwner;
    cancellation: { kind: 'abort_signal'; signal: AbortSignal };
  }): Promise<WebAuthnRegistrationCredential>;
}

export interface PasskeyLoginAssertionSurface {
  getAuthenticationCredentialsSerialized(args: {
    subjectId: string;
    challengeB64u: string;
    allowCredentials: WebAuthnAllowCredential[];
    includeSecondPrfOutput?: boolean;
  }): Promise<WebAuthnAuthenticationCredential>;
}

export interface EmailOtpSigningSessionSurface {
  rememberEmailOtpAppSessionBinding(binding: EmailOtpAppSessionBinding): void;
  persistEmailOtpEd25519YaoSessionForRefreshInternal(
    record: ThresholdEd25519SessionRecord,
  ): Promise<void>;
  prepareEmailOtpEd25519YaoLoginRecoveryInternal(args: {
    walletSession: WalletSessionRef;
    remainingUses: number;
    emailHashHex: string;
  }): Promise<PreparedColdEmailOtpEd25519YaoRecoveryV1 | null>;
  activateEmailOtpEd25519YaoUnlockedRecoveryInternal(args: {
    prepared: PreparedColdEmailOtpEd25519YaoRecoveryV1;
    bootstrap: EmailOtpEd25519YaoRecoveryBootstrapV1;
    pendingFactorHandle: EmailOtpEd25519YaoPendingFactorHandle;
  }): Promise<ThresholdEd25519SessionRecord>;
  loginWithEmailOtpEd25519YaoCapabilityInternal(
    args: LoginWithEmailOtpEd25519YaoCapabilityInternalArgs,
  ): Promise<ThresholdEd25519SessionRecord>;
  loginWithEmailOtpEcdsaCapabilityInternal(
    args: LoginWithEmailOtpEcdsaCapabilityInternalArgs,
  ): Promise<LoginWithEmailOtpEcdsaCapabilityInternalResult>;
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
  resolveExactKeyExportLane(
    input: SigningEngineResolveExactKeyExportLaneInput,
  ): Promise<SigningEngineResolveExactKeyExportLaneResult>;
  exportKeypairWithUI(
    input: SigningEngineExportKeypairWithUIInput,
  ): Promise<{ accountId: string; exportedSchemes: Array<'ed25519' | 'secp256k1'> }>;
}

export interface EmailOtpRegistrationEnrollmentSurface {
  prepareEmailOtpRegistrationEnrollmentMaterialInternal(
    args: PrepareEmailOtpRegistrationEnrollmentMaterialInternalArgs,
  ): Promise<PrepareEmailOtpRegistrationEnrollmentMaterialInternalResult>;
}

export type RegistrationSigningSurface = RpIdSurface &
  Ed25519YaoRegistrationActivationSurface &
  Pick<WalletIframeWarmupSurface, 'warmCriticalResources'> &
  Pick<
    SigningSessionSurface,
    'hydrateSigningSession' | 'persistSigningSessionSealForThresholdSession'
  > &
  Pick<
    EmailOtpRegistrationEnrollmentSurface,
    'prepareEmailOtpRegistrationEnrollmentMaterialInternal'
  > &
  Pick<
    EmailOtpSigningSessionSurface,
    'rememberEmailOtpAppSessionBinding' | 'persistEmailOtpEd25519YaoSessionForRefreshInternal'
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
  EcdsaRegistrationSurface;

export type SeamsWebBaseContext<TSigningEngine> = {
  signingEngine: TSigningEngine;
  nearClient: NearClient;
  configs: SeamsConfigsReadonly;
  theme: ThemeMode;
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
  Ed25519YaoRegistrationActivationSurface &
  WebAuthnRegistrationConfirmationSurface &
  Pick<RegistrationAccountSurface, 'storeWalletEd25519RecoveryRegistrationData'> &
  Pick<EcdsaRegistrationSurface, 'storeWalletEcdsaRecoverySignerRecords'>;

export type EmailRecoveryWebContext = SeamsWebBaseContext<EmailRecoverySigningSurface>;

export type DeviceLinkingSigningSurface = LocalLoginStateSurface &
  NearSigningSurface &
  Pick<SigningSessionSurface, 'hydrateSigningSession'> &
  RpIdSurface &
  WebAuthnRegistrationConfirmationSurface &
  Pick<
    UserProfileStoreSurface & RegistrationAccountSurface,
    'storeUserData' | 'storeAuthenticator'
  > &
  Pick<EcdsaRegistrationSurface, 'storeWalletEcdsaSignerRecords'>;

export type DeviceLinkingWebContext = SeamsWebBaseContext<DeviceLinkingSigningSurface>;
