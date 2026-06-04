import type { SigningRuntime } from '@/core/runtime/types';
import type { NonceCoordinator } from '@/core/signingEngine/nonce/NonceCoordinator';
import type {
  NearAccountRef,
  ThresholdEcdsaChainTarget,
  WalletId as EcdsaWalletId,
  WalletSessionRef,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdRuntimePolicyScope } from '@/core/signingEngine/threshold/sessionPolicy';
import type {
  ProvisionWarmEd25519CapabilityResult,
  WarmEcdsaSigningSessionStatus,
  WarmSessionEcdsaCapabilityState,
} from '@/core/signingEngine/session/warmCapabilities/types';
import type { ThresholdEcdsaLoginPrefillResult } from '@/core/signingEngine/session/warmCapabilities/ecdsaLoginPrefill';
import type { NearClient, SignedTransaction } from '@/core/rpcClients/near/NearClient';
import type {
  ActionResult,
  DelegateRelayResult,
  EmailOtpAuthPolicy,
  GetRecentUnlocksResult,
  LoginAndCreateSessionResult,
  WalletSession,
  RegistrationResult,
  SignAndSendDelegateActionResult,
  SignDelegateActionResult,
  SigningSessionStatus,
  SignTransactionResult,
  ThemeName,
  SeamsConfigsReadonly,
} from '@/core/types/seams';
import type {
  ActionHooksOptions,
  DelegateActionHooksOptions,
  DelegateRelayHooksOptions,
  KeyExportHooksOptions,
  LoginHooksOptions,
  RegistrationHooksOptions,
  RegistrationFlowEvent,
  SendTransactionHooksOptions,
  SignAndSendDelegateActionHooksOptions,
  SignAndSendTransactionHooksOptions,
  SignNEP413HooksOptions,
  SignTransactionHooksOptions,
  SigningFlowEvent,
  SyncAccountHooksOptions,
  UnlockFlowEvent,
} from '@/core/types/sdkSentEvents';
import type {
  ConfirmationBehavior,
  ConfirmationConfig,
  WasmSignedDelegate,
} from '@/core/types/signer-worker';
import type { WebAuthnAuthenticationCredential } from '@/core/types';
import type {
  ThresholdEd25519HssFinalizedReportEnvelope,
  ThresholdEd25519HssPreparedSessionEnvelope,
} from '@/core/signingEngine/threshold/crypto/hssClientSignerWasm';
import type { AccountId } from '@/core/types/accountIds';
import type { ActionArgs, TransactionInput } from '@/core/types/actions';
import type { DelegateActionInput, SignedDelegate } from '@/core/types/delegate';
import type { MultichainSigningRequest } from '@/core/signingEngine/chains/tempo/types';
import type { EvmSignedResult } from '@/core/signingEngine/chains/evm/evmAdapter';
import type { TempoSignedResult } from '@/core/signingEngine/chains/tempo/tempoAdapter';
import type { SignNEP413MessageParams, SignNEP413MessageResult } from './near/signNEP413';
import type { SyncAccountResult } from './syncAccount';
import type { EmailRecoveryFlowOptions } from '@/core/types/emailRecovery';
import type { UserPreferencesManager } from '@/core/signingEngine/session/userPreferences';
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
import type { EvmSigningRequest } from '@/core/signingEngine/chains/evm/types';
import type { TempoSigningRequest } from '@/core/signingEngine/chains/tempo/types';
import type { WebAuthnAllowCredential } from '@/core/signingEngine/webauthnAuth/credentials/collectAuthenticationCredentialForChallengeB64u';
import type { RegistrationCredentialConfirmationPayload } from '@/core/signingEngine/workerManager/validation';
import type {
  KeyExportEventCallback,
  SigningEngineExportKeypairWithUIInput,
} from '@/core/signingEngine/flows/recovery/public';
import type { ThresholdEcdsaSessionBootstrapResult } from '@/core/signingEngine/threshold/ecdsa/activation';
import type { EcdsaBootstrapRequest } from '@/core/signingEngine/session/passkey/ecdsaBootstrap';
import type { ConnectEd25519SessionArgs } from '@/core/signingEngine/session/passkey/public';
import type { EmailOtpBootstrapRecovery } from '@/core/signingEngine/stepUpConfirmation/otpPrompt/bootstrapRecovery';
import type {
  EnrollAndLoginWithEmailOtpEcdsaCapabilityInternalArgs,
  EnrollAndLoginWithEmailOtpEcdsaCapabilityInternalResult,
  EnrollEmailOtpInternalArgs,
  EnrollEmailOtpInternalResult,
  LoginWithEmailOtpEcdsaCapabilityInternalArgs,
  LoginWithEmailOtpEcdsaCapabilityInternalResult,
  PrepareEmailOtpRegistrationEnrollmentMaterialInternalArgs,
  PrepareEmailOtpRegistrationEnrollmentMaterialInternalResult,
} from '@/core/signingEngine/flows/signEvmFamily/emailOtpPublic';
import type * as thresholdEd25519Public from '@/core/signingEngine/threshold/ed25519/public';
import type {
  DeviceLinkingQRData,
  LinkDeviceResult,
  ScanAndLinkDeviceOptionsDevice1,
  StartDevice2LinkingFlowArgs,
  StartDevice2LinkingFlowResults,
} from '@/core/types/linkDevice';
import type { WebAuthnRegistrationCredential } from '@/core/types/webauthn';
import type {
  WalletEmailOtpChannel,
  WalletEmailOtpLoginOperation,
} from '@shared/utils/emailOtpDomain';
import type {
  AddSignerSelection,
  RegistrationAuthMethodInput,
  RegisterWalletInput,
  RegistrationSignerSelection,
  WalletId,
} from '@shared/utils/registrationIntent';

type PublicThresholdEcdsaSessionKeyRef = Omit<
  ThresholdEcdsaSessionBootstrapResult['thresholdEcdsaKeyRef'],
  'ecdsaThresholdKeyId' | 'signingRootId' | 'signingRootVersion' | 'ecdsaHssExportArtifact'
>;

export type PublicThresholdEcdsaSessionBootstrapResult = Omit<
  ThresholdEcdsaSessionBootstrapResult,
  'thresholdEcdsaKeyRef'
> & {
  thresholdEcdsaKeyRef: PublicThresholdEcdsaSessionKeyRef;
};

export type SignTempoArgs = {
  walletSession: WalletSessionRef;
  request: MultichainSigningRequest;
  chainTarget: ThresholdEcdsaChainTarget;
  options?: {
    confirmationConfig?: Partial<ConfirmationConfig>;
    /** Internal host-only cancellation probe; ignored in wallet-router calls. */
    shouldAbort?: () => boolean;
    onEvent?: (event: SigningFlowEvent) => void;
  };
};

export type RegisterNearWalletArgs = {
  nearAccountId: string;
  authMethod?: RegistrationAuthMethodInput;
  options?: RegistrationHooksOptions;
};

export type RegisterEvmWalletArgs = {
  chainTargets: readonly ThresholdEcdsaChainTarget[];
  participantIds: readonly number[];
  authMethod?: RegistrationAuthMethodInput;
  options?: RegistrationHooksOptions;
};

export type TempoNonceLifecycleEvent = SigningFlowEvent;

export type TempoNonceLifecycleOptions = {
  onEvent?: (event: TempoNonceLifecycleEvent) => void;
};

type ReportTempoNonceLifecycleBaseArgs = {
  walletSession: WalletSessionRef;
  signedResult: TempoSignedResult | EvmSignedResult;
  options?: TempoNonceLifecycleOptions;
};

export type ReportTempoBroadcastAcceptedArgs = ReportTempoNonceLifecycleBaseArgs & {
  txHash?: `0x${string}`;
};

export type ReportTempoBroadcastRejectedArgs = ReportTempoNonceLifecycleBaseArgs & {
  error?: unknown;
};

export type ReportTempoFinalizedArgs = ReportTempoNonceLifecycleBaseArgs & {
  txHash?: `0x${string}`;
  receiptStatus?: 'success' | 'reverted';
};

export type ReportTempoDroppedOrReplacedArgs = ReportTempoNonceLifecycleBaseArgs & {
  reason: 'dropped' | 'replaced';
  txHash?: `0x${string}`;
};

export type ReconcileTempoNonceLaneArgs = ReportTempoNonceLifecycleBaseArgs;

export type TempoNonceLaneStatus = {
  chainNextNonce: string;
  unresolvedInFlightNonces: string[];
  blocked: boolean;
  blockedNonce?: string;
};

export type FinalizedEvmTxPayloadVerification = {
  verified: boolean;
  reason: 'matched' | 'tx_unavailable' | 'mismatch';
  observedTo?: string | null;
  observedInput?: string | null;
};

export type ExecuteEvmFamilyTransactionArgs = {
  walletSession: WalletSessionRef;
  request: MultichainSigningRequest;
  chainTarget: ThresholdEcdsaChainTarget;
  payloadExpectation?: {
    to?: `0x${string}`;
    input?: `0x${string}`;
  };
  postFinalizationCheck?: () => Promise<void>;
  finalization?: {
    timeoutMs?: number;
    pollIntervalMs?: number;
    confirmations?: number;
  };
  options?: {
    confirmationConfig?: Partial<ConfirmationConfig>;
    /** Internal host-only cancellation probe; ignored in wallet-router calls. */
    shouldAbort?: () => boolean;
    onEvent?: (event: TempoNonceLifecycleEvent) => void;
  };
};

export type ExecuteEvmFamilyTransactionResult = {
  txHash: `0x${string}`;
  signedResult: TempoSignedResult | EvmSignedResult;
  payloadVerification: FinalizedEvmTxPayloadVerification;
};

export type BootstrapThresholdEcdsaSessionArgs = {
  walletSession: WalletSessionRef;
  chainTarget: ThresholdEcdsaChainTarget;
  relayerUrl?: string;
  runtimeScopeBootstrap?: {
    environmentId: string;
    publishableKey: string;
  };
  ttlMs?: number;
  remainingUses?: number;
  kind: 'reuse_warm_ecdsa_bootstrap';
  source?: 'login' | 'registration' | 'manual-bootstrap' | 'email_otp';
  ecdsaThresholdKeyId?: never;
  participantIds?: never;
  sessionKind?: never;
  sessionIdentity?: never;
  routeAuth?: never;
  webauthnAuthentication?: never;
  passkeyPrfFirstB64u?: never;
  emailOtpAuthContext?: never;
};

export type EmailOtpChallengeResult = {
  challengeId: string;
  otpChannel: WalletEmailOtpChannel;
  emailHint?: string;
  expiresAtMs?: number;
  appSessionVersion?: string;
};

export type EmailOtpEnrollmentResult = {
  thresholdEcdsaClientVerifyingShareB64u: string;
  recoveryKeys: string[];
  challengeId: string;
  otpChannel: WalletEmailOtpChannel;
  enrollmentSealKeyVersion: string;
  clientUnlockPublicKeyB64u: string;
  unlockKeyVersion: string;
};

export type EmailOtpDeviceEnrollmentRestoreResult = {
  walletId: string;
  userId: string;
  authSubjectId: string;
  enrollmentId: string;
  enrollmentVersion: string;
  enrollmentSealKeyVersion: string;
  recoveryKeyId: string;
  activeRecoveryWrappedEnrollmentEscrowCount: number;
};

export type EmailOtpDeviceEnrollmentRemoveResult = {
  walletId: string;
  authSubjectId: string;
  enrollmentId: string;
  removed: true;
};

export type GoogleEmailOtpSessionExchangeResult = {
  jwt?: string;
  session: {
    userId: string;
    walletId: string;
    email?: string;
    name?: string;
    googleEmailOtpResolution?: {
      mode: 'existing_wallet' | 'register_started';
      registrationAttemptId?: string;
      expiresAt?: string;
    };
    runtimePolicyScope?: ThresholdRuntimePolicyScope;
  };
};

export type EmailOtpEcdsaCapabilityArgs = {
  walletSession: WalletSessionRef;
  chainTarget: ThresholdEcdsaChainTarget;
  emailOtpAuthPolicy?: EmailOtpAuthPolicy;
  relayUrl?: string;
  challengeId?: string;
  otpCode: string;
  shamirPrimeB64u?: string;
  appSessionJwt?: string;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  registrationAttemptId?: string;
  onEvent?: (event: UnlockFlowEvent) => void;
};

export type EmailOtpEcdsaCapabilityResult = {
  recovery: EmailOtpBootstrapRecovery;
  bootstrap: PublicThresholdEcdsaSessionBootstrapResult;
  warmCapability: WarmSessionEcdsaCapabilityState;
};

export type EmailOtpEcdsaEnrollmentCapabilityArgs = Omit<EmailOtpEcdsaCapabilityArgs, 'onEvent'> & {
  clientSecret32?: Uint8Array;
  onEvent?: (event: RegistrationFlowEvent | UnlockFlowEvent) => void;
};

export type EmailOtpEcdsaEnrollmentCapabilityResult = {
  enrollment: EmailOtpEnrollmentResult;
  bootstrap: PublicThresholdEcdsaSessionBootstrapResult;
  warmCapability: WarmSessionEcdsaCapabilityState;
};

export interface AuthCapability {
  unlock(nearAccountId: string, options?: LoginHooksOptions): Promise<LoginAndCreateSessionResult>;
  lock(): Promise<void>;
  getWalletSession(walletId?: string): Promise<WalletSession>;
  getRecentUnlocks(): Promise<GetRecentUnlocksResult>;
  hasPasskeyCredential(nearAccountId: AccountId): Promise<boolean>;
  prefillThresholdEcdsaPresignPool(args: {
    walletSession: WalletSessionRef;
    chainTarget: ThresholdEcdsaChainTarget;
    waitForPoolReady?: boolean;
    poolReadyTimeoutMs?: number;
    poolReadyPollIntervalMs?: number;
    minRemainingUsesBeforePrefill?: number;
  }): Promise<ThresholdEcdsaLoginPrefillResult>;
  requestEmailOtpChallenge(args: {
    nearAccountId: string;
    relayUrl?: string;
    appSessionJwt?: string;
    operation?: WalletEmailOtpLoginOperation;
    onEvent?: (event: UnlockFlowEvent) => void;
  }): Promise<EmailOtpChallengeResult>;
  requestEmailOtpEnrollmentChallenge(args: {
    nearAccountId: string;
    relayUrl?: string;
    appSessionJwt?: string;
    onEvent?: (event: RegistrationFlowEvent) => void;
  }): Promise<EmailOtpChallengeResult>;
  requestEmailOtpSigningSessionChallenge(args: {
    walletSession: WalletSessionRef;
    chainTarget: ThresholdEcdsaChainTarget;
    onEvent?: (event: UnlockFlowEvent) => void;
  }): Promise<Pick<EmailOtpChallengeResult, 'challengeId' | 'emailHint'>>;
  refreshEmailOtpSigningSession(args: {
    walletSession: WalletSessionRef;
    chainTarget: ThresholdEcdsaChainTarget;
    challengeId: string;
    otpCode: string;
    ttlMs?: number;
    remainingUses?: number;
    onEvent?: (event: UnlockFlowEvent) => void;
  }): Promise<EmailOtpEcdsaCapabilityResult>;
  exchangeGoogleEmailOtpSession(args: {
    idToken: string;
    accountMode: 'register' | 'login';
    relayUrl?: string;
    sessionKind?: 'jwt' | 'cookie';
    rerollRegistrationAttempt?: boolean;
    onEvent?: (event: RegistrationFlowEvent | UnlockFlowEvent) => void;
  }): Promise<GoogleEmailOtpSessionExchangeResult>;
  enrollEmailOtp(args: {
    nearAccountId: string;
    otpCode: string;
    relayUrl?: string;
    challengeId?: string;
    shamirPrimeB64u?: string;
    appSessionJwt?: string;
    clientSecret32?: Uint8Array;
    onEvent?: (event: RegistrationFlowEvent) => void;
  }): Promise<EmailOtpEnrollmentResult>;
  loginWithEmailOtpEcdsaCapability(
    args: EmailOtpEcdsaCapabilityArgs,
  ): Promise<EmailOtpEcdsaCapabilityResult>;
  enrollAndLoginWithEmailOtpEcdsaCapability(
    args: EmailOtpEcdsaEnrollmentCapabilityArgs,
  ): Promise<EmailOtpEcdsaEnrollmentCapabilityResult>;
}

export interface RegistrationCapability {
  addWalletSigner(args: {
    walletId: WalletId | string;
    rpId: string;
    signerSelection: AddSignerSelection;
    options?: RegistrationHooksOptions;
  }): Promise<RegistrationResult>;
  registerWallet(args: {
    authMethod: RegistrationAuthMethodInput;
    wallet: RegisterWalletInput;
    rpId: string;
    signerSelection: RegistrationSignerSelection;
    options?: RegistrationHooksOptions;
  }): Promise<RegistrationResult>;
  registerWithEmailOtp(args: {
    authMethod: Extract<RegistrationAuthMethodInput, { kind: 'email_otp' }>;
    wallet: RegisterWalletInput;
    rpId: string;
    signerSelection: RegistrationSignerSelection;
    options?: RegistrationHooksOptions;
  }): Promise<RegistrationResult>;
  registerPasskey(
    nearAccountId: string,
    options?: RegistrationHooksOptions,
  ): Promise<RegistrationResult>;
  registerPasskeyInternal(
    nearAccountId: string,
    options?: RegistrationHooksOptions,
    confirmationConfigOverride?: ConfirmationConfig,
  ): Promise<RegistrationResult>;
}

export interface NearSignerCapability {
  registerNearWallet(args: RegisterNearWalletArgs): Promise<RegistrationResult>;

  executeAction(args: {
    nearAccount: NearAccountRef;
    receiverId: string;
    actionArgs: ActionArgs | ActionArgs[];
    options: ActionHooksOptions;
  }): Promise<ActionResult>;

  signAndSendTransactions(args: {
    nearAccount: NearAccountRef;
    transactions: TransactionInput[];
    options: SignAndSendTransactionHooksOptions;
  }): Promise<ActionResult[]>;

  signAndSendTransaction(args: {
    nearAccount: NearAccountRef;
    receiverId: string;
    actions: ActionArgs[];
    options: SignAndSendTransactionHooksOptions;
  }): Promise<ActionResult>;

  signTransactionsWithActions(args: {
    nearAccount: NearAccountRef;
    transactions: TransactionInput[];
    options: SignTransactionHooksOptions;
  }): Promise<SignTransactionResult[]>;

  sendTransaction(args: {
    signedTransaction: SignedTransaction;
    options?: SendTransactionHooksOptions;
  }): Promise<ActionResult>;

  signDelegateAction(args: {
    nearAccount: NearAccountRef;
    delegate: DelegateActionInput;
    options: DelegateActionHooksOptions;
  }): Promise<SignDelegateActionResult>;

  sendDelegateActionViaRelayer(args: {
    relayerUrl: string;
    signedDelegate: SignedDelegate | WasmSignedDelegate;
    hash: string;
    signal?: AbortSignal;
    options?: DelegateRelayHooksOptions;
  }): Promise<DelegateRelayResult>;

  signAndSendDelegateAction(args: {
    nearAccount: NearAccountRef;
    delegate: DelegateActionInput;
    relayerUrl: string;
    signal?: AbortSignal;
    options: SignAndSendDelegateActionHooksOptions;
  }): Promise<SignAndSendDelegateActionResult>;

  signNEP413Message(args: {
    nearAccount: NearAccountRef;
    params: SignNEP413MessageParams;
    options: SignNEP413HooksOptions;
  }): Promise<SignNEP413MessageResult>;
}

export interface TempoSignerCapability {
  signTempo(args: SignTempoArgs): Promise<TempoSignedResult | EvmSignedResult>;
  executeEvmFamilyTransaction(
    args: ExecuteEvmFamilyTransactionArgs,
  ): Promise<ExecuteEvmFamilyTransactionResult>;
  reportBroadcastAccepted(args: ReportTempoBroadcastAcceptedArgs): Promise<void>;
  reportBroadcastRejected(args: ReportTempoBroadcastRejectedArgs): Promise<void>;
  reportFinalized(args: ReportTempoFinalizedArgs): Promise<void>;
  reportDroppedOrReplaced(args: ReportTempoDroppedOrReplacedArgs): Promise<void>;
  reconcileNonceLane(args: ReconcileTempoNonceLaneArgs): Promise<TempoNonceLaneStatus>;
  bootstrapEcdsaSession(
    args: BootstrapThresholdEcdsaSessionArgs,
  ): Promise<PublicThresholdEcdsaSessionBootstrapResult>;
}

export interface EvmSignerCapability {
  registerEvmWallet(args: RegisterEvmWalletArgs): Promise<RegistrationResult>;

  bootstrapEcdsaSession(
    args: BootstrapThresholdEcdsaSessionArgs,
  ): Promise<PublicThresholdEcdsaSessionBootstrapResult>;
}

export interface RecoveryCapability {
  getRecoveryEmails(accountId: string): Promise<Array<{ hashHex: string; email: string }>>;

  setRecoveryEmails(args: {
    accountId: string;
    recoveryEmails: string[];
    options: ActionHooksOptions;
  }): Promise<ActionResult>;

  syncAccount(args: {
    accountId?: string;
    options?: SyncAccountHooksOptions;
  }): Promise<SyncAccountResult>;

  startEmailRecovery(args: {
    accountId: string;
    options?: EmailRecoveryFlowOptions;
  }): Promise<{ mailtoUrl: string; nearPublicKey: string }>;

  finalizeEmailRecovery(args: {
    accountId: string;
    nearPublicKey?: string;
    options?: EmailRecoveryFlowOptions;
  }): Promise<void>;

  cancelEmailRecovery(args?: { accountId?: string; nearPublicKey?: string }): Promise<void>;
  startDevice2LinkingFlow(
    args: StartDevice2LinkingFlowArgs,
  ): Promise<StartDevice2LinkingFlowResults>;

  stopDevice2LinkingFlow(): Promise<void>;

  linkDeviceWithScannedQRData(
    qrData: DeviceLinkingQRData,
    options: ScanAndLinkDeviceOptionsDevice1,
  ): Promise<LinkDeviceResult>;
}

export type ThresholdEd25519SeedExportUiOptions = {
  variant?: 'drawer' | 'modal';
  theme?: 'dark' | 'light';
  onEvent?: KeyExportHooksOptions['onEvent'];
};

export type ExportKeypairWithUIInput =
  | {
      kind: 'near';
      nearAccount: NearAccountRef;
      options: ThresholdEd25519SeedExportUiOptions & {
        chain: 'near';
      };
    }
  | {
      kind: 'ecdsa';
      chainTarget: ThresholdEcdsaChainTarget;
      walletSession: WalletSessionRef;
      options: ThresholdEd25519SeedExportUiOptions;
    };

export interface KeyExportCapability {
  exportKeypairWithUI(input: ExportKeypairWithUIInput): Promise<void>;
  exportThresholdEd25519SeedFromHssReport(args: {
    nearAccountId: string;
    preparedSession: ThresholdEd25519HssPreparedSessionEnvelope;
    finalizedReport: ThresholdEd25519HssFinalizedReportEnvelope;
    expectedPublicKey: string;
    options: ThresholdEd25519SeedExportUiOptions;
  }): Promise<void>;
}

export interface PreferencesCapability {
  setCurrentWallet(walletId: WalletId): void;
  getCurrentWalletId(): WalletId | null;
  onConfirmationConfigChange(callback: (config: ConfirmationConfig) => void): () => void;
  onCurrentWalletChange(callback: (walletId: WalletId | null) => void): () => void;
  setConfirmBehavior(behavior: ConfirmationBehavior): void;
  setConfirmationConfig(config: ConfirmationConfig): void;
  getConfirmationConfig(): ConfirmationConfig;
}

export interface SeamsWebSigningSurface {
  readonly seamsWebConfigs: SeamsConfigsReadonly;
  readonly signingRuntime: SigningRuntime;
  setTheme(next: ThemeName): void;
  getUserPreferences(): UserPreferencesManager;
  getRpId(): string;
  getNonceCoordinator(): NonceCoordinator;
  warmCriticalResources(nearAccountId?: string): Promise<void>;
  assertSealedRefreshStartupParity(): Promise<void>;
  restorePersistedSessionsForWallet(
    args: RestorePersistedSessionsForWalletInput,
  ): Promise<RestorePersistedSessionsForWalletResult>;
  readPersistedAvailableSigningLanes(
    args: Omit<ReadAvailableSigningLanesInput, 'ecdsaChainTargets'>,
  ): Promise<AvailableSigningLanes>;
  connectEd25519Session(
    args: ConnectEd25519SessionArgs,
  ): Promise<ProvisionWarmEd25519CapabilityResult>;
  bootstrapEcdsaSession(args: EcdsaBootstrapRequest): Promise<ThresholdEcdsaSessionBootstrapResult>;
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
  enrollEmailOtpInternal(args: EnrollEmailOtpInternalArgs): Promise<EnrollEmailOtpInternalResult>;
  prepareEmailOtpRegistrationEnrollmentMaterialInternal(
    args: PrepareEmailOtpRegistrationEnrollmentMaterialInternalArgs,
  ): Promise<PrepareEmailOtpRegistrationEnrollmentMaterialInternalResult>;
  enrollAndLoginWithEmailOtpEcdsaCapabilityInternal(
    args: EnrollAndLoginWithEmailOtpEcdsaCapabilityInternalArgs,
  ): Promise<EnrollAndLoginWithEmailOtpEcdsaCapabilityInternalResult>;
  listThresholdEcdsaSessionRecordsForWalletTarget(
    args: ListThresholdEcdsaSessionRecordsForWalletTargetInput,
  ): SessionPublicThresholdEcdsaSessionRecord[];
  clearAllThresholdEcdsaSessionRecords(): void;
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
  scheduleThresholdEcdsaLoginPresignPrefill(args: {
    walletId: EcdsaWalletId;
    chainTarget: ThresholdEcdsaChainTarget;
    thresholdEcdsaSessionRecord: ThresholdEcdsaSessionRecord;
    minRemainingUsesBeforePrefill?: number;
  }): Promise<ThresholdEcdsaLoginPrefillResult>;
  clearVolatileWarmSigningMaterial(walletId?: EcdsaWalletId): Promise<void>;
  clearThresholdEcdsaCommitQueue(): void;
  signNear<TRequest extends NearSignIntentRequest>(
    request: TRequest,
  ): Promise<NearSignIntentResult<TRequest>>;
  signTempo(args: {
    walletSession: WalletSessionRef;
    request: TempoSigningRequest | EvmSigningRequest;
    chainTarget: ThresholdEcdsaChainTarget;
    confirmationConfigOverride?: Partial<ConfirmationConfig>;
    shouldAbort?: () => boolean;
    onEvent?: (event: SigningFlowEvent) => void;
  }): Promise<TempoSignedResult | EvmSignedResult>;
  reportTempoBroadcastAccepted(args: RuntimeReportTempoBroadcastAcceptedArgs): Promise<void>;
  reportTempoBroadcastRejected(args: RuntimeReportTempoBroadcastRejectedArgs): Promise<void>;
  reportTempoFinalized(args: RuntimeReportTempoFinalizedArgs): Promise<void>;
  reportTempoDroppedOrReplaced(args: RuntimeReportTempoDroppedOrReplacedArgs): Promise<void>;
  reconcileTempoNonceLane(args: RuntimeReconcileTempoNonceLaneArgs): Promise<RuntimeTempoNonceLaneStatus>;
  requestRegistrationCredentialConfirmation(params: {
    nearAccountId: string;
    signerSlot: number;
    confirmerText?: { title?: string; body?: string };
    confirmationConfigOverride?: Partial<ConfirmationConfig>;
    challengeB64u?: string;
  }): Promise<RegistrationCredentialConfirmationPayload>;
  getAuthenticationCredentialsSerialized(args: {
    nearAccountId: AccountId;
    challengeB64u: string;
    allowCredentials: WebAuthnAllowCredential[];
    includeSecondPrfOutput?: boolean;
  }): Promise<WebAuthnAuthenticationCredential>;
  extractCosePublicKey(attestationObjectBase64url: string): Promise<Uint8Array>;
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
  prepareThresholdEd25519HssClientCeremonyFromCredential(
    args: Parameters<typeof thresholdEd25519Public.prepareThresholdEd25519HssClientCeremonyFromCredential>[1],
  ): ReturnType<typeof thresholdEd25519Public.prepareThresholdEd25519HssClientCeremonyFromCredential>;
  prepareThresholdEd25519HssClientCeremonyFromPrfFirst(
    args: Parameters<typeof thresholdEd25519Public.prepareThresholdEd25519HssClientCeremonyFromPrfFirst>[1],
  ): ReturnType<typeof thresholdEd25519Public.prepareThresholdEd25519HssClientCeremonyFromPrfFirst>;
  prepareThresholdEd25519HssClientRequest(
    args: Parameters<typeof thresholdEd25519Public.prepareThresholdEd25519HssClientRequest>[1],
  ): ReturnType<typeof thresholdEd25519Public.prepareThresholdEd25519HssClientRequest>;
  deriveThresholdEd25519HssClientOutputMask(
    args: Parameters<typeof thresholdEd25519Public.deriveThresholdEd25519HssClientOutputMask>[1],
  ): ReturnType<typeof thresholdEd25519Public.deriveThresholdEd25519HssClientOutputMask>;
  buildThresholdEd25519HssClientOwnedStagedEvaluatorArtifact(
    args: Parameters<
      typeof thresholdEd25519Public.buildThresholdEd25519HssClientOwnedStagedEvaluatorArtifact
    >[1],
  ): ReturnType<
    typeof thresholdEd25519Public.buildThresholdEd25519HssClientOwnedStagedEvaluatorArtifact
  >;
  runThresholdEd25519HssCeremonyWithSession(
    args: Parameters<typeof thresholdEd25519Public.runThresholdEd25519HssCeremonyWithSession>[1],
  ): ReturnType<typeof thresholdEd25519Public.runThresholdEd25519HssCeremonyWithSession>;
}

export interface SeamsWebContext {
  signingEngine: SeamsWebSigningSurface;
  signingRuntime: SigningRuntime;
  nearClient: NearClient;
  configs: SeamsConfigsReadonly;
  theme: ThemeName;
}
