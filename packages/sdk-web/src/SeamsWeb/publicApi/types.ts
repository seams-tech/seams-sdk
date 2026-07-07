import type { NonceCoordinator } from '@/core/signingEngine/nonce/NonceCoordinator';
import type {
  NearAccountRef,
  ThresholdEcdsaChainTarget,
  WalletId as EcdsaWalletId,
  WalletSessionRef,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type {
  ExactEcdsaSigningLaneIdentity,
  ExactEd25519SigningLaneIdentity,
} from '@/core/signingEngine/session/identity/exactSigningLaneIdentity';
import type {
  EmailOtpDeviceEnrollmentRemoveResult,
  EmailOtpDeviceEnrollmentRestoreResult,
  EmailOtpEnrollmentResult,
  EmailOtpRecoveryCodeBackupStatus,
  EmailOtpRecoveryCodeLifecycleStatus,
  EmailOtpRecoveryCodeStatus,
  GoogleEmailOtpSessionExchangeResult,
} from '@/core/signingEngine/session/emailOtp/publicTypes';
import type {
  ProvisionWarmEd25519CapabilityResult,
  WarmEcdsaSigningSessionStatus,
  WarmSessionEcdsaCapabilityState,
} from '@/core/signingEngine/session/warmCapabilities/types';
import type { RouterAbEcdsaHssLoginPresignaturePrefillResult } from '@/core/signingEngine/session/warmCapabilities/ecdsaLoginPrefill';
import type {
  AccessKeyList,
  NearClient,
  SignedTransaction,
} from '@/core/rpcClients/near/NearClient';
import type {
  ActionResult,
  DelegateRouterApiResult,
  EmailOtpAuthPolicy,
  GetRecentUnlocksResult,
  LoginAndCreateSessionResult,
  WalletSession,
  RegistrationResult,
  SignAndSendDelegateActionResult,
  SignDelegateActionResult,
  SigningSessionStatus,
  SignTransactionResult,
  SeamsRegistrationNearAccountProvisioning,
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
import type { MultichainSigningRequest } from '@/core/signingEngine/chains/tempo/tempoSigning.types';
import type { EvmSignedResult } from '@/core/signingEngine/chains/evm/evmAdapter';
import type { TempoSignedResult } from '@/core/signingEngine/chains/tempo/tempoAdapter';
import type {
  SignNEP413MessageParams,
  SignNEP413MessageResult,
} from '@/SeamsWeb/operations/near/signNEP413';
import type { SyncAccountResult } from '@/SeamsWeb/operations/recovery/syncAccount';
import type { EmailRecoveryFlowOptions } from '@/core/types/emailRecovery';
import type { UserPreferencesManager } from '@/core/signingEngine/session/userPreferences';
import type {
  AvailableSigningLanes,
  ListThresholdEcdsaSessionRecordsForWalletTargetInput,
  ReadAvailableSigningLanesInput,
  DiscoverPersistedSessionsForWalletInput,
  DiscoverPersistedSessionsForWalletResult,
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
import type { WebAuthnAllowCredential } from '@/core/signingEngine/webauthnAuth/credentials/collectAuthenticationCredentialForChallengeB64u';
import type { RegistrationCredentialConfirmationPayload } from '@/core/signingEngine/workerManager/validation';
import type {
  KeyExportEventCallback,
  SigningEngineResolveExactKeyExportLaneInput,
  SigningEngineResolveExactKeyExportLaneResult,
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
  RegistrationNearAccountProvisioning,
  RegistrationSignerSetSelection,
  WalletId,
} from '@shared/utils/registrationIntent';
import type {
  ClientAuthenticatorData,
  ClientUserData,
  StoreUserDataInput,
} from '@/core/accountData/near/nearAccountData.types';
import type {
  EmailOtpWalletRegistrationEcdsaPreparedClientBootstrap,
  PasskeyWalletRegistrationEcdsaPreparedClientBootstrap,
  PrepareEmailOtpWalletRegistrationEcdsaClientBootstrapInput,
  PreparePasskeyWalletRegistrationEcdsaClientBootstrapInput,
} from '@/core/signingEngine/flows/registration/services/ecdsaRegistrationBootstrap';
import type { FinalizeWalletRegistrationEcdsaSessionsInput } from '@/core/signingEngine/flows/registration/services/ecdsaRegistrationSessions';
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
import type { HydrateWarmSigningSessionInput } from '@/core/signingEngine/session/passkey/warmSessionHydration';

type PublicThresholdEcdsaSessionKeyRef = Omit<
  ThresholdEcdsaSessionBootstrapResult['thresholdEcdsaKeyRef'],
  | 'ecdsaThresholdKeyId'
  | 'signingRootId'
  | 'signingRootVersion'
  | 'ecdsaHssExportArtifact'
  | 'walletSessionJwt'
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

export type RegisterNearImplicitWalletArgs = {
  accountProvisioning?: Extract<RegistrationNearAccountProvisioning, { kind: 'implicit_account' }>;
  nearAccountId?: never;
  wallet?: Extract<RegisterWalletInput, { kind: 'provided' }>;
  authMethod?: RegistrationAuthMethodInput;
  options?: RegistrationHooksOptions;
};

export type RegisterNearSponsoredWalletArgs = {
  accountProvisioning: Extract<
    RegistrationNearAccountProvisioning,
    { kind: 'sponsored_named_account' }
  >;
  wallet: Extract<RegisterWalletInput, { kind: 'provided' }>;
  nearAccountId?: never;
  authMethod?: RegistrationAuthMethodInput;
  options?: RegistrationHooksOptions;
};

export type RegisterNearWalletArgs =
  | RegisterNearImplicitWalletArgs
  | RegisterNearSponsoredWalletArgs;

export type FundImplicitNearAccountForTestingResult =
  | {
      ok: true;
      walletId: string;
      nearAccountId: string;
      fundedAmountYocto: string;
      transactionHash?: string;
      message?: string;
    }
  | {
      ok: false;
      code: string;
      message: string;
    };

export type PasskeyRegistrationOptions = RegistrationHooksOptions & {
  wallet?: Extract<RegisterWalletInput, { kind: 'provided' }>;
  nearAccountProvisioning?: SeamsRegistrationNearAccountProvisioning;
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
    projectEnvironmentId: string;
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

export type {
  EmailOtpDeviceEnrollmentRemoveResult,
  EmailOtpDeviceEnrollmentRestoreResult,
  EmailOtpEnrollmentResult,
  EmailOtpRecoveryCodeBackupStatus,
  EmailOtpRecoveryCodeLifecycleStatus,
  EmailOtpRecoveryCodeStatus,
  GoogleEmailOtpSessionExchangeResult,
};

export type EmailOtpBackedUpEnrollmentResult = Omit<EmailOtpEnrollmentResult, 'recoveryKeys'> & {
  recoveryCodeBackup: EmailOtpRecoveryCodeBackupStatus;
};

export type GoogleEmailOtpRegistrationBackedUpEnrollmentResult = Omit<
  EmailOtpBackedUpEnrollmentResult,
  'challengeId'
> & {
  registrationAuthorityId: string;
  challengeId?: never;
  otpCode?: never;
  delivery?: never;
  webauthn?: never;
  passkey?: never;
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
  registrationAttemptId?: string;
  emailOtpAuthorityEmail?: string;
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
  enrollment: EmailOtpEnrollmentResult | EmailOtpBackedUpEnrollmentResult;
  bootstrap: PublicThresholdEcdsaSessionBootstrapResult;
  warmCapability: WarmSessionEcdsaCapabilityState;
};

export type GoogleEmailOtpWalletAuthRequestedMode = 'register' | 'login';
export type GoogleEmailOtpWalletAuthResolvedMode = 'register' | 'login';
export type GoogleEmailOtpWalletAuthDelivery = 'sent' | 'reused';

export type GoogleEmailOtpRegistrationOfferId = string & {
  readonly __googleEmailOtpRegistrationOfferId: unique symbol;
};

export type GoogleEmailOtpRegistrationCandidateId = string & {
  readonly __googleEmailOtpRegistrationCandidateId: unique symbol;
};

export type RegistrationFinalizeIdempotencyKey = string & {
  readonly __registrationFinalizeIdempotencyKey: unique symbol;
};

export type GoogleEmailOtpRegistrationBackupActionKind = 'download' | 'copy' | 'print' | 'manual';

export type EmailOtpRecoveryCodeBackupAck = {
  kind: 'email_otp_recovery_code_backup_ack_v1';
  offerId: GoogleEmailOtpRegistrationOfferId;
  candidateId: GoogleEmailOtpRegistrationCandidateId;
  recoveryCodesIssuedAtMs: number;
  backupActionKind: GoogleEmailOtpRegistrationBackupActionKind;
  acknowledgedAtMs: number;
  idempotencyKey: RegistrationFinalizeIdempotencyKey;
  recoveryKeys?: never;
  recoveryCodes?: never;
  appSessionJwt?: never;
  otpCode?: never;
  challengeId?: never;
  walletId?: never;
  webauthn?: never;
  passkey?: never;
};

export type EmailOtpRecoveryCodeRotationResult = {
  status: EmailOtpRecoveryCodeStatus;
  recoveryCodeBackup: EmailOtpRecoveryCodeBackupStatus;
};

export type GoogleEmailOtpRegistrationCandidate = {
  candidateId: GoogleEmailOtpRegistrationCandidateId;
  walletId: WalletId;
};

export type GoogleEmailOtpRegistrationOffer = {
  kind: 'google_email_otp_registration_offer_v1';
  offerId: GoogleEmailOtpRegistrationOfferId;
  expiresAtMs: number;
  emailHint: string;
  candidates: readonly [
    GoogleEmailOtpRegistrationCandidate,
    ...GoogleEmailOtpRegistrationCandidate[],
  ];
  selectedCandidateId: GoogleEmailOtpRegistrationCandidateId;
  delivery?: never;
  challengeId?: never;
  otpCode?: never;
  webauthn?: never;
  passkey?: never;
};

export type GoogleEmailOtpRegistrationFinalizeInput = {
  kind: 'google_email_otp_registration_finalize_v1';
  offerId: GoogleEmailOtpRegistrationOfferId;
  candidateId: GoogleEmailOtpRegistrationCandidateId;
  idempotencyKey: RegistrationFinalizeIdempotencyKey;
  emailOtpEnrollment: GoogleEmailOtpRegistrationBackedUpEnrollmentResult;
  backupAck: EmailOtpRecoveryCodeBackupAck;
  walletId?: never;
  otpCode?: never;
  challengeId?: never;
  delivery?: never;
  webauthn?: never;
  passkey?: never;
};

export type GoogleEmailOtpWalletAuthEcdsaTargets =
  | { kind: 'configured' }
  | { kind: 'none' }
  | {
      kind: 'explicit';
      targets: readonly [ThresholdEcdsaChainTarget, ...ThresholdEcdsaChainTarget[]];
    };

export type GoogleEmailOtpWalletAuthFailureCode =
  | 'google_exchange_failed'
  | 'email_otp_challenge_failed'
  | 'email_otp_invalid_code'
  | 'email_otp_expired'
  | 'email_otp_rate_limited'
  | 'registration_failed'
  | 'registration_restore_required'
  | 'email_otp_device_recovery_required'
  | 'unlock_failed'
  | 'recovery_code_backup_incomplete'
  | 'local_signing_session_not_ready'
  | 'wallet_iframe_unavailable'
  | 'flow_cancelled'
  | 'flow_expired';

export type GoogleEmailOtpWalletAuthFailure = {
  code: GoogleEmailOtpWalletAuthFailureCode;
  message: string;
  retryAfterMs?: number;
};

export type GoogleEmailOtpWalletAuthResult<T> =
  | { ok: true; value: T }
  | { ok: false; error: GoogleEmailOtpWalletAuthFailure };

export type GoogleEmailOtpWalletAuthPromptCopy = {
  title: string;
  description: string;
  submitLabel: string;
  helperText: string;
};

export type GoogleEmailOtpWalletAuthSubmitSuccess = {
  walletId: WalletId;
  session: WalletSession;
  mode: GoogleEmailOtpWalletAuthResolvedMode;
};

export type GoogleEmailOtpWalletAuthRegistrationCompleted = {
  walletId: WalletId;
  session: WalletSession;
  mode: 'register';
};

export type GoogleEmailOtpWalletAuthBaseFlow = {
  kind: 'google_email_otp_wallet_auth_flow_v1';
  flowId: string;
  requestedMode: GoogleEmailOtpWalletAuthRequestedMode;
  mode: GoogleEmailOtpWalletAuthResolvedMode;
  walletId: WalletId;
  emailHint: string;
  prompt: GoogleEmailOtpWalletAuthPromptCopy;
  expiresAtMs: number;
  cancel(): Promise<void>;
};

export type GoogleEmailOtpWalletAuthRegistrationFlow = GoogleEmailOtpWalletAuthBaseFlow & {
  state: 'registration_ready';
  mode: 'register';
  completeRegistration(): Promise<
    GoogleEmailOtpWalletAuthResult<GoogleEmailOtpWalletAuthRegistrationCompleted>
  >;
  rerollWalletId(): Promise<
    GoogleEmailOtpWalletAuthResult<GoogleEmailOtpWalletAuthRegistrationFlow>
  >;
  delivery?: never;
  resend?: never;
  submit?: never;
};

export type GoogleEmailOtpWalletAuthLoginFlow = GoogleEmailOtpWalletAuthBaseFlow & {
  state: 'challenge_sent';
  mode: 'login';
  delivery: GoogleEmailOtpWalletAuthDelivery;
  resend(): Promise<GoogleEmailOtpWalletAuthResult<GoogleEmailOtpWalletAuthFlow>>;
  submit(input: {
    otpCode: string;
  }): Promise<GoogleEmailOtpWalletAuthResult<GoogleEmailOtpWalletAuthSubmitSuccess>>;
  completeRegistration?: never;
  rerollWalletId?: never;
};

export type GoogleEmailOtpWalletAuthFlow =
  | GoogleEmailOtpWalletAuthRegistrationFlow
  | GoogleEmailOtpWalletAuthLoginFlow;

export type GoogleEmailOtpWalletAuthStartInput = {
  idToken: string;
  mode: GoogleEmailOtpWalletAuthRequestedMode;
  relayUrl?: string;
  sessionKind?: 'jwt' | 'cookie';
  ecdsaTargets?: GoogleEmailOtpWalletAuthEcdsaTargets;
  emailOtpAuthPolicy?: EmailOtpAuthPolicy;
  onEvent?: (event: RegistrationFlowEvent | UnlockFlowEvent) => void;
};

export interface AuthCapability {
  unlock(walletId: string, options?: LoginHooksOptions): Promise<LoginAndCreateSessionResult>;
  lock(): Promise<void>;
  getWalletSession(walletId?: string): Promise<WalletSession>;
  getRecentUnlocks(): Promise<GetRecentUnlocksResult>;
  hasPasskeyCredential(walletId: string): Promise<boolean>;
  prefillRouterAbEcdsaHssPresignaturePool(args: {
    walletSession: WalletSessionRef;
    chainTarget: ThresholdEcdsaChainTarget;
    waitForPoolReady?: boolean;
    poolReadyTimeoutMs?: number;
    poolReadyPollIntervalMs?: number;
    minRemainingUsesBeforePrefill?: number;
  }): Promise<RouterAbEcdsaHssLoginPresignaturePrefillResult>;
  requestEmailOtpChallenge(args: {
    walletId: string;
    relayUrl?: string;
    appSessionJwt?: string;
    operation?: WalletEmailOtpLoginOperation;
    onEvent?: (event: UnlockFlowEvent) => void;
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
    onEvent?: (event: RegistrationFlowEvent | UnlockFlowEvent) => void;
  }): Promise<GoogleEmailOtpSessionExchangeResult>;
  loginWithEmailOtpEcdsaCapability(
    args: EmailOtpEcdsaCapabilityArgs,
  ): Promise<EmailOtpEcdsaCapabilityResult>;
  beginGoogleEmailOtpWalletAuth(
    args: GoogleEmailOtpWalletAuthStartInput,
  ): Promise<GoogleEmailOtpWalletAuthResult<GoogleEmailOtpWalletAuthFlow>>;
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
    signerSelection: RegistrationSignerSetSelection;
    options?: RegistrationHooksOptions;
  }): Promise<RegistrationResult>;
  registerWithEmailOtp(args: {
    authMethod: Extract<RegistrationAuthMethodInput, { kind: 'email_otp' }>;
    wallet: RegisterWalletInput;
    signerSelection: RegistrationSignerSetSelection;
    options?: RegistrationHooksOptions;
  }): Promise<RegistrationResult>;
  registerPasskey(options?: PasskeyRegistrationOptions): Promise<RegistrationResult>;
  createPasskeyRegistrationActivationSurface(
    args: CreatePasskeyRegistrationActivationSurfaceArgs,
  ): WalletIframeRegistrationActivationSurface;
  requestEmailOtpEnrollmentChallenge(args: {
    walletId: string;
    relayUrl?: string;
    appSessionJwt?: string;
    onEvent?: (event: RegistrationFlowEvent) => void;
  }): Promise<EmailOtpChallengeResult>;
  enrollEmailOtp(args: {
    walletId: string;
    otpCode: string;
    relayUrl?: string;
    challengeId?: string;
    shamirPrimeB64u?: string;
    appSessionJwt?: string;
    clientSecret32?: Uint8Array;
    onEvent?: (event: RegistrationFlowEvent) => void;
  }): Promise<EmailOtpEnrollmentResult | EmailOtpBackedUpEnrollmentResult>;
  enrollAndLoginWithEmailOtpEcdsaCapability(
    args: EmailOtpEcdsaEnrollmentCapabilityArgs,
  ): Promise<EmailOtpEcdsaEnrollmentCapabilityResult>;
}

export type RegistrationActivationSurfaceState =
  | { kind: 'idle' }
  | { kind: 'mounting'; activationId: string }
  | { kind: 'ready'; activationId: string; expiresAtMs: number }
  | { kind: 'starting'; activationId: string }
  | { kind: 'completed'; activationId: string; result: RegistrationResult }
  | {
      kind: 'cancelled';
      activationId: string;
      reason: 'user_cancelled' | 'expired' | 'disposed' | 'target_unavailable';
    }
  | { kind: 'failed'; activationId: string; error: string };

export type WalletIframeRegistrationActivationSurface = {
  kind: 'wallet_iframe_registration_activation_surface_v1';
  mount(target: HTMLElement): void;
  dispose(): void;
  state(): RegistrationActivationSurfaceState;
  onStateChange(listener: (state: RegistrationActivationSurfaceState) => void): () => void;
};

export type CreatePasskeyRegistrationActivationSurfaceArgs = {
  wallet: Extract<RegisterWalletInput, { kind: 'provided' }>;
  options?: RegistrationHooksOptions;
  presentation: RegistrationActivationButtonPresentation;
};

export type RegistrationActivationButtonCssProperty =
  | 'width'
  | 'height'
  | 'minWidth'
  | 'minHeight'
  | 'maxWidth'
  | 'maxHeight'
  | 'padding'
  | 'border'
  | 'borderColor'
  | 'borderRadius'
  | 'background'
  | 'backgroundColor'
  | 'color'
  | 'boxShadow'
  | 'fontFamily'
  | 'fontSize'
  | 'fontWeight'
  | 'lineHeight'
  | 'letterSpacing'
  | 'textAlign'
  | 'cursor'
  | 'outline'
  | 'outlineColor'
  | 'outlineOffset'
  | 'outlineWidth';

export type RegistrationActivationButtonCss = Partial<
  Record<RegistrationActivationButtonCssProperty, string>
>;

export type RegistrationActivationButtonPresentation =
  | {
      kind: 'outline_overlay';
      label: string;
      busyLabel: string;
      accessibleLabel: string;
      iframeButtonStyle?: RegistrationActivationButtonCss;
      iframeVisualStyle?: never;
      shadowPaddingPx?: never;
    }
  | {
      kind: 'iframe_button';
      label: string;
      busyLabel: string;
      accessibleLabel: string;
      iframeVisualStyle: RegistrationActivationButtonCss;
      shadowPaddingPx: number;
      iframeButtonStyle?: never;
    };

export interface NearSignerCapability {
  registerNearWallet(args: RegisterNearWalletArgs): Promise<RegistrationResult>;

  fundImplicitNearAccountForTesting(args: {
    walletSession: WalletSessionRef;
    nearAccount: NearAccountRef;
    nearPublicKey: string;
  }): Promise<FundImplicitNearAccountForTestingResult>;

  executeAction(args: {
    walletSession: WalletSessionRef;
    nearAccount: NearAccountRef;
    receiverId: string;
    actionArgs: ActionArgs | ActionArgs[];
    options: ActionHooksOptions;
  }): Promise<ActionResult>;

  signAndSendTransaction(args: {
    walletSession: WalletSessionRef;
    nearAccount: NearAccountRef;
    receiverId: string;
    actions: ActionArgs[];
    options: SignAndSendTransactionHooksOptions;
  }): Promise<ActionResult>;

  signTransactionWithActions(args: {
    walletSession: WalletSessionRef;
    nearAccount: NearAccountRef;
    transaction: TransactionInput;
    options: SignTransactionHooksOptions;
  }): Promise<SignTransactionResult>;

  sendTransaction(args: {
    walletSession: WalletSessionRef;
    nearAccount: NearAccountRef;
    signedTransaction: SignedTransaction;
    options?: SendTransactionHooksOptions;
  }): Promise<ActionResult>;

  signDelegateAction(args: {
    walletSession: WalletSessionRef;
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
  }): Promise<DelegateRouterApiResult>;

  signAndSendDelegateAction(args: {
    walletSession: WalletSessionRef;
    nearAccount: NearAccountRef;
    delegate: DelegateActionInput;
    relayerUrl: string;
    signal?: AbortSignal;
    options: SignAndSendDelegateActionHooksOptions;
  }): Promise<SignAndSendDelegateActionResult>;

  signNEP413Message(args: {
    walletSession: WalletSessionRef;
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
  getRecoveryEmails(walletId: string): Promise<Array<{ hashHex: string; email: string }>>;

  setRecoveryEmails(args: {
    walletId: string;
    recoveryEmails: string[];
    options: ActionHooksOptions;
  }): Promise<ActionResult>;

  syncAccount(args: {
    walletId?: string;
    options?: SyncAccountHooksOptions;
  }): Promise<SyncAccountResult>;

  startEmailRecovery(args: {
    walletId: string;
    options?: EmailRecoveryFlowOptions;
  }): Promise<{ mailtoUrl: string; nearPublicKey: string }>;

  finalizeEmailRecovery(args: {
    walletId: string;
    nearPublicKey?: string;
    options?: EmailRecoveryFlowOptions;
  }): Promise<void>;

  cancelEmailRecovery(args?: { walletId?: string; nearPublicKey?: string }): Promise<void>;

  getEmailOtpRecoveryCodeStatus(args: {
    walletId: string;
    relayUrl?: string;
    appSessionJwt?: string;
  }): Promise<EmailOtpRecoveryCodeStatus>;

  rotateEmailOtpRecoveryCodes(args: {
    walletId: string;
    relayUrl?: string;
    appSessionJwt?: string;
  }): Promise<EmailOtpRecoveryCodeRotationResult>;
}

export interface DevicesCapability {
  startDevice2LinkingFlow(
    args: StartDevice2LinkingFlowArgs,
  ): Promise<StartDevice2LinkingFlowResults>;

  stopDevice2LinkingFlow(): Promise<void>;

  linkDeviceWithScannedQRData(
    qrData: DeviceLinkingQRData,
    options: ScanAndLinkDeviceOptionsDevice1,
  ): Promise<LinkDeviceResult>;

  viewAccessKeyList(args: {
    walletSession: WalletSessionRef;
    nearAccount: NearAccountRef;
  }): Promise<AccessKeyList>;

  deleteDeviceKey(args: {
    walletSession: WalletSessionRef;
    nearAccount: NearAccountRef;
    publicKeyToDelete: string;
    options: ActionHooksOptions;
  }): Promise<ActionResult>;
}

export type ThresholdEd25519SeedExportUiOptions = {
  variant?: 'drawer' | 'modal';
  theme?: 'dark' | 'light';
  onEvent?: KeyExportHooksOptions['onEvent'];
};

export type ExportKeypairWithUIInput =
  | {
      kind: 'near';
      walletSession: WalletSessionRef;
      nearAccount: NearAccountRef;
      laneIdentity: ExactEd25519SigningLaneIdentity;
      options: ThresholdEd25519SeedExportUiOptions & {
        chain: 'near';
      };
    }
  | {
      kind: 'ecdsa';
      chainTarget: ThresholdEcdsaChainTarget;
      walletSession: WalletSessionRef;
      laneIdentity: ExactEcdsaSigningLaneIdentity;
      options: ThresholdEd25519SeedExportUiOptions;
    };

export type ResolveExactKeyExportLaneInput = SigningEngineResolveExactKeyExportLaneInput;
export type ResolveExactKeyExportLaneResult = SigningEngineResolveExactKeyExportLaneResult;

export interface KeyExportCapability {
  resolveExactKeyExportLane(
    input: ResolveExactKeyExportLaneInput,
  ): Promise<ResolveExactKeyExportLaneResult>;
  exportKeypairWithUI(input: ExportKeypairWithUIInput): Promise<void>;
  exportThresholdEd25519SeedFromHssReport(args: {
    walletSession: WalletSessionRef;
    nearAccount: NearAccountRef;
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
  setConfirmationConfig(config: Partial<ConfirmationConfig>): void;
  getConfirmationConfig(): ConfirmationConfig;
}
