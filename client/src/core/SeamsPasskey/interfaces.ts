import type {
  EmailOtpBootstrapRecovery,
  SigningEnginePublic,
  ThresholdEcdsaSessionBootstrapResult,
  ThresholdEcdsaLoginPrefillResult,
} from '../signingEngine/SigningEngine';
import type {
  NearAccountRef,
  ThresholdEcdsaChainTarget,
  WalletId,
  WalletSessionRef,
  WalletSubjectId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdRuntimePolicyScope } from '../signingEngine/threshold/sessionPolicy';
import type { ThresholdEcdsaEmailOtpAuthContext } from '../signingEngine/session/identity/laneIdentity';
import type { WarmSessionEcdsaCapabilityState } from '../signingEngine/session/warmCapabilities/types';
import type { AppOrThresholdSessionAuth } from '@shared/utils/sessionTokens';
import type { NearClient, SignedTransaction } from '../rpcClients/near/NearClient';
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
  SignTransactionResult,
  ThemeName,
  SeamsConfigsReadonly,
} from '../types/seams';
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
} from '../types/sdkSentEvents';
import type {
  ConfirmationBehavior,
  ConfirmationConfig,
  WasmSignedDelegate,
} from '../types/signer-worker';
import type {
  ThresholdEd25519HssFinalizedReportEnvelope,
  ThresholdEd25519HssPreparedSessionEnvelope,
} from '../signingEngine/threshold/crypto/hssClientSignerWasm';
import type { AccountId } from '../types/accountIds';
import type { ActionArgs, TransactionInput } from '../types/actions';
import type { DelegateActionInput, SignedDelegate } from '../types/delegate';
import type { MultichainSigningRequest } from '../signingEngine/chains/tempo/types';
import type { EvmSignedResult } from '../signingEngine/chains/evm/evmAdapter';
import type { TempoSignedResult } from '../signingEngine/chains/tempo/tempoAdapter';
import type { SignNEP413MessageParams, SignNEP413MessageResult } from './near/signNEP413';
import type { SyncAccountResult } from './syncAccount';
import type { EmailRecoveryFlowOptions } from '../types/emailRecovery';
import type {
  DeviceLinkingQRData,
  LinkDeviceResult,
  ScanAndLinkDeviceOptionsDevice1,
  StartDevice2LinkingFlowArgs,
  StartDevice2LinkingFlowResults,
} from '../types/linkDevice';
import type {
  WebAuthnAuthenticationCredential,
  WebAuthnRegistrationCredential,
} from '../types/webauthn';
import type {
  WalletEmailOtpChannel,
  WalletEmailOtpLoginOperation,
} from '@shared/utils/emailOtpDomain';

export type SignTempoArgs = {
  walletSession: WalletSessionRef;
  subjectId: WalletSubjectId;
  request: MultichainSigningRequest;
  chainTarget: ThresholdEcdsaChainTarget;
  options?: {
    confirmationConfig?: Partial<ConfirmationConfig>;
    /** Internal host-only cancellation probe; ignored in wallet-router calls. */
    shouldAbort?: () => boolean;
    onEvent?: (event: SigningFlowEvent) => void;
  };
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
  subjectId: WalletSubjectId;
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
  subjectId: WalletSubjectId;
  chainTarget: ThresholdEcdsaChainTarget;
  relayerUrl?: string;
  ecdsaThresholdKeyId?: string;
  participantIds?: number[];
  runtimeScopeBootstrap?: {
    environmentId: string;
    publishableKey: string;
  };
  ttlMs?: number;
  remainingUses?: number;
  smartAccount?: {
    chainId: number;
    factory?: string;
    entryPoint?: string;
    salt?: string;
    counterfactualAddress?: string;
  };
} & (
  | {
      kind: 'reuse_warm_ecdsa_bootstrap';
      source?: 'login' | 'registration' | 'manual-bootstrap' | 'email_otp';
      sessionKind?: never;
      sessionIdentity?: never;
      routeAuth?: never;
      webauthnAuthentication?: never;
      clientRootShare32B64u?: never;
      emailOtpAuthContext?: never;
    }
  | {
      kind: 'passkey_fresh_ecdsa_bootstrap';
      source?: 'login' | 'registration' | 'manual-bootstrap' | 'email_otp';
      sessionKind: 'jwt';
      sessionIdentity: {
        thresholdSessionId: string;
        walletSigningSessionId: string;
      };
      clientRootShare32B64u: string;
      routeAuth:
        | { kind: 'app_session'; jwt: string }
        | { kind: 'bootstrap_grant'; token: string }
        | { kind: 'publishable_key'; token: string }
        | { kind: 'registration_continuation'; token: string };
      webauthnAuthentication?: never;
      emailOtpAuthContext?: never;
    }
  | {
      kind: 'passkey_fresh_ecdsa_bootstrap';
      source?: 'login' | 'registration' | 'manual-bootstrap' | 'email_otp';
      sessionKind: 'jwt';
      sessionIdentity: {
        thresholdSessionId: string;
        walletSigningSessionId: string;
      };
      clientRootShare32B64u: string;
      webauthnAuthentication: WebAuthnAuthenticationCredential;
      routeAuth?: never;
      emailOtpAuthContext?: never;
    }
  | {
      kind: 'passkey_fresh_ecdsa_bootstrap';
      source?: 'login' | 'registration' | 'manual-bootstrap' | 'email_otp';
      sessionKind: 'cookie';
      sessionIdentity: {
        thresholdSessionId: string;
        walletSigningSessionId: string;
      };
      clientRootShare32B64u: string;
      routeAuth?: never;
      webauthnAuthentication?: never;
      emailOtpAuthContext?: never;
    }
  | {
      kind: 'passkey_fresh_ecdsa_bootstrap';
      source?: 'login' | 'registration' | 'manual-bootstrap' | 'email_otp';
      sessionKind: 'cookie';
      sessionIdentity: {
        thresholdSessionId: string;
        walletSigningSessionId: string;
      };
      clientRootShare32B64u: string;
      webauthnAuthentication: WebAuthnAuthenticationCredential;
      routeAuth?: never;
      emailOtpAuthContext?: never;
    }
  | {
      kind: 'passkey_cookie_reconnect_ecdsa_bootstrap';
      source?: 'login' | 'registration' | 'manual-bootstrap' | 'email_otp';
      sessionKind: 'cookie';
      sessionIdentity: {
        thresholdSessionId: string;
        walletSigningSessionId: string;
      };
      routeAuth?: never;
      webauthnAuthentication?: never;
      clientRootShare32B64u?: never;
      emailOtpAuthContext?: never;
    }
  | {
      kind: 'threshold_session_auth_reconnect_ecdsa_bootstrap';
      source?: 'login' | 'registration' | 'manual-bootstrap' | 'email_otp';
      sessionKind: 'jwt';
      sessionIdentity: {
        thresholdSessionId: string;
        walletSigningSessionId: string;
      };
      routeAuth:
        | { kind: 'app_session'; jwt: string }
        | { kind: 'threshold_session'; jwt: string };
      webauthnAuthentication?: never;
      clientRootShare32B64u: string;
      emailOtpAuthContext?: never;
    }
  | {
      kind: 'email_otp_ecdsa_bootstrap';
      source: 'email_otp';
      sessionKind: 'jwt' | 'cookie';
      sessionIdentity: {
        thresholdSessionId: string;
        walletSigningSessionId: string;
      };
      clientRootShare32B64u: string;
      emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
      webauthnAuthentication?: never;
      routeAuth?:
        | { kind: 'app_session'; jwt: string }
        | { kind: 'threshold_session'; jwt: string }
        | { kind: 'bootstrap_grant'; token: string }
        | { kind: 'publishable_key'; token: string }
        | { kind: 'registration_continuation'; token: string };
    }
);

export type EmailOtpChallengeResult = {
  challengeId: string;
  otpChannel: WalletEmailOtpChannel;
  emailHint?: string;
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
  signingRootId: string;
  signingRootVersion: string;
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
  subjectId: WalletSubjectId;
  chainTarget: ThresholdEcdsaChainTarget;
  emailOtpAuthPolicy?: EmailOtpAuthPolicy;
  relayUrl?: string;
  challengeId?: string;
  otpCode: string;
  shamirPrimeB64u?: string;
  appSessionJwt?: string;
  routeAuth?: AppOrThresholdSessionAuth;
  ecdsaThresholdKeyId?: string;
  participantIds?: number[];
  sessionKind?: 'jwt' | 'cookie';
  sessionId?: string;
  ttlMs?: number;
  remainingUses?: number;
  registrationAttemptId?: string;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  onEvent?: (event: UnlockFlowEvent) => void;
};

export type EmailOtpEcdsaCapabilityResult = {
  recovery: EmailOtpBootstrapRecovery;
  bootstrap: ThresholdEcdsaSessionBootstrapResult;
  warmCapability: WarmSessionEcdsaCapabilityState;
};

export type EmailOtpEcdsaEnrollmentCapabilityArgs = Omit<EmailOtpEcdsaCapabilityArgs, 'onEvent'> & {
  clientSecret32?: Uint8Array;
  onEvent?: (event: RegistrationFlowEvent | UnlockFlowEvent) => void;
};

export type EmailOtpEcdsaEnrollmentCapabilityResult = {
  enrollment: EmailOtpEnrollmentResult;
  bootstrap: ThresholdEcdsaSessionBootstrapResult;
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
    subjectId: WalletSubjectId;
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
    subjectId: WalletSubjectId;
    chainTarget: ThresholdEcdsaChainTarget;
    onEvent?: (event: UnlockFlowEvent) => void;
  }): Promise<Pick<EmailOtpChallengeResult, 'challengeId' | 'emailHint'>>;
  refreshEmailOtpSigningSession(args: {
    walletSession: WalletSessionRef;
    subjectId: WalletSubjectId;
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
  ): Promise<ThresholdEcdsaSessionBootstrapResult>;
}

export interface EvmSignerCapability {
  bootstrapEcdsaSession(
    args: BootstrapThresholdEcdsaSessionArgs,
  ): Promise<ThresholdEcdsaSessionBootstrapResult>;
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
      subjectId: WalletSubjectId;
      chainTarget: ThresholdEcdsaChainTarget;
      // This is UI/auth-session context only. It must not be used as ECDSA lane identity.
      walletSessionUserId: string;
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

export interface PasskeyManagerContext {
  signingEngine: SigningEnginePublic;
  nearClient: NearClient;
  configs: SeamsConfigsReadonly;
  theme: ThemeName;
}
