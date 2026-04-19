import type {
  EmailOtpBootstrapRecovery,
  SigningEnginePublic,
  ThresholdEcdsaActivationChain,
  ThresholdEcdsaLoginPrefillResult,
  ThresholdEcdsaSessionBootstrapResult,
} from '../signingEngine/SigningEngine';
import type { ThresholdRuntimePolicyScope } from '../signingEngine/threshold/session/sessionPolicy';
import type { WarmSessionEcdsaCapabilityState } from '../signingEngine/session/warmSessionTypes';
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
  TatchiConfigsReadonly,
} from '../types/tatchi';
import type {
  ActionHooksOptions,
  DelegateActionHooksOptions,
  DelegateRelayHooksOptions,
  LoginHooksOptions,
  RegistrationHooksOptions,
  SendTransactionHooksOptions,
  SignAndSendDelegateActionHooksOptions,
  SignAndSendTransactionHooksOptions,
  SignNEP413HooksOptions,
  SignTransactionHooksOptions,
  SyncAccountHooksOptions,
} from '../types/sdkSentEvents';
import type {
  ConfirmationBehavior,
  ConfirmationConfig,
  WasmSignedDelegate,
} from '../types/signer-worker';
import type {
  ThresholdEd25519HssFinalizedReportEnvelope,
  ThresholdEd25519HssPreparedSessionEnvelope,
} from '../signingEngine/signers/wasm/hssClientSignerWasm';
import type { AccountId } from '../types/accountIds';
import type { ActionArgs, TransactionInput } from '../types/actions';
import type { DelegateActionInput, SignedDelegate } from '../types/delegate';
import type { MultichainSigningRequest } from '../signingEngine/chainAdaptors/tempo/types';
import type { EvmSignedResult } from '../signingEngine/chainAdaptors/evm/evmAdapter';
import type { TempoSignedResult } from '../signingEngine/chainAdaptors/tempo/tempoAdapter';
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
  nearAccountId: string;
  request: MultichainSigningRequest;
  options?: {
    confirmationConfig?: Partial<ConfirmationConfig>;
    /** Internal host-only cancellation probe; ignored in wallet-router calls. */
    shouldAbort?: () => boolean;
    onEvent?: (event: {
      step: number;
      phase: string;
      status: 'progress' | 'success' | 'error';
      message?: string;
      data?: unknown;
    }) => void;
  };
};

export type TempoNonceLifecycleEvent = {
  step: number;
  phase: string;
  status: 'progress' | 'success' | 'error';
  message?: string;
  data?: unknown;
};

export type TempoNonceLifecycleOptions = {
  onEvent?: (event: TempoNonceLifecycleEvent) => void;
};

type ReportTempoNonceLifecycleBaseArgs = {
  nearAccountId: string;
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
  nearAccountId: string;
  request: MultichainSigningRequest;
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
  nearAccountId: string;
  options?: {
    chain?: ThresholdEcdsaActivationChain;
    relayerUrl?: string;
    participantIds?: number[];
    sessionKind?: 'jwt' | 'cookie';
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
  };
};

export type EmailOtpChallengeResult = {
  challengeId: string;
  otpChannel: WalletEmailOtpChannel;
  emailHint?: string;
};

export type EmailOtpEnrollmentResult = {
  thresholdEcdsaClientVerifyingShareB64u: string;
  challengeId: string;
  otpChannel: WalletEmailOtpChannel;
  emailOtpKeyVersion: string;
  unlockPublicKeyB64u: string;
  unlockKeyVersion: string;
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
  nearAccountId: string;
  chain?: ThresholdEcdsaActivationChain;
  emailOtpAuthPolicy?: EmailOtpAuthPolicy;
  relayUrl?: string;
  challengeId?: string;
  otpCode: string;
  shamirPrimeB64u?: string;
  appSessionJwt?: string;
  thresholdRouteAuth?: AppOrThresholdSessionAuth;
  ecdsaThresholdKeyId?: string;
  participantIds?: number[];
  sessionKind?: 'jwt' | 'cookie';
  sessionId?: string;
  ttlMs?: number;
  remainingUses?: number;
  registrationAttemptId?: string;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
};

export type EmailOtpEcdsaCapabilityResult = {
  recovery: EmailOtpBootstrapRecovery;
  bootstrap: ThresholdEcdsaSessionBootstrapResult;
  warmCapability: WarmSessionEcdsaCapabilityState;
};

export type EmailOtpEcdsaEnrollmentCapabilityArgs = EmailOtpEcdsaCapabilityArgs & {
  clientSecret32?: Uint8Array;
};

export type EmailOtpEcdsaEnrollmentCapabilityResult = {
  enrollment: EmailOtpEnrollmentResult;
  bootstrap: ThresholdEcdsaSessionBootstrapResult;
  warmCapability: WarmSessionEcdsaCapabilityState;
};

export interface AuthCapability {
  unlock(nearAccountId: string, options?: LoginHooksOptions): Promise<LoginAndCreateSessionResult>;
  lock(): Promise<void>;
  getWalletSession(nearAccountId?: string): Promise<WalletSession>;
  getRecentUnlocks(): Promise<GetRecentUnlocksResult>;
  hasPasskeyCredential(nearAccountId: AccountId): Promise<boolean>;
  prefillThresholdEcdsaPresignPool(args: {
    nearAccountId: string;
    chain?: ThresholdEcdsaActivationChain;
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
  }): Promise<EmailOtpChallengeResult>;
  requestEmailOtpEnrollmentChallenge(args: {
    nearAccountId: string;
    relayUrl?: string;
    appSessionJwt?: string;
  }): Promise<EmailOtpChallengeResult>;
  exchangeGoogleEmailOtpSession(args: {
    idToken: string;
    accountMode: 'register' | 'login';
    relayUrl?: string;
    sessionKind?: 'jwt' | 'cookie';
  }): Promise<GoogleEmailOtpSessionExchangeResult>;
  enrollEmailOtp(args: {
    nearAccountId: string;
    otpCode: string;
    relayUrl?: string;
    challengeId?: string;
    shamirPrimeB64u?: string;
    appSessionJwt?: string;
    clientSecret32?: Uint8Array;
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
    nearAccountId: string;
    receiverId: string;
    actionArgs: ActionArgs | ActionArgs[];
    options: ActionHooksOptions;
  }): Promise<ActionResult>;

  signAndSendTransactions(args: {
    nearAccountId: string;
    transactions: TransactionInput[];
    options: SignAndSendTransactionHooksOptions;
  }): Promise<ActionResult[]>;

  signAndSendTransaction(args: {
    nearAccountId: string;
    receiverId: string;
    actions: ActionArgs[];
    options: SignAndSendTransactionHooksOptions;
  }): Promise<ActionResult>;

  signTransactionsWithActions(args: {
    nearAccountId: string;
    transactions: TransactionInput[];
    options: SignTransactionHooksOptions;
  }): Promise<SignTransactionResult[]>;

  sendTransaction(args: {
    signedTransaction: SignedTransaction;
    options?: SendTransactionHooksOptions;
  }): Promise<ActionResult>;

  signDelegateAction(args: {
    nearAccountId: string;
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
    nearAccountId: string;
    delegate: DelegateActionInput;
    relayerUrl: string;
    signal?: AbortSignal;
    options: SignAndSendDelegateActionHooksOptions;
  }): Promise<SignAndSendDelegateActionResult>;

  signNEP413Message(args: {
    nearAccountId: string;
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

export type ExportKeypairChain = 'near' | 'evm' | 'tempo';
export type ThresholdEd25519SeedExportUiOptions = {
  variant?: 'drawer' | 'modal';
  theme?: 'dark' | 'light';
};

export interface KeyExportCapability {
  exportKeypairWithUI(
    nearAccountId: string,
    options: {
      chain: ExportKeypairChain;
      variant?: 'drawer' | 'modal';
      theme?: 'dark' | 'light';
    },
  ): Promise<void>;
  exportThresholdEd25519SeedFromHssReport(args: {
    nearAccountId: string;
    preparedSession: ThresholdEd25519HssPreparedSessionEnvelope;
    finalizedReport: ThresholdEd25519HssFinalizedReportEnvelope;
    expectedPublicKey: string;
    options: ThresholdEd25519SeedExportUiOptions;
  }): Promise<void>;
}

export interface PreferencesCapability {
  setCurrentUser(nearAccountId: AccountId): void;
  getCurrentUserAccountId(): AccountId;
  onConfirmationConfigChange(callback: (config: ConfirmationConfig) => void): () => void;
  onCurrentUserChange(callback: (nearAccountId: AccountId | null) => void): () => void;
  setConfirmBehavior(behavior: ConfirmationBehavior): void;
  setConfirmationConfig(config: ConfirmationConfig): void;
  getConfirmationConfig(): ConfirmationConfig;
}

export interface PasskeyManagerContext {
  signingEngine: SigningEnginePublic;
  nearClient: NearClient;
  configs: TatchiConfigsReadonly;
  theme: ThemeName;
}
